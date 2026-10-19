import hmac
import ipaddress
import os
import secrets
import sqlite3
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for

from devices_config import DEVICES, ROUTER_ADMIN

RESULTS = ("success", "invalid_credentials", "mfa_required", "code_rejected",
           "rate_limited", "smtp_error", "error")


def create_app(data_dir=None):
    app = Flask(__name__)
    directory = Path(data_dir or os.environ.get("ROUTER_DATA_DIR", "/var/lib/router"))
    directory.mkdir(parents=True, exist_ok=True)
    secret_file = directory / "session.key"
    if not secret_file.exists():
        with secret_file.open("x") as file:
            file.write(secrets.token_hex(32))
        secret_file.chmod(0o600)
    app.secret_key = secret_file.read_text().strip()
    app.config.update(
        SESSION_COOKIE_NAME="router_session", SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict", PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=4096, AUDIT_DB=str(directory / "connections.sqlite3"),
        FIREWALL_LOG="/var/log/fw.log",
    )
    with sqlite3.connect(app.config["AUDIT_DB"]) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, received_at TEXT NOT NULL,
            device TEXT NOT NULL, source_ip TEXT NOT NULL, username TEXT NOT NULL,
            stage TEXT NOT NULL, result TEXT NOT NULL, status INTEGER NOT NULL
        )""")
    Path(app.config["AUDIT_DB"]).chmod(0o600)
    clients = {device["ip"]: key for key, device in DEVICES.items()}
    login_lock = threading.Lock()
    failed_logins = {}

    def save(event, device):
        with sqlite3.connect(app.config["AUDIT_DB"], timeout=10) as db:
            db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                event["id"], event["timestamp"], datetime.now(timezone.utc).isoformat(),
                device, event["source_ip"], event["username"], event["stage"], event["result"], event["status"],
            ))

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def check_csrf():
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(request.form.get("csrf", "").encode(), expected.encode()):
            abort(400)

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            check_csrf()
            session.pop("admin", None)
            username = request.form.get("username", "")
            now = time.time()
            with login_lock:
                recent = [entry for entry in failed_logins.get(request.remote_addr, []) if now - entry < 60]
                locked = len(recent) >= 5
                valid = (not locked and
                         hmac.compare_digest(username.encode(), ROUTER_ADMIN["username"].encode()) and
                         hmac.compare_digest(request.form.get("password", "").encode(), ROUTER_ADMIN["password"].encode()))
                failed_logins[request.remote_addr] = [] if valid else recent + ([] if locked else [now])
            status = 302 if valid else 429 if locked else 401
            save({"id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
                  "source_ip": request.remote_addr or "unknown", "username": username[:128],
                  "stage": "password", "result": "success" if valid else "rate_limited" if locked else "invalid_credentials",
                  "status": status}, "router")
            if valid:
                session.clear()
                session.permanent = True
                session["admin"] = True
                return redirect(url_for("index"))
            return render_template("login.html", error="Try again in one minute." if locked else "Invalid credentials."), status
        if not session.get("admin"):
            return render_template("login.html")
        device = request.args.get("device", "")
        result = request.args.get("result", "")
        conditions, params = [], []
        if device:
            conditions.append("device = ?")
            params.append(device)
        if result:
            conditions.append("result = ?")
            params.append(result)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with sqlite3.connect(app.config["AUDIT_DB"], timeout=10) as db:
            db.row_factory = sqlite3.Row
            count = db.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0]
            pages = max(1, (count + 199) // 200)
            page = min(pages, max(1, request.args.get("page", 1, type=int)))
            rows = db.execute("SELECT * FROM events" + where + " ORDER BY rowid DESC LIMIT 200 OFFSET ?", [*params, (page - 1) * 200]).fetchall()
        return render_template("events.html", rows=rows, count=count, devices=[*DEVICES, "router"],
                               results=RESULTS, selected_device=device, selected_result=result, page=page, pages=pages)

    @app.get("/firewall")
    def firewall():
        if not session.get("admin"):
            return redirect(url_for("index"))
        try:
            with open(app.config["FIREWALL_LOG"], errors="replace") as file:
                lines = "".join(deque(file, maxlen=200))
        except FileNotFoundError:
            lines = "No firewall events yet."
        return render_template("firewall.html", lines=lines)

    @app.post("/logout")
    def logout():
        check_csrf()
        session.clear()
        return redirect(url_for("index"))

    @app.post("/api/events")
    def ingest():
        # The collector accepts writes only from the five device IPs.
        # Device identity comes from the TCP peer, not a client-controlled field.
        device = clients.get(request.remote_addr)
        if device is None:
            abort(403)
        event = request.get_json(silent=True)
        expected = {"id", "timestamp", "username", "source_ip", "stage", "result", "status"}
        if not isinstance(event, dict) or set(event) != expected:
            abort(400)
        try:
            uuid.UUID(event["id"])
            timestamp = datetime.fromisoformat(event["timestamp"])
            if timestamp.tzinfo is None:
                raise ValueError()
            ipaddress.ip_address(event["source_ip"])
            if not isinstance(event["username"], str) or len(event["username"]) > 128:
                raise ValueError()
            if event["stage"] not in ("password", "mfa") or event["result"] not in RESULTS:
                raise ValueError()
            if type(event["status"]) is not int or not 100 <= event["status"] <= 599:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            abort(400)
        save(event, device)
        return "", 204

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000)
