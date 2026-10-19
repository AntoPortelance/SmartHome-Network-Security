"""Queue authentication events locally and deliver them to the router."""

import json
import os
import sqlite3
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import g, request, session

from devices_config import DEVICES


class AuditQueue:
    def __init__(self, path, url):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.url = url
        self.wake = threading.Event()
        self.flush_lock = threading.Lock()
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        self.path.chmod(0o600)

    def record(self, event):
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("INSERT INTO pending VALUES (?, ?)", (event["id"], json.dumps(event)))
        self.wake.set()

    def flush(self):
        with self.flush_lock:
            with sqlite3.connect(self.path, timeout=10) as db:
                rows = db.execute("SELECT id, payload FROM pending ORDER BY rowid LIMIT 100").fetchall()
            for event_id, payload in rows:
                req = urllib.request.Request(
                    self.url, data=payload.encode(),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=3) as response:
                        if response.status != 204:
                            return
                except (OSError, urllib.error.URLError):
                    return
                with sqlite3.connect(self.path, timeout=10) as db:
                    db.execute("DELETE FROM pending WHERE id = ?", (event_id,))

    def run(self, logger):
        while True:
            self.wake.wait(2)
            self.wake.clear()
            try:
                self.flush()
            except (OSError, sqlite3.Error):
                logger.error("Audit queue could not be delivered; events remain queued")


def configure_audit(app, device_key):
    queue = AuditQueue(
        os.environ.get("AUDIT_QUEUE_PATH", "/var/lib/device-audit/pending.sqlite3"),
        os.environ.get("AUDIT_URL", "http://127.0.0.1:5000/api/events"),
    )
    app.extensions["audit"] = queue
    threading.Thread(target=queue.run, args=(app.logger,), daemon=True).start()

    @app.before_request
    def identify_attempt():
        if request.method != "POST" or request.path not in {"/", "/mfa"}:
            return
        g.audit_stage = "password" if request.path == "/" else "mfa"
        g.audit_username = ""
        if request.path == "/":
            g.audit_username = request.form.get("username", "")[:128]
        else:
            g.audit_username = DEVICES[device_key]["username"] if session.get("mfa_challenge") else ""

    @app.after_request
    def record_attempt(response):
        if not hasattr(g, "audit_stage"):
            return response
        result = getattr(g, "audit_result", None)
        if result is None:
            if response.status_code == 302:
                result = "success" if session.get("authenticated") else "mfa_required"
            elif response.status_code == 429:
                result = "rate_limited"
            elif response.status_code == 503:
                result = "smtp_error"
            elif response.status_code == 401:
                result = "invalid_credentials" if g.audit_stage == "password" else "code_rejected"
            else:
                result = "error"
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": g.audit_username,
            "source_ip": request.remote_addr or "unknown",
            "stage": g.audit_stage,
            "result": result,
            "status": response.status_code,
        }
        try:
            queue.record(event)
        except (OSError, sqlite3.Error):
            app.logger.error("Authentication attempt could not be saved to the audit queue")
            if app.secret_key:
                session.clear()
            return app.make_response(("Audit storage unavailable. Please try again later.", 503))
        return response
