"""Web adaptation of generate_mail_code/check_code from secure_solution.py."""

import hashlib
import os
import secrets
import smtplib
import ssl
import threading
import time
from datetime import timedelta
from email.message import EmailMessage

from flask import redirect, request, session, url_for

from devices_config import DEVICES
from audit import configure_audit

CODE_TTL = 300
MAX_ATTEMPTS = 3
COOLDOWN = 60


def generate_mail_code():
    # Unlike random.randint in the original demo, use a secure generator.
    return f"{secrets.randbelow(1_000_000):06d}"


def send_mail_code(email, device_name, code):
    host = os.environ.get("SMTP_HOST", "")
    username = os.environ.get("SMTP_USERNAME", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", "") or username
    security = os.environ.get("SMTP_SECURITY", "starttls")
    if not host or not username or not password or not sender or not email:
        raise ValueError("SMTP configuration is incomplete")
    if security not in {"starttls", "ssl"}:
        raise ValueError("SMTP requires starttls or ssl")
    port = int(os.environ.get("SMTP_PORT", "465" if security == "ssl" else "587"))
    message = EmailMessage()
    message["Subject"] = f"{device_name} — code de connexion"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Votre code de connexion pour {device_name} est : {code}\n\n"
        "Ce code est valable 5 minutes et ne peut être utilisé qu'une fois.\n"
        "Si vous n'avez pas demandé cette connexion, ignorez ce message.\n"
    )
    context = ssl.create_default_context()
    if security == "ssl":
        connection = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
    else:
        connection = smtplib.SMTP(host, port, timeout=10)
    with connection as smtp:
        if security == "starttls":
            smtp.starttls(context=context)
        smtp.login(username, password)
        smtp.send_message(message)


class MFAState:
    """Keep codes on the server, never in Flask's readable session cookie."""

    def __init__(self):
        self.lock = threading.RLock()
        self.challenges = {}
        self.failures = 0
        self.locked_until = 0
        self.last_sent = None

    def locked(self):
        if self.locked_until and time.time() >= self.locked_until:
            self.failures = 0
            self.locked_until = 0
        return time.time() < self.locked_until

    def failed(self):
        self.failures += 1
        if self.failures >= MAX_ATTEMPTS:
            self.locked_until = time.time() + COOLDOWN
            self.challenges.clear()

    def discard(self):
        self.challenges.pop(session.get("mfa_challenge"), None)
        session.clear()

    def check_code(self, challenge_id, submitted):
        challenge = self.challenges.get(challenge_id)
        if not challenge or time.time() >= challenge["expires"]:
            self.challenges.pop(challenge_id, None)
            return "expired"
        digest = hashlib.sha256(submitted.encode()).hexdigest()
        if not secrets.compare_digest(digest, challenge["digest"]):
            self.failed()
            return "locked" if self.locked() else "invalid"
        del self.challenges[challenge_id]
        self.failures = 0
        return "valid"


def configure_mfa(app, device_key, device_name, render_page):
    configure_audit(app, device_key)
    app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_NAME=f"{device_key}_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )
    device = DEVICES[device_key]
    state = MFAState()
    app.extensions["mfa"] = state

    def authenticated():
        return session.get("authenticated") is True and session.get("device") == device_key

    app.extensions["is_authenticated"] = authenticated

    @app.context_processor
    def auth_context():
        return {"authenticated": authenticated(), "device_name": device_name}

    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_page()
        with state.lock:
            state.discard()
            if state.locked():
                return render_page(error="Too many attempts. Try again in one minute."), 429
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if not (secrets.compare_digest(username.encode(), device["username"].encode())
                    and secrets.compare_digest(password.encode(), device["password"].encode())):
                state.failed()
                return render_page(error="Invalid username or password"), 401
            if state.last_sent is not None and time.time() - state.last_sent < COOLDOWN:
                return render_page(error="Please wait one minute before requesting another code."), 429
            # Discard expired challenges so repeated logins cannot accumulate them.
            state.challenges = {key: value for key, value in state.challenges.items()
                                if value["expires"] > time.time()}
            code = generate_mail_code()
            try:
                send_mail_code(device.get("email", ""), device_name, code)
            except (OSError, smtplib.SMTPException, ValueError) as error:
                # Do not log the code, credentials or SMTP response bodies.
                app.logger.error("MFA email delivery failed (%s)", type(error).__name__)
                return render_page(error="Unable to send the code. Check the SMTP configuration and try again."), 503
            challenge_id = secrets.token_urlsafe(32)
            state.challenges[challenge_id] = {
                "digest": hashlib.sha256(code.encode()).hexdigest(),
                "expires": time.time() + CODE_TTL,
            }
            state.last_sent = time.time()
            session["mfa_challenge"] = challenge_id
            return redirect(url_for("verify_mfa"))

    @app.route("/mfa", methods=["GET", "POST"])
    def verify_mfa():
        with state.lock:
            if state.locked():
                state.discard()
                return render_page(error="Too many attempts. Try again in one minute."), 429
            challenge_id = session.get("mfa_challenge")
            challenge = state.challenges.get(challenge_id)
            if not challenge or time.time() >= challenge["expires"]:
                state.discard()
                return render_page(error="Code expired or unavailable. Log in again."), 401
            if request.method == "GET":
                return render_page(mfa_pending=True)
            outcome = state.check_code(challenge_id, request.form.get("code", ""))
            if outcome == "valid":
                session.clear()
                session.permanent = True
                session["authenticated"] = True
                session["device"] = device_key
                return redirect(url_for("login"))
            if outcome == "invalid":
                return render_page(mfa_pending=True, error="Invalid code. Please try again."), 401
            state.discard()
            return render_page(error="Too many attempts. Log in again in one minute."), 429

    @app.post("/logout")
    def logout():
        with state.lock:
            state.discard()
        return redirect(url_for("login"))
