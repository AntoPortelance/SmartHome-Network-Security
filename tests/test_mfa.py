"""Run inside each MFA container. All email deliveries are mocked."""

import os
import smtplib
import unittest
from unittest.mock import patch

from app import app
from devices_config import DEVICES
from mfa import send_mail_code


class MFATests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        audit_patch = patch.object(app.extensions["audit"], "record")
        self.audit = audit_patch.start()
        self.addCleanup(audit_patch.stop)
        self.client = app.test_client()
        self.key = app.config["SESSION_COOKIE_NAME"].removesuffix("_session")
        self.device = DEVICES[self.key]
        self.credentials = {key: self.device[key] for key in ("username", "password")}
        self.state = app.extensions["mfa"]
        self.state.challenges.clear()
        self.state.failures = 0
        self.state.locked_until = 0
        self.state.last_sent = None
        self.sender_patch = patch("mfa.send_mail_code")
        self.sender = self.sender_patch.start()
        self.addCleanup(self.sender_patch.stop)

    def begin(self):
        response = self.client.post("/", data=self.credentials)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/mfa"))
        recipient, _, code = self.sender.call_args.args
        self.assertEqual(recipient, self.device["email"])
        self.assertRegex(code, r"^[0-9]{6}$")
        return code

    def test_password_alone_does_not_grant_access(self):
        code = self.begin()
        self.assertIn(b"Email verification", self.client.get("/mfa").data)
        with self.client.session_transaction() as session:
            self.assertFalse(session.get("authenticated", False))
            self.assertNotIn(code, str(dict(session)))
        self.assertNotIn(code.encode(), self.client.get("/mfa").data)
        self.assertNotIn(b"access granted", self.client.get("/").data)

    def test_audit_tracks_both_steps_without_codes_or_passwords(self):
        code = self.begin()
        event = self.audit.call_args.args[0]
        self.assertEqual(event["result"], "mfa_required")
        self.assertNotIn(code, str(event))
        self.assertNotIn(self.device["password"], str(event))
        wrong = "000000" if code != "000000" else "000001"
        self.client.post("/mfa", data={"code": wrong})
        self.assertEqual(self.audit.call_args.args[0]["result"], "code_rejected")
        self.client.post("/mfa", data={"code": code})
        event = self.audit.call_args.args[0]
        self.assertEqual(event["result"], "success")
        self.assertEqual(event["stage"], "mfa")
        self.assertEqual(event["username"], self.device["username"])

    def test_valid_code_grants_access_and_logout_revokes_it(self):
        code = self.begin()
        response = self.client.post("/mfa", data={"code": code}, follow_redirects=True)
        self.assertIn(b"access granted", response.data)
        self.assertIn(b"access granted", self.client.get("/").data)
        self.client.post("/logout")
        self.assertNotIn(b"access granted", self.client.get("/").data)

    def test_wrong_password_does_not_send_email(self):
        response = self.client.post("/", data={**self.credentials, "password": "wrong"})
        self.assertEqual(response.status_code, 401)
        self.sender.assert_not_called()

    def test_three_wrong_passwords_lock_account_across_browsers(self):
        for _ in range(3):
            self.client.post("/", data={**self.credentials, "password": "wrong"})
        response = app.test_client().post("/", data=self.credentials)
        self.assertEqual(response.status_code, 429)
        self.sender.assert_not_called()

    def test_three_wrong_codes_lock_account(self):
        code = self.begin()
        wrong = "000000" if code != "000000" else "000001"
        for expected in (401, 401, 429):
            response = self.client.post("/mfa", data={"code": wrong})
            self.assertEqual(response.status_code, expected)
        self.assertEqual(self.client.post("/mfa", data={"code": code}).status_code, 429)
        self.assertEqual(app.test_client().post("/", data=self.credentials).status_code, 429)

    def test_expired_code_is_rejected(self):
        with patch("mfa.time.time", return_value=1000):
            code = self.begin()
        with patch("mfa.time.time", return_value=1301):
            response = self.client.post("/mfa", data={"code": code})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(b"access granted", response.data)

    def test_code_cannot_be_replayed_with_an_old_cookie(self):
        code = self.begin()
        cookie_name = app.config["SESSION_COOKIE_NAME"]
        pending_cookie = self.client.get_cookie(cookie_name).value
        self.assertEqual(self.client.post("/mfa", data={"code": code}).status_code, 302)
        attacker = app.test_client()
        attacker.set_cookie(cookie_name, pending_cookie)
        self.assertEqual(attacker.post("/mfa", data={"code": code}).status_code, 401)

    def test_other_browser_cannot_use_code(self):
        code = self.begin()
        response = app.test_client().post("/mfa", data={"code": code})
        self.assertEqual(response.status_code, 401)

    def test_smtp_failure_does_not_grant_access(self):
        self.sender.side_effect = smtplib.SMTPException("test failure")
        with self.assertLogs(app.logger, level="ERROR"):
            response = self.client.post("/", data=self.credentials)
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.state.challenges)
        self.assertNotIn(b"access granted", self.client.get("/").data)

    def test_email_requests_are_limited(self):
        self.begin()
        response = app.test_client().post("/", data=self.credentials)
        self.assertEqual(response.status_code, 429)
        self.sender.assert_called_once()

    def test_recipient_cannot_be_overridden_by_form(self):
        self.client.post("/", data={**self.credentials, "email": "other@example.test"})
        self.assertEqual(self.sender.call_args.args[0], self.device["email"])

    def test_nas_ping_requires_completed_mfa(self):
        if self.key != "nas":
            self.skipTest("NAS-only route")
        data = {"ip": DEVICES["laptop"]["ip"]}
        self.assertEqual(self.client.post("/ping", data=data).status_code, 302)
        code = self.begin()
        self.assertEqual(self.client.post("/ping", data=data).status_code, 302)
        self.client.post("/mfa", data={"code": code})
        with patch("app.subprocess.run") as ping:
            ping.return_value.returncode = 1
            ping.return_value.stdout = "100% packet loss"
            ping.return_value.stderr = ""
            response = self.client.post("/ping", data=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"100% packet loss", response.data)


class SMTPTests(unittest.TestCase):
    def test_starttls_and_registered_recipient(self):
        settings = {
            "SMTP_HOST": "smtp.example.test", "SMTP_PORT": "587",
            "SMTP_SECURITY": "starttls", "SMTP_USERNAME": "sender@example.test",
            "SMTP_PASSWORD": "test-only", "SMTP_FROM": "sender@example.test",
        }
        with patch.dict(os.environ, settings, clear=True), patch("mfa.smtplib.SMTP") as smtp:
            send_mail_code("recipient@example.test", "NAS", "012345")
            connection = smtp.return_value.__enter__.return_value
            connection.starttls.assert_called_once()
            connection.login.assert_called_once_with("sender@example.test", "test-only")
            message = connection.send_message.call_args.args[0]
            self.assertEqual(message["To"], "recipient@example.test")
            self.assertIn("012345", message.get_content())

    def test_ssl_transport(self):
        settings = {
            "SMTP_HOST": "smtp.example.test", "SMTP_SECURITY": "ssl",
            "SMTP_USERNAME": "sender@example.test", "SMTP_PASSWORD": "test-only",
        }
        with patch.dict(os.environ, settings, clear=True), patch("mfa.smtplib.SMTP_SSL") as smtp:
            send_mail_code("recipient@example.test", "NAS", "012345")
            self.assertEqual(smtp.call_args.args, ("smtp.example.test", 465))
            smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_missing_settings_fail_before_connecting(self):
        with patch.dict(os.environ, {}, clear=True), patch("mfa.smtplib.SMTP") as smtp:
            with self.assertRaises(ValueError):
                send_mail_code("recipient@example.test", "NAS", "012345")
            smtp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
