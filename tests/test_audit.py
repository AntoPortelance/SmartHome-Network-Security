import json
import sqlite3
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from flask import Flask, g
from audit import AuditQueue, configure_audit


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "queue.sqlite3"
        self.queue = AuditQueue(self.path, "http://router.invalid/api/events")

    def count(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT COUNT(*) FROM pending").fetchone()[0]

    def test_outage_preserves_queue_across_recreation(self):
        self.queue.record({"id": "event-1", "username": "test"})
        with patch("audit.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            self.queue.flush()
        self.assertEqual(self.count(), 1)
        restored = AuditQueue(self.path, "http://router.invalid/api/events")
        response = MagicMock()
        response.__enter__.return_value.status = 204
        with patch("audit.urllib.request.urlopen", return_value=response) as sender:
            restored.flush()
            payload = json.loads(sender.call_args.args[0].data)
        self.assertEqual(payload["id"], "event-1")
        self.assertEqual(self.count(), 0)

    def test_non_acknowledgement_does_not_delete_event(self):
        self.queue.record({"id": "event-1"})
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch("audit.urllib.request.urlopen", return_value=response):
            self.queue.flush()
        self.assertEqual(self.count(), 1)


class HookTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-only"
        self.app.config["TESTING"] = True
        with patch("audit.AuditQueue") as queue_class:
            configure_audit(self.app, "camera")
            self.queue = queue_class.return_value

        @self.app.post("/")
        def login():
            g.audit_result = "invalid_credentials"
            return "Denied", 401

        self.client = self.app.test_client()

    def test_attempt_contains_metadata_but_no_secrets(self):
        self.client.post("/", data={"username": "test-user", "password": "hidden-password", "code": "123456"})
        event = self.queue.record.call_args.args[0]
        self.assertEqual(event["username"], "test-user")
        self.assertEqual(event["result"], "invalid_credentials")
        self.assertNotIn("hidden-password", json.dumps(event))
        self.assertNotIn("123456", json.dumps(event))

    def test_storage_failure_denies_access(self):
        self.queue.record.side_effect = sqlite3.OperationalError("disk full")
        with self.assertLogs(self.app.logger, level="ERROR"):
            response = self.client.post("/", data={"username": "test-user"})
        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
