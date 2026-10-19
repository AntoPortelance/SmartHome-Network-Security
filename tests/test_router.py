import re
import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timezone

from app import create_app
from devices_config import DEVICES, ROUTER_ADMIN


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = create_app(self.directory.name)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def event(self, **changes):
        return {"id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
                "username": "audit-test-user", "source_ip": "192.0.2.12", "stage": "password",
                "result": "invalid_credentials", "status": 401, **changes}

    def submit(self, event):
        return self.client.post("/api/events", json=event,
                                environ_base={"REMOTE_ADDR": DEVICES["camera"]["ip"]})

    def count(self):
        with sqlite3.connect(self.app.config["AUDIT_DB"]) as db:
            return db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def csrf(self):
        return re.search(rb'name="csrf" value="([^"]+)"', self.client.get("/").data).group(1).decode()

    def login(self):
        return self.client.post("/", data={**ROUTER_ADMIN, "csrf": self.csrf()})

    def test_logs_require_login(self):
        self.submit(self.event())
        self.assertNotIn(b"audit-test-user", self.client.get("/").data)
        self.assertEqual(self.client.get("/firewall").status_code, 302)
        self.assertEqual(self.client.get("/api/events").status_code, 405)
        self.assertEqual(self.client.get("/connections.sqlite3").status_code, 404)

    def test_login_view_filters_and_logout(self):
        self.submit(self.event())
        self.assertEqual(self.login().status_code, 302)
        self.assertIn(b"audit-test-user", self.client.get("/?device=camera").data)
        self.assertNotIn(b"audit-test-user", self.client.get("/?device=nas").data)
        self.assertNotIn(b"audit-test-user", self.client.get("/?result=success").data)
        self.assertEqual(self.client.get("/firewall").status_code, 200)
        self.client.post("/logout", data={"csrf": self.csrf()})
        self.assertNotIn(b"audit-test-user", self.client.get("/").data)

    def test_bad_admin_password_and_csrf_are_rejected(self):
        self.assertEqual(self.client.post("/", data=ROUTER_ADMIN).status_code, 400)
        response = self.client.post("/", data={"username": ROUTER_ADMIN["username"],
                                               "password": "wrong", "csrf": self.csrf()})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(b"Authentication attempts", response.data)

    def test_collector_accepts_only_known_device_ips(self):
        self.assertEqual(self.client.post("/api/events", json=self.event()).status_code, 403)
        self.assertEqual(self.submit(self.event()).status_code, 204)
        self.assertEqual(self.count(), 1)

    def test_unknown_fields_and_invalid_payloads_are_rejected(self):
        for changes in ({"password": "must-not-be-stored"}, {"device": "nas"},
                        {"status": "401"}, {"source_ip": "not-an-ip"}, {"id": "invalid"}):
            self.assertEqual(self.submit(self.event(**changes)).status_code, 400)
        self.assertEqual(self.count(), 0)

    def test_duplicate_delivery_is_idempotent(self):
        event = self.event()
        self.assertEqual(self.submit(event).status_code, 204)
        self.assertEqual(self.submit(event).status_code, 204)
        self.assertEqual(self.count(), 1)

    def test_file_survives_app_recreation(self):
        self.submit(self.event())
        recreated = create_app(self.directory.name)
        with sqlite3.connect(recreated.config["AUDIT_DB"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def test_untrusted_username_is_escaped(self):
        self.submit(self.event(username="<script>alert(1)</script>"))
        self.login()
        body = self.client.get("/").data
        self.assertIn(b"&lt;script&gt;", body)
        self.assertNotIn(b"<script>alert(1)</script>", body)

    def test_older_records_are_accessible_through_pagination(self):
        self.submit(self.event(username="oldest-event"))
        for _ in range(200):
            self.submit(self.event())
        self.login()
        self.assertNotIn(b"oldest-event", self.client.get("/").data)
        self.assertIn(b"oldest-event", self.client.get("/?page=2").data)


if __name__ == "__main__":
    unittest.main()
