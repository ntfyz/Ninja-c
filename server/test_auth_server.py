from __future__ import annotations

import tempfile
import json
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

from auth_server import LOGIN_PATH, authenticate, create_key, make_handler, set_hwid


class AuthServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "auth.sqlite3"
        create_key(self.database, "TEST-KEY", "TEST-PASS", 30)
        self.hwid_a = "a" * 64
        self.hwid_b = "b" * 64

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_first_login_binds_hwid(self) -> None:
        result = authenticate(self.database, "TEST-KEY", "TEST-PASS", self.hwid_a)
        self.assertEqual(result.status.value, 200)
        self.assertTrue(result.payload["ok"])
        mismatch = authenticate(self.database, "TEST-KEY", "TEST-PASS", self.hwid_b)
        self.assertEqual(mismatch.payload["code"], "device_mismatch")

    def test_hwid_can_be_cleared_and_rebound(self) -> None:
        authenticate(self.database, "TEST-KEY", "TEST-PASS", self.hwid_a)
        set_hwid(self.database, "TEST-KEY", None)
        result = authenticate(self.database, "TEST-KEY", "TEST-PASS", self.hwid_b)
        self.assertTrue(result.payload["ok"])

    def test_bad_password_is_rejected(self) -> None:
        result = authenticate(self.database, "TEST-KEY", "wrong", self.hwid_a)
        self.assertEqual(result.payload["code"], "invalid_credentials")

    def test_http_login_endpoint(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.database))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body = json.dumps(
                {"username": "TEST-KEY", "password": "TEST-PASS", "device_id": self.hwid_a}
            ).encode()
            request = Request(
                f"http://127.0.0.1:{server.server_port}{LOGIN_PATH}",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urlopen(request, timeout=3) as response:
                payload = json.load(response)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["scope"], "authenticated")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
