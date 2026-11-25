from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

from app import web
from app.config import Config


def make_config(
    directory: Path,
    *,
    auth_mode: str = "dev",
    proxy_shared_secret: str | None = None,
    base_url: str | None = None,
    allowed_origins: tuple[str, ...] = (),
) -> Config:
    return Config(
        auth_mode=auth_mode,
        data_dir=directory,
        database_path=directory / "test.db",
        secret_key="test-secret-key-that-is-long-enough-1234567890",
        pn_encryption_key=None,
        cookie_secure=False,
        proxy_shared_secret=proxy_shared_secret,
        base_url=base_url,
        proxy_logout_url=None,
        github_url="https://github.com/RogerBergling/verify",
        allowed_origins=allowed_origins,
    )


class ConfigValidationTests(unittest.TestCase):
    def test_proxy_mode_requires_a_proxy_shared_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "AUTH_MODE": "proxy",
                "SECRET_KEY": "x" * 64,
                "BASE_URL": "https://verify.example.test",
                "DATA_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(SystemExit) as caught:
                    Config.from_env()
            self.assertIn("PROXY_SHARED_SECRET", str(caught.exception))

    def test_proxy_mode_rejects_the_example_placeholder_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "AUTH_MODE": "proxy",
                "SECRET_KEY": "change-me-to-a-long-random-string-at-least-32-chars",
                "PROXY_SHARED_SECRET": "p" * 64,
                "BASE_URL": "https://verify.example.test",
                "DATA_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(SystemExit) as caught:
                    Config.from_env()
            self.assertIn("placeholder", str(caught.exception))


class Client:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.jar = http.cookiejar.CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict, bytes]:
        url = path if path.startswith("http") else self.base_url + path
        data = None
        request_headers = {"User-Agent": "VerifyTest/1.0"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)
        request = Request(url, data=data, headers=request_headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status, dict(response.headers), response.read()
        except HTTPError as exc:
            raw = exc.read()
            exc.close()
            return exc.code, dict(exc.headers), raw

    def get(self, path: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
        return self.request("GET", path, headers=headers)

    def post_json(
        self, path: str, payload: dict | None = None, *, csrf: bool = True
    ) -> tuple[int, dict | None, bytes]:
        headers = {"X-CSRF-Token": self.csrf} if csrf else {}
        status, response_headers, raw = self.request(
            "POST", path, body=payload or {}, headers=headers
        )
        try:
            data = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            data = None
        return status, data, raw

    def login(self, user: str) -> str:
        status, _, raw = self.get(f"/dev/login?user={user}&next=/")
        text = raw.decode("utf-8", "replace")
        match = re.search(r'<meta name="csrf-token" content="([^"]*)"', text)
        self.csrf = match.group(1) if match else ""
        return text


class VerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.config = make_config(self.directory)
        web.RATE_LIMITER = web.RateLimiter()
        self.server = web.create_server(self.config, host="127.0.0.1", port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.servers = [self.server]

    def tearDown(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.tmp.cleanup()

    def client(self) -> Client:
        return Client(self.base)

    def start_extra_server(self, config: Config) -> Client:
        web.RATE_LIMITER = web.RateLimiter()
        server = web.create_server(config, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append(server)
        return Client(f"http://127.0.0.1:{server.server_address[1]}")

    def create_and_join(
        self, *, pn_mode: str = "masked", kind: str = "one_to_one"
    ) -> tuple[Client, Client, str, str, dict, dict]:
        alice = self.client()
        alice.login("alice")
        status, data, _ = alice.post_json(
            "/api/sessions",
            {
                "kind": kind,
                "context": "Test session",
                "pn_mode": pn_mode,
                "duration_minutes": 5,
            },
        )
        self.assertEqual(status, 201, data)
        assert data is not None
        session_id = data["id"]
        token = data["join_url"].rsplit("/", 1)[1]
        self.assertEqual(data["view"]["state"], "waiting")

        bob = self.client()
        bob.login("bob")
        status, _, raw = bob.get(f"/join/{token}")
        self.assertEqual(status, 200, raw.decode("utf-8", "replace"))

        status, joined, _ = bob.post_json(
            f"/api/sessions/{session_id}/join", {"token": token}
        )
        self.assertEqual(status, 200, joined)
        assert joined is not None
        self.assertEqual(joined["session"]["state"], "ready")
        return alice, bob, session_id, token, data, joined

    def test_health_and_login(self) -> None:
        client = self.client()
        status, _, raw = client.get("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw)["ok"])

        text = client.login("alice")
        self.assertIn("Start a verification", text)
        status, _, howto = client.get("/how-it-works")
        self.assertEqual(status, 200)
        self.assertIn(b"What to share", howto)
        self.assertIn(b"Who can hear the code", howto)
        status, data, _ = client.post_json(
            "/api/sessions",
            {
                "kind": "one_to_one",
                "context": "",
                "pn_mode": "masked",
                "duration_minutes": 5,
            },
        )
        self.assertEqual(status, 201, data)

    def test_invite_link_uses_configured_public_base_url(self) -> None:
        public_dir = self.directory / "public-base"
        public_dir.mkdir()
        config = make_config(public_dir, base_url="https://verify.example.test")
        client = self.start_extra_server(config)
        client.login("alice")
        status, data, _ = client.post_json(
            "/api/sessions",
            {
                "kind": "one_to_one",
                "context": "",
                "pn_mode": "masked",
                "duration_minutes": 5,
            },
        )
        self.assertEqual(status, 201, data)
        self.assertTrue(
            data["join_url"].startswith("https://verify.example.test/join/"),
            data["join_url"],
        )

    def test_language_detection_and_switch(self) -> None:
        client = self.client()
        client.login("alice")

        status, _, raw = client.get(
            "/", headers={"Accept-Language": "sv-SE,sv;q=0.9,en;q=0.8"}
        )
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn('lang="sv"', text)
        self.assertIn("Starta en verifiering", text)

        status, _, raw = client.get("/lang/en?next=/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn('lang="en"', text)
        self.assertIn("Start a verification", text)

        status, _, raw = client.get("/lang/sv?next=/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn('lang="sv"', text)
        self.assertIn("Starta en verifiering", text)

    def test_csrf_required(self) -> None:
        alice = self.client()
        alice.login("alice")
        status, data, _ = alice.post_json(
            "/api/sessions",
            {"kind": "one_to_one", "context": "", "pn_mode": "full"},
            csrf=False,
        )
        self.assertEqual(status, 403)
        self.assertEqual(data["error"]["code"], "csrf")

    def test_origin_accepts_same_host_even_if_base_url_differs(self) -> None:
        origin_dir = self.directory / "origin"
        origin_dir.mkdir()
        origin_config = make_config(
            origin_dir, base_url="https://wrong.example"
        )
        client = self.start_extra_server(origin_config)
        client.login("alice")

        payload = {
            "kind": "one_to_one",
            "context": "Origin test",
            "pn_mode": "masked",
            "duration_minutes": 5,
        }
        status, data, _ = client.request(
            "POST",
            "/api/sessions",
            body=payload,
            headers={
                "X-CSRF-Token": client.csrf,
                "Origin": client.base_url,
            },
        )
        self.assertEqual(status, 201, data)

        status, _, data = client.request(
            "POST",
            "/api/sessions",
            body=payload,
            headers={
                "X-CSRF-Token": client.csrf,
                "Origin": "https://evil.example",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(data)["error"]["code"], "origin")

    def test_forged_header_ignored_in_dev(self) -> None:
        alice = self.client()
        alice.login("alice")
        status, _, raw = alice.request(
            "GET",
            "/api/security-check",
            headers={"X-User-Id": "u-bob"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(raw)
        self.assertTrue(payload["ignored"])
        self.assertEqual(payload["identity"]["subject"], "dev:alice")
        self.assertEqual(payload["forged_user_id_header"], "u-bob")

    def test_full_flow_and_receipt(self) -> None:
        alice, bob, session_id, token, created, joined = self.create_and_join()

        status, _, view_data = alice.get(f"/api/sessions/{session_id}")
        self.assertEqual(status, 200)
        view = json.loads(view_data)["session"]
        self.assertEqual(view["state"], "ready")
        self.assertEqual(len(view["participants"]), 2)
        bob_view = next(p for p in view["participants"] if not p["is_me"])
        self.assertIsNone(bob_view["pn"])
        self.assertFalse(bob_view["pn_shared"])
        self.assertNotIn("code", view)
        self.assertNotIn("code", bob_view)
        self.assertNotIn("words", bob_view)
        self.assertNotIn("expires_in", view)
        self.assertIn("my_code", view)

        status, _, bob_data = bob.get(f"/api/sessions/{session_id}")
        bob_session = json.loads(bob_data)["session"]
        alice_view = next(p for p in bob_session["participants"] if not p["is_me"])
        self.assertIsNone(alice_view["pn"])
        self.assertFalse(alice_view["pn_shared"])

        alice_code = created["view"]["my_code"]
        bob_code = joined["session"]["my_code"]
        self.assertNotEqual(alice_code, bob_code)
        roster = joined["session"]["roster_version"]
        status, alice_confirmed, _ = alice.post_json(
            f"/api/sessions/{session_id}/confirm",
            {
                "decision": "match",
                "roster_version": roster,
                "code": bob_code,
            },
        )
        self.assertEqual(status, 200, alice_confirmed)
        self.assertEqual(alice_confirmed["session"]["state"], "confirming")
        self.assertTrue(alice_confirmed["session"]["my_confirmed"])

        status, bob_confirmed, _ = bob.post_json(
            f"/api/sessions/{session_id}/confirm",
            {
                "decision": "match",
                "roster_version": roster,
                "code": alice_code,
            },
        )
        self.assertEqual(status, 200, bob_confirmed)
        final = bob_confirmed["session"]
        self.assertEqual(final["state"], "verified")
        self.assertIsNotNone(final["receipt"])
        receipt_id = final["receipt"]["id"]

        status, _, receipt_data = alice.get(f"/api/receipts/{receipt_id}")
        self.assertEqual(status, 200)
        receipt = json.loads(receipt_data)
        self.assertEqual(receipt["payload"]["reference"], final["public_ref"])
        self.assertEqual(len(receipt["payload"]["participants"]), 2)
        for participant in receipt["payload"]["participants"]:
            self.assertNotIn("19900101-1234", participant["pn_masked"])
            self.assertNotIn("19850202-5678", participant["pn_masked"])

        status, _, raw = alice.get(f"/receipts/{receipt_id}")
        self.assertEqual(status, 200)
        self.assertIn(b"Verification receipt", raw)

    def test_single_use_token_and_idor(self) -> None:
        alice, bob, session_id, token, _, _ = self.create_and_join()

        agent = self.client()
        agent.login("agent")
        status, _, _ = agent.get(f"/api/sessions/{session_id}")
        self.assertIn(status, {403, 404})

        status, data, _ = agent.post_json(
            f"/api/sessions/{session_id}/join", {"token": token}
        )
        self.assertEqual(status, 410)
        self.assertEqual(data["error"]["code"], "used")

    def test_wrong_or_missing_counterpart_code_is_rejected(self) -> None:
        alice, bob, session_id, token, created, joined = self.create_and_join()
        roster = joined["session"]["roster_version"]

        status, data, _ = alice.post_json(
            f"/api/sessions/{session_id}/confirm",
            {"decision": "match", "roster_version": roster, "code": ""},
        )
        self.assertEqual(status, 422)
        self.assertEqual(data["error"]["code"], "invalid_code")

        status, data, _ = alice.post_json(
            f"/api/sessions/{session_id}/confirm",
            {
                "decision": "match",
                "roster_version": roster,
                "code": joined["session"]["my_code"],
            },
        )
        self.assertEqual(status, 200, data)

    def test_mismatch_creates_no_receipt(self) -> None:
        alice, bob, session_id, token, _, joined = self.create_and_join()
        roster = joined["session"]["roster_version"]
        status, data, _ = bob.post_json(
            f"/api/sessions/{session_id}/confirm",
            {"decision": "no_match", "roster_version": roster},
        )
        self.assertEqual(status, 200, data)
        self.assertEqual(data["session"]["state"], "mismatch")
        self.assertIsNone(data["session"]["receipt"])

        status, _, alice_data = alice.get(f"/api/sessions/{session_id}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(alice_data)["session"]["state"], "mismatch")

    def test_cannot_confirm_before_both_join(self) -> None:
        alice = self.client()
        alice.login("alice")
        status, data, _ = alice.post_json(
            "/api/sessions",
            {
                "kind": "one_to_one",
                "context": "",
                "pn_mode": "masked",
                "duration_minutes": 5,
            },
        )
        self.assertEqual(status, 201, data)
        session_id = data["id"]
        token = data["join_url"].rsplit("/", 1)[1]

        status, blocked, _ = alice.post_json(
            f"/api/sessions/{session_id}/confirm",
            {"decision": "match", "roster_version": data["view"]["roster_version"]},
        )
        self.assertEqual(status, 409)
        self.assertEqual(blocked["error"]["code"], "not_ready")

        bob = self.client()
        bob.login("bob")
        status, joined, _ = bob.post_json(
            f"/api/sessions/{session_id}/join", {"token": token}
        )
        self.assertEqual(status, 200, joined)
        roster = joined["session"]["roster_version"]

        status, _, alice_data = alice.get(f"/api/sessions/{session_id}")
        alice_view = json.loads(alice_data)["session"]
        self.assertFalse(alice_view["my_confirmed"])

        status, _, _ = bob.post_json(
            f"/api/sessions/{session_id}/confirm",
            {
                "decision": "match",
                "roster_version": roster,
                "code": data["view"]["my_code"],
            },
        )
        self.assertEqual(status, 200)
        status, final, _ = alice.post_json(
            f"/api/sessions/{session_id}/confirm",
            {
                "decision": "match",
                "roster_version": roster,
                "code": joined["session"]["my_code"],
            },
        )
        self.assertEqual(status, 200, final)
        self.assertEqual(final["session"]["state"], "verified")

    def test_full_mode_does_not_disclose_the_other_persons_number(self) -> None:
        alice, bob, session_id, token, created, joined = self.create_and_join(
            pn_mode="full"
        )
        status, _, alice_data = alice.get(f"/api/sessions/{session_id}")
        alice_view = json.loads(alice_data)["session"]
        bob_view = next(p for p in alice_view["participants"] if not p["is_me"])
        self.assertIsNone(bob_view["pn"])
        self.assertFalse(bob_view["pn_shared"])

        # Alice can still explicitly reveal her own number to Bob.
        status, _, _ = alice.post_json(f"/api/sessions/{session_id}/reveal", {})
        self.assertEqual(status, 200)
        status, _, bob_data = bob.get(f"/api/sessions/{session_id}")
        bob_session = json.loads(bob_data)["session"]
        alice_from_bob = next(p for p in bob_session["participants"] if not p["is_me"])
        self.assertEqual(alice_from_bob["pn"], "19900101-1234")

    def test_masked_reveal(self) -> None:
        alice, bob, session_id, token, created, joined = self.create_and_join(
            pn_mode="masked"
        )
        status, _, alice_data = alice.get(f"/api/sessions/{session_id}")
        alice_view = json.loads(alice_data)["session"]
        bob_view = next(p for p in alice_view["participants"] if not p["is_me"])
        self.assertIsNone(bob_view["pn"])
        self.assertFalse(bob_view["pn_shared"])

        status, reveal_data, _ = alice.post_json(
            f"/api/sessions/{session_id}/reveal", {}
        )
        self.assertEqual(status, 200, reveal_data)

        status, _, bob_data = bob.get(f"/api/sessions/{session_id}")
        bob_session = json.loads(bob_data)["session"]
        alice_view = next(p for p in bob_session["participants"] if not p["is_me"])
        self.assertEqual(alice_view["pn"], "19900101-1234")

    def test_expiry(self) -> None:
        alice, bob, session_id, token, created, joined = self.create_and_join()
        conn = sqlite3.connect(self.config.database_path)
        try:
            conn.execute(
                "UPDATE verifications SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?",
                (session_id,),
            )
            conn.commit()
        finally:
            conn.close()
        status, _, data = alice.get(f"/api/sessions/{session_id}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["session"]["state"], "expired")

    def test_personal_number_encrypted_at_rest(self) -> None:
        self.create_and_join()
        conn = sqlite3.connect(self.config.database_path)
        try:
            participant_rows = conn.execute(
                "SELECT pn_encrypted, pn_masked FROM participants"
            ).fetchall()
            user_rows = conn.execute(
                "SELECT pn_encrypted, pn_masked FROM users"
            ).fetchall()
        finally:
            conn.close()
        self.assertTrue(participant_rows)
        for encrypted, masked in participant_rows:
            self.assertIsNotNone(encrypted)
            self.assertNotIn("19900101-1234", encrypted or "")
            self.assertNotIn("19850202-5678", encrypted or "")
            self.assertTrue(masked)
        for encrypted, masked in user_rows:
            self.assertIsNotNone(encrypted)
            self.assertNotIn("19900101-1234", encrypted or "")
            self.assertNotIn("19850202-5678", encrypted or "")

    def test_proxy_mode_headers(self) -> None:
        proxy_config = make_config(
            self.directory / "proxy", auth_mode="proxy", proxy_shared_secret="proxy-secret"
        )
        proxy_config.data_dir.mkdir(parents=True, exist_ok=True)
        proxy = self.start_extra_server(proxy_config)

        status, _, _ = proxy.get("/")
        self.assertEqual(status, 401)

        headers = {
            "X-User-Id": "proxy-user-1",
            "X-Name": "Proxy",
            "X-Last-Name": "User",
            "X-Person-Id": "19900101-9999",
            "X-Proxy-Secret": "proxy-secret",
        }
        status, _, raw = proxy.get("/", headers=headers)
        self.assertEqual(status, 200, raw.decode("utf-8", "replace"))
        status, _, data = proxy.get("/api/me", headers=headers)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["subject"], "proxy-user-1")
        self.assertEqual(payload["name"], "Proxy User")
        self.assertEqual(payload["assurance"], "proxy")

        wrong = dict(headers)
        wrong["X-Proxy-Secret"] = "wrong"
        status, _, _ = proxy.get("/", headers=wrong)
        self.assertEqual(status, 401)

        missing = dict(headers)
        missing.pop("X-User-Id")
        status, _, _ = proxy.get("/", headers=missing)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
