import hashlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs
from urllib.request import Request

from test_downloads import Response

from archive_station.archive import ArchiveClient, ArchiveRedirects
from archive_station.archive_account import (
    CHANGED,
    DENIED,
    LOGIN_URL,
    UNAVAILABLE,
    AccountError,
    ArchiveAccount,
    NoLoginRedirects,
)
from archive_station.config import Settings
from archive_station.engine import Engine
from archive_station.store import Store
from archive_station.web import WebApp

EMAIL = "reader@example.test"
PASSWORD = "fixture-password-must-never-be-saved"
SIGNATURE = "fixture-session-signature"


def login_response(**overrides):
    data = {
        "success": True,
        "values": {
            "cookies": {
                "logged-in-user": "reader%40example.test; Path=/; Domain=.archive.org; Secure",
                "logged-in-sig": SIGNATURE + "; Path=/; Domain=.archive.org; Secure; Max-Age=3600",
            },
            "s3": {"access": "unused-access", "secret": "unused-secret"},
        },
    }
    data.update(overrides)
    return io.BytesIO(json.dumps(data).encode())


def connect(account):
    with patch("archive_station.archive_account.build_opener") as opener:
        opener.return_value.open.return_value = login_response()
        return account.connect(EMAIL, PASSWORD)


class AccountBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)
        self.account = ArchiveAccount(self.root, clock=lambda: 1000)


class AccountTests(AccountBase):
    def test_login_posts_only_to_archive_and_persists_cookies_without_password_or_s3_keys(self):
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            status = self.account.connect(EMAIL, PASSWORD)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, LOGIN_URL)
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(
                parse_qs(request.data.decode()), {"email": [EMAIL], "password": [PASSWORD]}
            )
            self.assertNotIn(PASSWORD, request.full_url)
            self.assertIsInstance(opener.call_args.args[0], NoLoginRedirects)
            self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 15)
        self.assertEqual(
            status,
            {
                "connected": True,
                "state": "connected",
                "email": EMAIL,
                "remember_credentials": False,
                "remember_choice": False,
                "reconnect_error": None,
            },
        )
        saved = self.account.path.read_text()
        for secret in (PASSWORD, "unused-access", "unused-secret"):
            self.assertNotIn(secret, saved)
        self.assertEqual(self.account.path.stat().st_mode & 0o777, 0o600)
        restarted = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertEqual(restarted.status(), status)
        self.assertEqual(
            restarted.snapshot()[1],
            f"logged-in-user=reader%40example.test; logged-in-sig={SIGNATURE}",
        )
        self.assertNotIn(SIGNATURE, json.dumps(status))
        self.assertFalse(list(self.root.glob(".archive-account-*")))

    def test_disconnect_removes_saved_session_and_expiry_never_sends_cookies(self):
        connect(self.account)
        expired = ArchiveAccount(self.root, clock=lambda: 5000)
        self.assertFalse(expired.status()["connected"])
        self.assertEqual(expired.status()["state"], "expired")
        self.assertEqual(expired.snapshot()[1], "")
        self.assertEqual(self.account.disconnect()["state"], "disconnected")
        self.assertFalse(self.account.path.exists())
        self.assertEqual(self.account.snapshot()[1], "")

    def test_bad_credentials_or_network_errors_do_not_expose_upstream_response(self):
        for response in (
            login_response(success=False, error=PASSWORD + SIGNATURE),
            io.BytesIO(("<html>" + PASSWORD).encode()),
        ):
            account = ArchiveAccount()
            with patch("archive_station.archive_account.build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(AccountError) as error:
                    account.connect(EMAIL, PASSWORD)
            self.assertNotIn(PASSWORD, str(error.exception))
            self.assertNotIn(SIGNATURE, str(error.exception))
            self.assertFalse(account.status()["connected"])
        for failure in (URLError(PASSWORD), HTTPError(LOGIN_URL, 403, PASSWORD, {}, None)):
            with patch("archive_station.archive_account.build_opener") as opener:
                opener.return_value.open.side_effect = failure
                with self.assertRaises(AccountError) as error:
                    ArchiveAccount().connect(EMAIL, PASSWORD)
            self.assertIn(str(error.exception), (DENIED, UNAVAILABLE))

    def test_invalid_login_input_never_makes_a_request(self):
        for email, password in (
            (None, PASSWORD),
            (EMAIL, None),
            ("x\n@example.test", PASSWORD),
            (EMAIL, ""),
            (EMAIL, "x" * 4097),
        ):
            with patch("archive_station.archive_account.build_opener") as opener:
                with self.assertRaises(AccountError):
                    self.account.connect(email, password)
                opener.assert_not_called()

    def test_login_redirects_are_refused_even_within_archive(self):
        for url in (
            "https://archive.org/account/login",
            "https://example.test/login",
            "http://archive.org/login",
        ):
            with self.assertRaises(AccountError):
                NoLoginRedirects().redirect_request(
                    Request(LOGIN_URL, data=b"password=x"), None, 307, "redirect", {}, url
                )

    def test_cookie_header_injection_and_missing_cookies_are_refused(self):
        for value in ("bad\r\nX-Secret: yes", '"quoted;value"', "a" * 9000):
            response = login_response()
            data = json.load(response)
            data["values"]["cookies"]["logged-in-sig"] = value
            with patch("archive_station.archive_account.build_opener") as opener:
                opener.return_value.open.return_value = io.BytesIO(json.dumps(data).encode())
                with self.assertRaises(AccountError):
                    ArchiveAccount().connect(EMAIL, PASSWORD)
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response(values={})
            with self.assertRaises(AccountError):
                ArchiveAccount().connect(EMAIL, PASSWORD)

    def test_failed_login_keeps_existing_session_and_failed_save_does_not_change_it(self):
        connect(self.account)
        before = self.account.path.read_bytes()
        self.account.last_attempt = float("-inf")
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response(success=False)
            with self.assertRaises(AccountError):
                self.account.connect(EMAIL, "wrong")
        self.assertEqual(self.account.path.read_bytes(), before)
        self.account.last_attempt = float("-inf")
        with patch("archive_station.archive_account.os.replace", side_effect=OSError("full")):
            with self.assertRaises(AccountError):
                connect(self.account)
        self.assertEqual(self.account.path.read_bytes(), before)
        self.assertTrue(self.account.status()["connected"])

    def test_disconnect_wins_over_a_pending_login_and_concurrent_login_is_rejected(self):
        started, release = threading.Event(), threading.Event()
        errors = []

        def network(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(5))
            return login_response()

        def login():
            try:
                self.account.connect(EMAIL, PASSWORD)
            except AccountError as error:
                errors.append(str(error))

        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.side_effect = network
            worker = threading.Thread(target=login)
            worker.start()
            try:
                self.assertTrue(started.wait(5))
                with self.assertRaises(AccountError):
                    self.account.connect(EMAIL, PASSWORD)
                self.account.disconnect()
            finally:
                release.set()
                worker.join(5)
        self.assertEqual(errors, [CHANGED])
        self.assertFalse(self.account.path.exists())

    def test_corrupt_or_symlink_session_file_is_ignored(self):
        self.account.path.write_text("{broken")
        self.assertFalse(ArchiveAccount(self.root).status()["connected"])
        self.account.path.unlink()
        target = self.root / "target"
        target.write_text("do not touch")
        self.account.path.symlink_to(target)
        self.assertFalse(ArchiveAccount(self.root).status()["connected"])
        self.assertEqual(target.read_text(), "do not touch")
        self.account.path.unlink()
        os.mkfifo(self.account.path)
        self.assertFalse(ArchiveAccount(self.root).status()["connected"])


class AuthenticatedDownloadTests(AccountBase):
    def test_private_files_require_account_and_metadata_cache_is_invalidated(self):
        client = ArchiveClient(self.account)
        payload = {
            "files": [
                {"name": "info.xml"},
                {"name": "restricted.zip", "private": "true", "size": "12", "sha1": "1" * 40},
            ]
        }
        with patch("archive_station.archive.build_opener") as opener:
            opener.return_value.open.side_effect = lambda *a, **kw: io.BytesIO(
                json.dumps(payload).encode()
            )
            public = client.manifest("test-item")
            self.assertEqual(len(public["files"]), 1)
            self.assertEqual(public["private_files"], 1)
            connect(self.account)
            full = client.manifest("test-item")
            request = opener.return_value.open.call_args.args[0]
            self.assertIn(SIGNATURE, request.get_header("Cookie"))
            self.assertEqual(len(full["files"]), 2)
            self.assertEqual(full["restricted_files"], 1)
            self.assertEqual(full["private_files"], 0)
            self.assertEqual(
                client.manifest("test-item", pattern="*.zip")["files"][0]["name"], "restricted.zip"
            )
            self.account.disconnect()
            self.assertEqual(len(client.manifest("test-item")["files"]), 1)
            self.assertIsNone(opener.return_value.open.call_args.args[0].get_header("Cookie"))
            self.assertEqual(opener.return_value.open.call_count, 3)

    def test_resume_sends_cookies_and_range_and_rejects_login_html(self):
        connect(self.account)
        client = ArchiveClient(self.account)
        with patch("archive_station.archive.build_opener") as opener:
            response = Mock(
                headers={"Content-Type": "application/zip"},
                url="https://archive.org/download/test-item/restricted.zip",
            )
            opener.return_value.open.return_value = response
            self.assertIs(client.open("test-item", "restricted.zip", 1024), response)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header("Range"), "bytes=1024-")
            self.assertIn(SIGNATURE, request.get_header("Cookie"))
            response.headers = {"Content-Type": "text/html; charset=utf-8"}
            response.url = "https://archive.org/account/login"
            with self.assertRaises(HTTPError) as error:
                client.open("test-item", "restricted.zip")
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
            response.close.assert_called_once()

    def test_credentials_never_follow_external_or_insecure_redirects(self):
        request = Request(
            "https://archive.org/download/test/file.zip",
            headers={"Cookie": f"logged-in-sig={SIGNATURE}"},
        )
        for url in (
            "https://archive.org.evil.test/file",
            "http://archive.org/file",
            "https://evil.test/file",
            "https://archive.org:8443/file",
        ):
            with self.assertRaises(ValueError):
                ArchiveRedirects().redirect_request(request, None, 302, "", {}, url)
        follow = ArchiveRedirects().redirect_request(
            request, None, 302, "", {}, "https://ia600001.us.archive.org/file.zip"
        )
        self.assertIn(SIGNATURE, follow.get_header("Cookie"))
        with self.assertRaises(HTTPError) as error:
            ArchiveRedirects().redirect_request(
                request, None, 302, "", {}, "https://archive.org/account/login"
            )
        error.exception.close()

    def test_saved_session_resumes_and_verifies_a_restricted_file(self):
        connect(self.account)
        client = ArchiveClient(ArchiveAccount(self.root, clock=lambda: 1001))
        data = b"fixture restricted content" * 200
        client.cache["test-item"] = (
            time.monotonic(),
            {
                "files": [
                    {
                        "name": "private.bin",
                        "private": True,
                        "size": str(len(data)),
                        "sha1": hashlib.sha1(data).hexdigest(),
                    }
                ]
            },
        )
        store = Store(self.root / "transfer.sqlite3")
        self.addCleanup(store.close)
        settings = Settings(self.root / "data", self.root / "downloads", [self.root])
        settings.update({"disk_reserve_mib": 0})
        job_id = store.add(client.manifest("test-item"), "all", "", self.root / "downloads")
        row = store.claim()
        partial = self.root / f"downloads/.archive-station-parts/{job_id}/{row['id']}.part"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(data[:128])
        engine = Engine(store, client, settings)
        self.addCleanup(engine.shutdown)
        with patch("archive_station.archive.build_opener") as opener:
            opener.return_value.open.return_value = Response(
                data[128:],
                206,
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Range": f"bytes 128-{len(data) - 1}/{len(data)}",
                },
            )
            engine.transfer(row)
            request = opener.return_value.open.call_args.args[0]
            self.assertIn(SIGNATURE, request.get_header("Cookie"))
            self.assertEqual(request.get_header("Range"), "bytes=128-")
        self.assertEqual((self.root / "downloads/test-item/private.bin").read_bytes(), data)
        self.assertFalse(partial.exists())

    def test_account_changed_during_metadata_fetch_cannot_publish_stale_selection(self):
        client = ArchiveClient(self.account)

        def network(*args, **kwargs):
            self.account.disconnect()
            return io.BytesIO(b'{"files":[{"name":"file.zip"}]}')

        with patch("archive_station.archive.build_opener") as opener:
            opener.return_value.open.side_effect = network
            with self.assertRaisesRegex(AccountError, "changé"):
                client.manifest("test-item")
        self.assertEqual(client.cache, {})


class AccountApiTests(AccountBase):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root / "state.sqlite3")
        self.addCleanup(self.store.close)
        settings = Settings(self.root / "data", self.root / "downloads", [self.root])
        self.client = ArchiveClient(self.account)
        self.app = WebApp(self.store, self.client, settings, self.root, dsm_auth=True)
        self.addCleanup(self.app.updates.shutdown)

    def request(self, path, body=None, auth=True, origin=None):
        raw = json.dumps(body).encode() if body is not None else b""
        env = {
            "PATH_INFO": path,
            "REQUEST_METHOD": "POST" if body is not None else "GET",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_HOST": "nas.test",
        }
        if auth:
            env["HTTP_X_ARCHIVE_STATION_DSM_AUTHENTICATED"] = "1"
        if origin:
            env["HTTP_ORIGIN"] = origin
        result = []
        data = b"".join(self.app(env, lambda status, headers: result.append(status)))
        return int(result[0].split()[0]), json.loads(data)

    def test_account_endpoints_require_dsm_and_same_origin(self):
        for endpoint in ("login", "logout", "forget"):
            with patch.object(self.account, "connect") as login:
                self.assertEqual(
                    self.request("/api/archive-account/" + endpoint, {}, auth=False)[0], 401
                )
                self.assertEqual(
                    self.request(
                        "/api/archive-account/" + endpoint, {}, origin="https://evil.test"
                    )[0],
                    403,
                )
                login.assert_not_called()

    def test_login_and_logout_clear_plans_and_settings_never_expose_secrets(self):
        token = self.app.plans.create(
            {"identifier": "item", "files": [{"name": "file", "size": 1}]}, "all", ""
        )
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            code, status = self.request(
                "/api/archive-account/login", {"email": EMAIL, "password": PASSWORD}
            )
        self.assertEqual(code, 200)
        self.assertTrue(status["connected"])
        with self.assertRaises(ValueError):
            self.app.plans.selection(token, "item")
        code, settings = self.request("/api/settings")
        self.assertEqual(settings["archive_account"], status)
        for secret in (PASSWORD, SIGNATURE, "unused-secret"):
            self.assertNotIn(secret, json.dumps(settings))
        self.assertEqual(
            self.request("/api/archive-account/logout", {})[1]["state"], "disconnected"
        )

    def test_archive_login_denial_is_not_a_dsm_401_or_secret_leak(self):
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response(success=False, error=PASSWORD)
            code, data = self.request(
                "/api/archive-account/login", {"email": EMAIL, "password": PASSWORD}
            )
        self.assertEqual(code, 400)
        self.assertEqual(data["error"], DENIED)

    def test_remember_is_explicit_and_forget_keeps_the_session_and_pending_plans(self):
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            code, status = self.request(
                "/api/archive-account/login",
                {
                    "email": EMAIL,
                    "password": PASSWORD,
                    "remember": True,
                },
            )
        self.assertEqual(code, 200)
        self.assertTrue(status["remember_credentials"])
        token = self.app.plans.create(
            {"identifier": "item", "files": [{"name": "file", "size": 1}]}, "all", ""
        )
        cookies = self.account.snapshot()[1]
        code, settings = self.request("/api/settings")
        for secret in (PASSWORD, SIGNATURE, self.account.credentials):
            self.assertNotIn(secret, json.dumps(settings))
        code, status = self.request("/api/archive-account/forget", {})
        self.assertEqual(code, 200)
        self.assertTrue(status["connected"])
        self.assertFalse(status["remember_credentials"])
        self.assertEqual(cookies, self.account.snapshot()[1])
        self.app.plans.selection(token, "item")

    def test_non_boolean_remember_option_is_rejected_before_login(self):
        for value in ("false", "true", 0, 1, [], None):
            with patch("archive_station.archive_account.build_opener") as opener:
                code, _ = self.request(
                    "/api/archive-account/login",
                    {
                        "email": EMAIL,
                        "password": PASSWORD,
                        "remember": value,
                    },
                )
                self.assertEqual(code, 400)
                opener.assert_not_called()

    def test_existing_public_task_can_add_restricted_files_after_login(self):
        payload = {
            "files": [
                {"name": "info.xml", "size": "5"},
                {"name": "private.zip", "private": True, "size": "12", "sha1": "1" * 40},
            ]
        }
        self.client.cache["test-item"] = (time.monotonic(), payload)
        status, job = self.request("/api/jobs", {"url": "test-item", "paused": True})
        self.assertEqual(status, 201)
        job_id = job["id"]
        original = [
            tuple(row)
            for row in self.store.db.execute("SELECT * FROM files WHERE job_id=?", (job_id,))
        ]
        self.assertEqual(len(original), 1)
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            self.assertEqual(
                self.request("/api/archive-account/login", {"email": EMAIL, "password": PASSWORD})[
                    0
                ],
                200,
            )
        with patch("archive_station.archive.build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            code, refreshed = self.request(f"/api/jobs/{job_id}/refresh", {})
        self.assertEqual(code, 200)
        self.assertEqual(refreshed["added_count"], 1)
        code, result = self.request(
            f"/api/jobs/{job_id}/apply-refresh", {"plan_id": refreshed["plan_id"], "paused": True}
        )
        self.assertEqual(code, 200, result)
        self.assertEqual(
            self.store.db.execute(
                "SELECT count(*) FROM files WHERE job_id=?", (job_id,)
            ).fetchone()[0],
            2,
        )
        preserved = [
            tuple(row)
            for row in self.store.db.execute(
                "SELECT * FROM files WHERE job_id=? AND name='info.xml'", (job_id,)
            )
        ]
        self.assertEqual(preserved, original)

    def test_logout_between_manifest_and_plan_creation_cannot_keep_old_plan(self):
        original = self.app.plans.create

        def create(*args, **kwargs):
            self.account.disconnect()
            self.app.plans.clear()
            return original(*args, **kwargs)

        with (
            patch("archive_station.archive.build_opener") as metadata,
            patch.object(self.app.plans, "create", side_effect=create),
        ):
            metadata.return_value.open.return_value = io.BytesIO(b'{"files":[{"name":"file"}]}')
            status, _ = self.request("/api/inspect", {"url": "test"})
        self.assertEqual(status, 400)
        self.assertFalse(self.app.plans.items)

    def test_old_plan_is_rejected_even_if_clearing_it_races(self):
        token = self.app.plans.create(
            {"identifier": "test-item", "files": [{"name": "file", "size": 1}]}, "all", ""
        )
        self.account.disconnect()  # Deliberately bypass plans.clear().
        self.assertEqual(self.request("/api/plans/" + token)[0], 400)
        status, _ = self.request(
            "/api/jobs", {"url": "test-item", "plan_id": token, "paused": True}
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.store.jobs(), [])
