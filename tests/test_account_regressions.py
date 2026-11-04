"""Real transfer and selection paths with deterministic authentication failures."""

import errno
import io
import json
import time
import traceback
from http.client import IncompleteRead
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from test_archive_account import EMAIL, PASSWORD, AccountBase, login_response
from test_downloads import PAYLOAD, Response, manifest
from test_remember_account import remember, renewed_response

from archive_station.archive import ArchiveClient
from archive_station.archive_account import DENIED, UNAVAILABLE, AccountError, ArchiveAccount
from archive_station.config import Settings
from archive_station.engine import Engine
from archive_station.store import Store


class AccountRegressionTests(AccountBase):
    def test_failed_saved_login_never_blocks_public_transfers_even_after_restart(self):
        remember(self.account)
        account = ArchiveAccount(self.root, clock=lambda: 5000)
        store = Store(self.root / "downloads.sqlite3")
        self.addCleanup(store.close)
        settings = Settings(self.root / "settings", self.root / "downloads", [self.root])
        data = manifest()
        data["files"] = [{**data["files"][0], "name": f"public-{i}.zip"} for i in range(5)]
        store.add(data, "all", "", self.root / "downloads")
        with (
            patch("archive_station.archive_account.build_opener") as login,
            patch("archive_station.archive.build_opener") as download,
        ):
            login.return_value.open.return_value = login_response(success=False)
            download.return_value.open.side_effect = lambda *a, **kw: Response(PAYLOAD)
            while row := store.claim():
                account = ArchiveAccount(self.root, clock=lambda: 5000)
                Engine(store, ArchiveClient(account), settings).run_transfer(row)
            store.finish_jobs()
            self.assertEqual(store.jobs()[0]["completed_files"], 5)
            self.assertEqual(login.return_value.open.call_count, 1)
            self.assertEqual(download.return_value.open.call_count, 5)
            self.assertTrue(
                all(
                    c.args[0].get_header("Cookie") is None
                    for c in download.return_value.open.call_args_list
                )
            )

    def test_public_html_downloads_are_not_treated_as_login_pages(self):
        for name in ("site/index", "site/page.shtml", "site/README", "site/login.html"):
            with self.subTest(name=name), patch("archive_station.archive.build_opener") as network:
                response = Response(
                    b"<html>archived content</html>", headers={"Content-Type": "text/html"}
                )
                response.url = "https://ia600001.us.archive.org/0/items/test/" + name
                network.return_value.open.return_value = response
                with ArchiveClient().open("test", name) as result:
                    self.assertEqual(result.read(), b"<html>archived content</html>")

    def test_login_throttle_does_not_exhaust_file_attempts_during_short_outage(self):
        remember(self.account)
        store = Store(self.root / "downloads.sqlite3")
        self.addCleanup(store.close)
        settings = Settings(self.root / "settings", self.root / "downloads", [self.root])
        store.add(manifest(), "all", "", self.root / "downloads")
        engine = Engine(store, ArchiveClient(self.account), settings)
        now = [0]

        def login(*args, **kwargs):
            if now[0] < 80:
                raise URLError("temporary outage")
            return renewed_response()

        def download(request, **kwargs):
            if "renewed-signature" not in (request.get_header("Cookie") or ""):
                raise HTTPError(request.full_url, 403, "expired", {}, None)
            return Response(PAYLOAD)

        with (
            patch("archive_station.archive_account.time.monotonic", side_effect=lambda: now[0]),
            patch("archive_station.archive_account.build_opener") as auth,
            patch("archive_station.archive.build_opener") as network,
        ):
            auth.return_value.open.side_effect = login
            network.return_value.open.side_effect = download
            row = store.claim()
            engine.run_transfer(row)
            self.assertEqual(store.files(row["job_id"])["files"][0]["attempts"], 1)
            for moment in (5, 30, 59, 60, 65, 80, 119, 120):
                now[0] = moment
                store.update(row["id"], available_at=0)
                engine.run_transfer(store.claim())
                saved = store.files(row["job_id"])["files"][0]
                self.assertLessEqual(saved["attempts"], 2)
                self.assertNotEqual(saved["status"], "error")
            self.assertEqual(saved["status"], "completed")
            self.assertEqual(auth.return_value.open.call_count, 3)

    def test_local_key_error_and_clock_skew_do_not_persist_credential_rejection(self):
        remember(self.account)
        identity = self.account.snapshot()[0]
        with patch(
            "archive_station.credentials.os.open", side_effect=OSError(errno.EMFILE, "files")
        ):
            with self.assertRaises(AccountError) as error:
                self.account.refresh(identity)
        self.assertTrue(error.exception.retryable)
        self.assertFalse(self.account.blocked)
        self.assertFalse(ArchiveAccount(self.root).blocked)
        self.account.last_refresh = float("-inf")
        self.account.clock = lambda: 5000
        data = json.loads(login_response().read())
        data["values"]["cookies"]["logged-in-sig"] = (
            "signature; Expires=Thu, 01 Jan 1970 00:30:00 GMT"
        )
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.return_value = io.BytesIO(json.dumps(data).encode())
            with self.assertRaises(AccountError) as error:
                self.account.refresh(identity)
        self.assertTrue(error.exception.retryable)
        self.assertFalse(ArchiveAccount(self.root).blocked)

    def test_legacy_block_without_rejection_reason_is_reconsidered(self):
        remember(self.account)
        value = json.loads(self.account.path.read_text())
        value.update(version=2, blocked=True)
        value.pop("blocked_reason", None)
        self.account.path.write_text(json.dumps(value))
        account = ArchiveAccount(self.root, clock=lambda: 5000)
        self.assertFalse(account.blocked)
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.return_value = renewed_response()
            self.assertTrue(account.request_snapshot()[1])

    def test_new_login_repairs_corrupt_owned_key_and_survives_restart(self):
        for corrupt in (b"short", b"x" * 44, b"!" * 44):
            with self.subTest(corrupt=corrupt):
                self.account.vault.path.write_bytes(corrupt)
                self.account.last_attempt = float("-inf")
                remember(self.account)
                restarted = ArchiveAccount(self.root, clock=lambda: 1001)
                self.assertEqual(restarted.vault.decrypt(restarted.credentials, EMAIL), PASSWORD)
                self.assertEqual(self.account.vault.path.stat().st_mode & 0o777, 0o600)

    def test_cached_failures_do_not_reuse_exception_tracebacks(self):
        remember(self.account)
        identity = self.account.snapshot()[0]
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.side_effect = URLError("outage")
            lengths = []
            for _ in range(1000):
                try:
                    self.account.refresh(identity)
                except AccountError as error:
                    lengths.append(len(traceback.extract_tb(error.__traceback__)))
            self.assertEqual(login.return_value.open.call_count, 1)
        self.assertLess(max(lengths), 6)
        self.assertNotIsInstance(self.account.refresh_error, BaseException)

    def test_routine_renewal_during_metadata_read_keeps_account_selection_valid(self):
        remember(self.account)
        client = ArchiveClient(self.account)
        identity = self.account.snapshot()[0]

        class RenewDuringRead(io.BytesIO):
            def read(response, *args):
                self.assertTrue(self.account.refresh(identity))
                return super().read(*args)

        with (
            patch("archive_station.archive_account.build_opener") as login,
            patch("archive_station.archive.build_opener") as metadata,
        ):
            login.return_value.open.return_value = renewed_response()
            metadata.return_value.open.return_value = RenewDuringRead(
                b'{"files":[{"name":"private.bin","private":true}]}'
            )
            result = client.manifest("test")
        self.assertEqual(result["restricted_files"], 1)
        self.assertEqual(result["account_generation"], self.account.identity())

    def test_inflight_denial_retries_after_manual_session_only_login(self):
        client = ArchiveClient(self.account)
        calls = []

        def request(req, **kwargs):
            calls.append(req)
            if len(calls) == 1:
                with patch("archive_station.archive_account.build_opener") as login:
                    login.return_value.open.return_value = login_response()
                    self.account.connect(EMAIL, PASSWORD, remember=False)
                raise HTTPError(req.full_url, 403, "denied", {}, None)
            return Response(b"content")

        with patch("archive_station.archive.build_opener") as download:
            download.return_value.open.side_effect = request
            with client.open("test", "file", offset=123) as response:
                self.assertEqual(response.read(), b"content")
        self.assertIsNone(calls[0].get_header("Cookie"))
        self.assertIsNotNone(calls[1].get_header("Cookie"))
        self.assertEqual([r.get_header("Range") for r in calls], ["bytes=123-"] * 2)

    def test_truncated_login_is_retryable_and_does_not_leak_response(self):
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.side_effect = IncompleteRead(PASSWORD.encode(), 999)
            with self.assertRaises(AccountError) as error:
                self.account.connect(EMAIL, PASSWORD)
        self.assertTrue(error.exception.retryable)
        self.assertEqual(str(error.exception), UNAVAILABLE)

    def test_success_clears_transient_renewal_error_but_not_a_credential_refusal(self):
        remember(self.account)
        self.account.refresh_error = (UNAVAILABLE, True)
        self.account.last_refresh = time.monotonic()
        with patch("archive_station.archive.build_opener") as download:
            download.return_value.open.side_effect = lambda *a, **kw: Response(b"ok")
            with ArchiveClient(self.account).open("test", "file"):
                pass
            self.assertIsNone(self.account.status()["reconnect_error"])
            with self.assertRaises(AccountError) as waiting:
                self.account.refresh(self.account.snapshot()[0])
            self.assertGreater(waiting.exception.retry_after, 0)
            self.account.blocked = True
            self.account.refresh_error = (DENIED, False)
            with ArchiveClient(self.account).open("test", "file"):
                pass
            self.assertEqual(self.account.status()["reconnect_error"], DENIED)

    def test_session_save_failure_is_cached_without_blocking_public_access(self):
        remember(self.account)
        self.account.clock = lambda: 5000
        before = self.account.path.read_bytes()
        with (
            patch("archive_station.archive_account.build_opener") as login,
            patch("archive_station.archive_account.os.replace", side_effect=OSError("full")),
        ):
            login.return_value.open.return_value = renewed_response()
            self.assertEqual(self.account.request_snapshot()[1], "")
            with self.assertRaises(AccountError) as waiting:
                self.account.refresh(self.account.snapshot()[0])
            self.assertGreater(waiting.exception.retry_after, 0)
        self.assertFalse(self.account.blocked)
        self.assertEqual(self.account.path.read_bytes(), before)

    def test_completed_manual_attempt_throttle_does_not_claim_login_in_progress(self):
        remember(self.account)
        with self.assertRaises(AccountError) as error:
            self.account.connect(EMAIL, PASSWORD)
        self.assertNotIn("déjà en cours", str(error.exception))
        self.assertGreater(error.exception.retry_after, 0)

    def test_private_notice_obeys_file_type_and_filename_filters(self):
        client = ArchiveClient()
        payload = {
            "files": [
                {"name": "public.zip", "source": "original"},
                {"name": "private.pdf", "source": "original", "private": True},
                {"name": "derived.zip", "source": "derivative", "private": True},
            ]
        }
        with patch("archive_station.archive.build_opener") as metadata:
            metadata.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            result = client.manifest("test", mode="original", pattern="*.zip")
        self.assertEqual(result["private_files"], 0)
