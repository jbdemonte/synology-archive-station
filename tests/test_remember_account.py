import hashlib
import io
import json
import os
import threading
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs

from test_archive_account import EMAIL, PASSWORD, SIGNATURE, AccountBase, login_response
from test_downloads import Response

from archive_station.archive import ArchiveClient
from archive_station.archive_account import DENIED, LOGIN_URL, AccountError, ArchiveAccount
from archive_station.config import Settings
from archive_station.credentials import CredentialError
from archive_station.engine import Engine
from archive_station.store import Store


def remember(account, password=PASSWORD):
    with patch("archive_station.archive_account.build_opener") as opener:
        opener.return_value.open.return_value = login_response()
        return account.connect(EMAIL, password, remember=True)


def renewed_response():
    response = json.loads(login_response().read())
    response["values"]["cookies"]["logged-in-sig"] = "renewed-signature; Max-Age=3600"
    return io.BytesIO(json.dumps(response).encode())


class RememberAccountTests(AccountBase):
    def test_credentials_are_authenticated_ciphertext_with_private_key_and_survive_restart(self):
        status = remember(self.account)
        self.assertTrue(status["remember_credentials"])
        self.assertTrue(status["remember_choice"])
        for path in self.root.iterdir():
            self.assertNotIn(PASSWORD.encode(), path.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.account.credentials, json.dumps(status))
        restarted = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertEqual(restarted.vault.decrypt(restarted.credentials, EMAIL), PASSWORD)
        self.assertEqual(restarted.status(), status)
        with self.assertRaises(CredentialError):
            restarted.vault.decrypt(restarted.credentials, "another@example.test")

    def test_opt_out_and_forget_remove_credentials_without_logging_out(self):
        remember(self.account)
        cookie = self.account.snapshot()[1]
        self.account.forget_credentials()
        self.assertEqual(self.account.snapshot()[1], cookie)
        self.assertFalse(self.account.status()["remember_credentials"])
        self.assertFalse(self.account.status()["remember_choice"])
        self.assertFalse(self.account.vault.path.exists())
        self.assertEqual(json.loads(self.account.path.read_text())["credentials"], "")
        self.account.last_attempt = float("-inf")
        remember(self.account)
        self.account.last_attempt = float("-inf")
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            self.account.connect(EMAIL, PASSWORD, remember=False)
        self.assertFalse(self.account.vault.path.exists())
        self.assertTrue(self.account.status()["connected"])
        self.assertFalse(ArchiveAccount(self.root).status()["remember_choice"])

    def test_disconnect_removes_credentials_and_key(self):
        remember(self.account)
        self.account.disconnect()
        self.assertFalse(self.account.path.exists())
        self.assertFalse(self.account.vault.path.exists())
        self.assertFalse(self.account.credentials)
        self.assertFalse(self.account.status()["connected"])

    def test_old_session_is_read_without_requiring_or_inventing_a_password(self):
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            self.account.connect(EMAIL, PASSWORD)
        data = json.loads(self.account.path.read_text())
        legacy = {key: data[key] for key in ("email", "cookies", "expires")}
        legacy["version"] = 1
        self.account.path.write_text(json.dumps(legacy))
        restarted = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertTrue(restarted.status()["connected"])
        self.assertFalse(restarted.status()["remember_credentials"])
        self.assertTrue(restarted.status()["remember_choice"])
        self.assertEqual(json.loads(self.account.path.read_text()), legacy)

    def test_expired_session_renews_from_encrypted_credentials_after_restart(self):
        remember(self.account)
        restarted = ArchiveAccount(self.root, clock=lambda: 5000)
        self.assertEqual(restarted.status()["state"], "expired")
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = renewed_response()
            identity, cookie = restarted.request_snapshot()
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, LOGIN_URL)
            self.assertEqual(parse_qs(request.data.decode())["password"], [PASSWORD])
        self.assertIn("renewed-signature", cookie)
        self.assertTrue(identity[1])
        self.assertEqual(ArchiveAccount(self.root, clock=lambda: 5001).snapshot()[1], cookie)

    def test_session_only_mode_never_attempts_automatic_login(self):
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response()
            self.account.connect(EMAIL, PASSWORD, remember=False)
        restarted = ArchiveAccount(self.root, clock=lambda: 5000)
        with patch("archive_station.archive_account.build_opener") as opener:
            self.assertEqual(restarted.request_snapshot()[1], "")
            self.assertFalse(restarted.refresh(restarted.snapshot()[0]))
            opener.assert_not_called()

    def test_bad_saved_password_blocks_automatic_login_across_restarts(self):
        remember(self.account)
        restarted = ArchiveAccount(self.root, clock=lambda: 5000)
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.return_value = login_response(success=False)
            with self.assertRaisesRegex(AccountError, "refusée"):
                restarted.request_snapshot()
            again = ArchiveAccount(self.root, clock=lambda: 9000)
            with self.assertRaisesRegex(AccountError, "refusée"):
                again.request_snapshot()
            self.assertEqual(opener.return_value.open.call_count, 1)
        self.assertEqual(again.status()["reconnect_error"], DENIED)
        remember(again)
        self.assertIsNone(again.status()["reconnect_error"])

    def test_transient_error_is_retryable_and_automatic_attempts_are_rate_limited(self):
        remember(self.account)
        restarted = ArchiveAccount(self.root, clock=lambda: 5000)
        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.side_effect = URLError(PASSWORD)
            for _ in range(4):
                with self.assertRaises(AccountError) as error:
                    restarted.request_snapshot()
                self.assertTrue(error.exception.retryable)
                self.assertNotIn(PASSWORD, str(error.exception))
            self.assertEqual(opener.return_value.open.call_count, 1)
            restarted.last_refresh -= 61
            opener.return_value.open.side_effect = None
            opener.return_value.open.return_value = renewed_response()
            self.assertIn("renewed-signature", restarted.request_snapshot()[1])
            self.assertEqual(opener.return_value.open.call_count, 2)

    def test_parallel_transfers_share_one_renewal(self):
        remember(self.account)
        self.account.clock = lambda: 5000
        started, release = threading.Event(), threading.Event()
        results, errors = [], []

        def network(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(5))
            return renewed_response()

        def request():
            try:
                results.append(self.account.request_snapshot()[1])
            except Exception as error:
                errors.append(error)

        with patch("archive_station.archive_account.build_opener") as opener:
            opener.return_value.open.side_effect = network
            threads = [threading.Thread(target=request) for _ in range(5)]
            try:
                for thread in threads:
                    thread.start()
                self.assertTrue(started.wait(5))
            finally:
                release.set()
                for thread in threads:
                    thread.join(5)
            self.assertEqual(opener.return_value.open.call_count, 1)
        self.assertFalse(errors)
        self.assertEqual(len(results), 5)
        self.assertTrue(all("renewed-signature" in value for value in results))

    def test_logout_or_forget_during_renewal_cannot_restore_credentials(self):
        for action in ("disconnect", "forget_credentials"):
            with self.subTest(action=action):
                self.account.last_attempt = float("-inf")
                remember(self.account)
                started, release = threading.Event(), threading.Event()
                identity = self.account.snapshot()[0]
                results = []

                def network(*args, started=started, release=release, **kwargs):
                    started.set()
                    self.assertTrue(release.wait(5))
                    return renewed_response()

                with patch("archive_station.archive_account.build_opener") as opener:
                    opener.return_value.open.side_effect = network
                    thread = threading.Thread(
                        target=lambda results=results, identity=identity: results.append(
                            self.account.refresh(identity)
                        )
                    )
                    thread.start()
                    try:
                        self.assertTrue(started.wait(5))
                        getattr(self.account, action)()
                    finally:
                        release.set()
                        thread.join(5)
                self.assertEqual(results, [False])
                self.assertFalse(self.account.credentials)
                self.assertFalse(self.account.vault.path.exists())

    def test_corrupt_ciphertext_or_missing_key_is_safe_and_never_submitted(self):
        remember(self.account)
        self.account.clock = lambda: 5000
        original = self.account.credentials
        self.account.credentials = "tampered" + original
        with patch("archive_station.archive_account.build_opener") as opener:
            with self.assertRaises(AccountError) as error:
                self.account.request_snapshot()
            self.assertNotIn(original, str(error.exception))
            opener.assert_not_called()
        self.account.last_attempt = float("-inf")
        remember(self.account)
        self.account.clock = lambda: 9000
        self.account.vault.path.unlink()
        with patch("archive_station.archive_account.build_opener") as opener:
            with self.assertRaises(AccountError):
                self.account.request_snapshot()
            opener.assert_not_called()
        self.assertFalse(self.account.vault.path.exists())

    def test_key_cannot_follow_symlinks_or_block_on_a_fifo(self):
        target = self.root / "untouched"
        target.write_text("original")
        self.account.vault.path.symlink_to(target)
        with self.assertRaises(CredentialError):
            self.account.vault.encrypt(EMAIL, PASSWORD)
        self.assertEqual(target.read_text(), "original")
        self.account.vault.path.unlink()
        os.mkfifo(self.account.vault.path)
        with self.assertRaises(CredentialError):
            self.account.vault.encrypt(EMAIL, PASSWORD)

    def test_failed_save_keeps_old_credentials_and_session(self):
        remember(self.account)
        before = self.account.path.read_bytes()
        self.account.last_attempt = float("-inf")
        with patch("archive_station.archive_account.os.replace", side_effect=OSError("full")):
            with self.assertRaises(AccountError):
                remember(self.account, "different-password")
        self.assertEqual(self.account.path.read_bytes(), before)
        self.assertEqual(self.account.vault.decrypt(self.account.credentials, EMAIL), PASSWORD)

    def test_unicode_password_at_maximum_length_round_trips(self):
        password = "🔒" * 4096
        remember(self.account, password)
        restarted = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertTrue(restarted.status()["remember_credentials"])
        self.assertEqual(restarted.vault.decrypt(restarted.credentials, EMAIL), password)


class RenewedTransferTests(AccountBase):
    def test_authentication_retry_preserves_range_and_does_not_loop_on_forbidden_files(self):
        remember(self.account)
        client = ArchiveClient(self.account)
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.return_value = renewed_response()
            with patch("archive_station.archive.build_opener") as download:
                download.return_value.open.side_effect = [
                    HTTPError("https://archive.org/test", 403, "denied", {}, None),
                    Response(b"content", 206, {"Content-Type": "application/zip"}),
                ]
                with client.open("test-item", "private.zip", 128):
                    pass
                calls = download.return_value.open.call_args_list
                self.assertEqual(
                    [call.args[0].get_header("Range") for call in calls], ["bytes=128-"] * 2
                )
                self.assertIn(SIGNATURE, calls[0].args[0].get_header("Cookie"))
                self.assertIn("renewed-signature", calls[1].args[0].get_header("Cookie"))
                download.return_value.open.side_effect = lambda *args, **kwargs: (
                    _ for _ in ()
                ).throw(HTTPError("https://archive.org/test", 403, "no permission", {}, None))
                with self.assertRaises(HTTPError) as denied:
                    client.open("test-item", "private.zip", 128)
                denied.exception.close()
                self.assertEqual(login.return_value.open.call_count, 1)

    def test_repeated_denial_gets_exactly_one_retry(self):
        remember(self.account)
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.return_value = renewed_response()
            with patch("archive_station.archive.build_opener") as download:
                download.return_value.open.side_effect = [
                    HTTPError("https://archive.org/test", code, "denied", {}, None)
                    for code in (401, 403)
                ]
                with self.assertRaises(HTTPError) as error:
                    ArchiveClient(self.account).open("test-item", "private.zip")
                self.assertEqual(error.exception.code, 403)
                error.exception.close()
                self.assertEqual(download.return_value.open.call_count, 2)
                self.assertEqual(login.return_value.open.call_count, 1)

    def test_metadata_renewal_updates_cache_identity_and_includes_restricted_files(self):
        remember(self.account)
        client = ArchiveClient(self.account)
        payload = b'{"files":[{"name":"private.zip","private":true,"size":"12"}]}'
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.return_value = renewed_response()
            with patch("archive_station.archive.build_opener") as download:
                download.return_value.open.side_effect = [
                    HTTPError("https://archive.org/metadata/test", 401, "expired", {}, None),
                    io.BytesIO(payload),
                ]
                self.assertEqual(client.manifest("test-item")["restricted_files"], 1)
                self.assertEqual(client.manifest("test-item")["restricted_files"], 1)
                self.assertEqual(download.return_value.open.call_count, 2)
                self.assertEqual(client.cache_identity, self.account.snapshot()[0])

    def test_partial_file_resumes_after_renewal_and_final_checksum_matches(self):
        remember(self.account)
        client = ArchiveClient(ArchiveAccount(self.root, clock=lambda: 1001))
        store = Store(self.root / "state.sqlite3")
        self.addCleanup(store.close)
        settings = Settings(self.root / "data", self.root / "downloads", [self.root])
        settings.update({"disk_reserve_mib": 0})
        data = b"authorized content fixture" * 200
        job = store.add(
            {
                "identifier": "test-item",
                "title": "Fixture",
                "files": [
                    {
                        "name": "private.bin",
                        "size": len(data),
                        "algorithm": "sha1",
                        "digest": hashlib.sha1(data).hexdigest(),
                    }
                ],
            },
            "all",
            "",
            self.root / "downloads",
        )
        row = store.claim()
        partial = self.root / f"downloads/.archive-station-parts/{job}/{row['id']}.part"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(data[:128])
        engine = Engine(store, client, settings)
        self.addCleanup(engine.shutdown)
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.return_value = renewed_response()
            with patch("archive_station.archive.build_opener") as download:
                download.return_value.open.side_effect = [
                    HTTPError("https://archive.org/test", 403, "expired", {}, None),
                    Response(
                        data[128:], 206, {"Content-Range": f"bytes 128-{len(data) - 1}/{len(data)}"}
                    ),
                ]
                engine.run_transfer(row)
        self.assertEqual((self.root / "downloads/test-item/private.bin").read_bytes(), data)
        self.assertFalse(partial.exists())

    def test_transient_renewal_failure_keeps_file_queued_and_partial_intact(self):
        remember(self.account)
        store = Store(self.root / "state.sqlite3")
        self.addCleanup(store.close)
        settings = Settings(self.root / "data", self.root / "downloads", [self.root])
        settings.update({"disk_reserve_mib": 0})
        job = store.add(
            {
                "identifier": "test-item",
                "title": "Fixture",
                "files": [
                    {
                        "name": "private.bin",
                        "size": 1000,
                        "algorithm": None,
                        "digest": None,
                    }
                ],
            },
            "all",
            "",
            self.root / "downloads",
        )
        row = store.claim()
        partial = self.root / f"downloads/.archive-station-parts/{job}/{row['id']}.part"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(b"prefix")
        engine = Engine(store, ArchiveClient(self.account), settings)
        self.addCleanup(engine.shutdown)
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.side_effect = URLError("temporarily offline")
            with patch("archive_station.archive.build_opener") as download:
                download.return_value.open.side_effect = HTTPError(
                    "https://archive.org/test", 401, "expired", {}, None
                )
                engine.run_transfer(row)
        self.assertEqual(partial.read_bytes(), b"prefix")
        saved = store.db.execute(
            "SELECT status, attempts FROM files WHERE id=?", (row["id"],)
        ).fetchone()
        self.assertEqual(tuple(saved), ("queued", 1))
