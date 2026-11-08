"""Transfer and selection regressions with deterministic authentication responses."""

import io
import json
from http.client import IncompleteRead
from unittest.mock import patch

from test_archive_account import EMAIL, PASSWORD, AccountBase, connect
from test_downloads import PAYLOAD, Response, manifest

from archive_station.archive import ArchiveClient
from archive_station.archive_account import CHANGED, UNAVAILABLE, AccountError, ArchiveAccount
from archive_station.config import Settings
from archive_station.engine import Engine
from archive_station.store import Store


class AccountRegressionTests(AccountBase):
    def test_expired_session_never_blocks_public_transfers_even_after_restart(self):
        connect(self.account)
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
            download.return_value.open.side_effect = lambda *a, **kw: Response(PAYLOAD)
            while row := store.claim():
                account = ArchiveAccount(self.root, clock=lambda: 5000)
                Engine(store, ArchiveClient(account), settings).run_transfer(row)
            store.finish_jobs()
            self.assertEqual(store.jobs()[0]["completed_files"], 5)
            login.assert_not_called()
            self.assertEqual(download.return_value.open.call_count, 5)
            self.assertTrue(
                all(
                    call.args[0].get_header("Cookie") is None
                    for call in download.return_value.open.call_args_list
                )
            )

    def test_manual_login_during_metadata_read_invalidates_the_selection(self):
        client = ArchiveClient(self.account)

        class LoginDuringRead(io.BytesIO):
            def read(response, *args):
                connect(self.account)
                return super().read(*args)

        with patch("archive_station.archive.build_opener") as metadata:
            metadata.return_value.open.return_value = LoginDuringRead(
                b'{"files":[{"name":"private.bin","private":true},{"name":"public.txt"}]}'
            )
            with self.assertRaisesRegex(AccountError, CHANGED):
                client.manifest("test")
        self.assertEqual(client.cache, {})

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

    def test_truncated_login_is_retryable_and_does_not_leak_response(self):
        with patch("archive_station.archive_account.build_opener") as login:
            login.return_value.open.side_effect = IncompleteRead(PASSWORD.encode(), 999)
            with self.assertRaises(AccountError) as error:
                self.account.connect(EMAIL, PASSWORD)
        self.assertTrue(error.exception.retryable)
        self.assertEqual(str(error.exception), UNAVAILABLE)

    def test_completed_manual_attempt_throttle_does_not_claim_login_in_progress(self):
        connect(self.account)
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
