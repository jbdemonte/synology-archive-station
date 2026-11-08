"""Session-only storage, legacy credential removal and startup without crypto."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from test_archive_account import EMAIL, PASSWORD, SIGNATURE, AccountBase, connect

from archive_station.archive_account import ArchiveAccount


class SessionMigrationTests(AccountBase):
    def legacy(self, version=3, **fields):
        value = {
            "version": version,
            "email": EMAIL,
            "cookies": {"logged-in-user": "reader%40example.test", "logged-in-sig": SIGNATURE},
            "expires": 4600,
            "credentials": "old-encrypted-password",
            "remember_choice": True,
            "blocked": True,
            "blocked_reason": "credentials",
            **fields,
        }
        self.account.path.write_text(json.dumps(value))
        key = self.root / "archive-account.key"
        key.write_text("old-key")
        return value, key

    def test_legacy_sessions_drop_saved_credentials_and_keep_valid_cookies(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                value, key = self.legacy(version)
                with patch("archive_station.archive_account.build_opener") as login:
                    account = ArchiveAccount(self.root, clock=lambda: 1001)
                    self.assertIn(SIGNATURE, account.request_snapshot()[1])
                    login.assert_not_called()
                self.assertEqual(
                    account.status(),
                    {
                        "connected": True,
                        "state": "connected",
                        "email": EMAIL,
                    },
                )
                self.assertEqual(
                    json.loads(account.path.read_text()),
                    {
                        "version": 4,
                        **{name: value[name] for name in ("email", "cookies", "expires")},
                    },
                )
                self.assertEqual(account.path.stat().st_mode & 0o777, 0o600)
                self.assertFalse(key.exists())
                self.assertEqual(
                    ArchiveAccount(self.root, clock=lambda: 1002).status(), account.status()
                )

    def test_abandoned_fields_are_ignored_even_when_their_types_are_invalid(self):
        self.legacy(credentials={"ciphertext": "invalid"}, remember_choice="no", blocked=[])
        account = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertTrue(account.status()["connected"])
        self.assertEqual(
            set(json.loads(account.path.read_text())), {"version", "email", "cookies", "expires"}
        )

    def test_each_abandoned_field_alone_triggers_cleanup_even_in_version_four(self):
        for field in ("credentials", "remember_choice", "blocked", "blocked_reason"):
            with self.subTest(field=field):
                value, key = self.legacy(version=4)
                value = {
                    name: item
                    for name, item in value.items()
                    if name in {"version", "email", "cookies", "expires", field}
                }
                self.account.path.write_text(json.dumps(value))
                account = ArchiveAccount(self.root, clock=lambda: 1001)
                self.assertTrue(account.status()["connected"])
                self.assertNotIn(field, json.loads(account.path.read_text()))
                self.assertFalse(key.exists())

    def test_failed_rewrite_keeps_the_session_in_memory_and_still_removes_the_key(self):
        value, key = self.legacy()
        with (
            patch("archive_station.archive_account.os.replace", side_effect=OSError(PASSWORD)),
            self.assertNoLogs(),
        ):
            account = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertIn(SIGNATURE, account.snapshot()[1])
        self.assertEqual(json.loads(account.path.read_text()), value)
        self.assertFalse(key.exists())
        self.assertFalse(list(self.root.glob(".archive-account-*")))

    def test_failed_key_removal_keeps_the_session_and_still_rewrites_the_file(self):
        _, key = self.legacy()
        unlink = Path.unlink

        def remove(path, *args, **kwargs):
            if path == key:
                raise PermissionError(PASSWORD)
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", remove), self.assertNoLogs():
            account = ArchiveAccount(self.root, clock=lambda: 1001)
        self.assertIn(SIGNATURE, account.snapshot()[1])
        self.assertTrue(key.exists())
        self.assertEqual(
            set(json.loads(account.path.read_text())), {"version", "email", "cookies", "expires"}
        )

    def test_failed_permission_repair_attempts_rewrite_without_losing_the_session(self):
        connect(self.account)
        saved = self.account.path.read_bytes()
        fchmod = os.fchmod
        for rewrite_fails in (False, True):
            with self.subTest(rewrite_fails=rewrite_fails):
                self.account.path.chmod(0o644)
                calls = []

                def change_mode(fd, mode, *, calls=calls, rewrite_fails=rewrite_fails):
                    calls.append(mode)
                    if len(calls) == 1 or rewrite_fails:
                        raise PermissionError(PASSWORD)
                    fchmod(fd, mode)

                with (
                    patch("archive_station.archive_account.os.fchmod", side_effect=change_mode),
                    self.assertNoLogs(),
                ):
                    account = ArchiveAccount(self.root, clock=lambda: 1001)
                self.assertEqual(calls, [0o600, 0o600])
                self.assertTrue(account.status()["connected"])
                self.assertEqual(account.path.read_bytes(), saved)
                self.assertEqual(
                    account.path.stat().st_mode & 0o777, 0o644 if rewrite_fails else 0o600
                )
                self.assertFalse(list(self.root.glob(".archive-account-*")))

    def test_legacy_key_is_unlinked_without_following_symlinks_or_opening_fifos(self):
        target = self.root / "untouched"
        target.write_text("original")
        key = self.root / "archive-account.key"
        key.symlink_to(target)
        ArchiveAccount(self.root)
        self.assertFalse(key.is_symlink())
        self.assertEqual(target.read_text(), "original")
        os.mkfifo(key)
        ArchiveAccount(self.root)
        self.assertFalse(key.exists())

    def test_invalid_sessions_are_ignored_and_orphan_keys_are_removed(self):
        for fields in ({"cookies": {}}, {"expires": float("inf")}, {"version": 5}):
            with self.subTest(fields=fields):
                _, key = self.legacy(**fields)
                account = ArchiveAccount(self.root)
                self.assertEqual(account.status()["state"], "disconnected")
                self.assertFalse(key.exists())

    def test_expired_migrated_session_stays_expired_without_any_login_request(self):
        self.legacy()
        with patch("archive_station.archive_account.build_opener") as login:
            account = ArchiveAccount(self.root, clock=lambda: 5000)
            self.assertEqual(
                account.status(), {"connected": False, "state": "expired", "email": EMAIL}
            )
            identity, cookie = account.request_snapshot()
            self.assertEqual(cookie, "")
            self.assertFalse(account.refresh(identity))
            login.assert_not_called()

    def test_disconnect_removes_any_leftover_key_and_saved_session(self):
        connect(self.account)
        key = self.root / "archive-account.key"
        key.write_text("leftover key")
        self.account.disconnect()
        self.assertFalse(self.account.path.exists())
        self.assertFalse(key.exists())
        self.assertEqual(self.account.status()["state"], "disconnected")

    def test_app_starts_and_shuts_down_with_compiled_dependencies_unavailable(self):
        code = """
import sys
from types import SimpleNamespace
from unittest.mock import patch
for name in ('cryptography', 'cffi', '_cffi_backend', 'pycparser'):
    sys.modules[name] = None
from archive_station.__main__ import main
root = sys.argv[1]
sys.argv = ['archive-station', '--no-auth', '--data-dir', root + '/state',
            '--download-dir', root + '/downloads']
server = SimpleNamespace(run=lambda: print('started without crypto'), close=lambda: None)
with patch('waitress.create_server', return_value=server):
    main()
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.root)], capture_output=True, text=True, timeout=20
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("started without crypto", result.stdout)
