"""Persist actual integrity checks, not assumptions from settings or metadata."""

import hashlib
import sqlite3
import time
from contextlib import closing
from unittest.mock import patch

from test_downloads import PAYLOAD, Base, Response, manifest

from archive_station.engine import Interrupted
from archive_station.refresh import difference
from archive_station.reports import Reports, render_report
from archive_station.store import Store


class VerificationResultsTests(Base):
    def test_upgrade_preserves_progress_without_trusting_legacy_size_only_checks(self):
        data = manifest()
        data["files"] += [{**data["files"][0], "name": name} for name in ("size.zip", "next.zip")]
        job = self.store.add(data, "all", "", self.downloads)
        self.engine.transfer(self.store.claim())
        self.settings.update({"verify_checksums": False})
        self.engine.transfer(self.store.claim())
        before = self.store.jobs()[0]
        self.store.close()
        with closing(sqlite3.connect(self.root / "state.sqlite3")) as db, db:
            db.execute("ALTER TABLE files DROP COLUMN size_source")
        self.store = Store(self.root / "state.sqlite3")
        self.engine.store = self.store
        after = self.store.jobs(include_verification=True)[0]
        self.assertEqual(after["downloaded"], before["downloaded"])
        self.assertEqual(after["completed_files"], 2)
        self.assertEqual(after["verified_sha1_files"], 1)
        self.assertEqual(after["verified_size_files"], 0)
        self.assertEqual(after["verification_unknown_files"], 1)
        self.assertEqual(self.store.claim()["size_source"], "metadata")
        self.assertEqual(len(self.store.files(job)["files"]), 3)

    def test_repair_cannot_promote_an_observed_size_into_reference_verification(self):
        data = manifest(size=False)
        data["files"][0].update(algorithm=None, digest=None)
        job = self.store.add(data, "all", "", self.downloads)
        with patch.object(self.client, "open", return_value=Response(PAYLOAD, headers={})):
            self.engine.transfer(self.store.claim())
        for _ in range(2):
            self.store.finish_jobs()
            self.store.close()
            self.store = Store(self.root / "state.sqlite3")
            self.engine.store = self.store
            self.store.action(job, "repair")
            with patch.object(self.client, "open") as network:
                self.engine.transfer(self.store.claim())
                network.assert_not_called()
            file = self.store.files(job)["files"][0]
            self.assertEqual(file["verification_method"], "unverified")
            self.assertEqual(file["size_source"], "observed")
            result = self.store.verification_summary(job)
            self.assertEqual(result["verified_size_files"], 0)
            self.assertEqual(result["unverified_files"], 1)

    def test_report_aggregates_are_not_computed_by_progress_polling(self):
        self.add()
        self.engine.transfer(self.store.claim())
        with patch.object(
            self.store, "verification_summary", wraps=self.store.verification_summary
        ) as summary:
            self.store.jobs()
            summary.assert_not_called()
            Reports(self.store, self.settings).update()
            summary.assert_called_once()
        self.assertIsNotNone(self.store.jobs(include_verification=True)[0]["last_verification_at"])

    def test_sha1_and_md5_results_survive_restart_and_settings_changes(self):
        data = manifest()
        data["files"].append(
            {
                **data["files"][0],
                "name": "md5.zip",
                "algorithm": "md5",
                "digest": hashlib.md5(PAYLOAD).hexdigest(),
            }
        )
        job = self.store.add(data, "all", "", self.downloads)
        start = time.time()
        while row := self.store.claim():
            self.engine.transfer(row)
        self.settings.update({"verify_checksums": False})
        self.store.close()
        self.store = Store(self.root / "state.sqlite3")
        self.engine.store = self.store
        self.store.finish_jobs()
        for file in self.store.files(job)["files"]:
            self.assertEqual(file["verification_method"], file["algorithm"])
            self.assertGreaterEqual(file["verification_at"], start)
        summary = self.store.jobs(include_verification=True)[0]
        self.assertEqual(summary["verified_sha1_files"], 1)
        self.assertEqual(summary["verified_md5_files"], 1)
        self.assertEqual(summary["verification_unknown_files"], 0)
        for language, label in (("en", "Hash verified"), ("fr", "Vérifiés par hash")):
            report = render_report(
                summary, {**self.settings.get(), "language": language}, time.time()
            )
            self.assertIn(f"{label:<24} : 2 / 2", report)

    def test_disabled_hash_check_is_size_only_until_explicit_repair(self):
        job = self.add()
        self.settings.update({"verify_checksums": False})
        self.engine.transfer(self.store.claim())
        self.store.finish_jobs()
        self.settings.update({"verify_checksums": True})
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_sha1_files"], 0)
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_size_files"], 1)
        self.settings.update({"verify_checksums": False})
        self.store.action(job, "repair")
        self.assertIsNone(self.store.files(job)["files"][0]["verification_method"])
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_size_files"], 0)
        self.engine.transfer(self.store.claim())
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_sha1_files"], 1)
        self.assertEqual(self.client.offsets, [0])  # Repair reuses the file after hashing it.

    def test_setting_change_after_check_cannot_relabel_its_result(self):
        job = self.add()
        verify = self.engine.verify_file

        def verify_and_disable(path, row):
            result = verify(path, row)
            self.settings.update({"verify_checksums": False})
            return result

        with patch.object(self.engine, "verify_file", side_effect=verify_and_disable):
            self.engine.transfer(self.store.claim())
        self.assertEqual(self.store.files(job)["files"][0]["verification_method"], "sha1")

    def test_missing_hash_distinguishes_known_size_http_size_and_no_reference(self):
        for name, known_size, headers, expected in (
            ("metadata.zip", True, {}, "size"),
            ("http.zip", False, {"Content-Length": str(len(PAYLOAD))}, "size"),
            ("unknown.zip", False, {}, "unverified"),
        ):
            with self.subTest(name=name):
                data = manifest(identifier=name, name=name, size=known_size)
                data["files"][0].update(algorithm=None, digest=None)
                job = self.store.add(data, "all", "", self.downloads)
                with patch.object(
                    self.client, "open", return_value=Response(PAYLOAD, headers=headers)
                ):
                    self.engine.transfer(self.store.claim())
                result = self.store.files(job)["files"][0]
                self.assertEqual(result["verification_method"], expected)
                self.assertEqual(result["status"], "completed")

    def test_existing_and_resumed_files_record_full_file_verification(self):
        for name, location, length in (
            ("existing.zip", "target", len(PAYLOAD)),
            ("partial.zip", "partial", 12345),
            ("full-partial.zip", "partial", len(PAYLOAD)),
        ):
            with self.subTest(name=name):
                job = self.add(identifier=name, name=name)
                row = self.store.claim()
                if location == "target":
                    target = self.downloads / name / name
                    target.parent.mkdir(parents=True)
                    target.write_bytes(PAYLOAD)
                else:
                    self.partial(row, PAYLOAD[:length])
                self.engine.transfer(row)
                self.assertEqual(self.store.files(job)["files"][0]["verification_method"], "sha1")
        self.assertEqual(self.client.offsets, [12345])

    def test_corrupt_resumed_prefix_and_interrupted_hash_are_never_reported_verified(self):
        job = self.add()
        row = self.store.claim()
        self.partial(row, b"x" * 12345)
        self.engine.run_transfer(row)
        self.assertFalse(self.target().exists())
        result = self.store.files(job)["files"][0]
        self.assertIsNone(result["verification_method"])
        self.assertIsNone(result["verification_at"])
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_sha1_files"], 0)
        self.assertEqual(self.store.jobs(include_verification=True)[0]["incident_count"], 1)
        self.partial(row, PAYLOAD)
        with patch.object(self.engine, "verify_file", side_effect=Interrupted):
            self.engine.run_transfer(row)
        self.assertIsNone(self.store.files(job)["files"][0]["verification_method"])
        self.assertEqual(self.store.jobs(include_verification=True)[0]["completed_files"], 0)
        self.assertTrue(list(self.downloads.rglob("*.part")))

    def test_publication_failure_does_not_record_a_completed_check(self):
        job = self.add()
        row = self.store.claim()
        with patch("archive_station.engine.os.link", side_effect=OSError("Publish failed")):
            self.engine.run_transfer(row)
        self.assertIsNone(self.store.files(job)["files"][0]["verification_method"])
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_sha1_files"], 0)
        self.engine.transfer(row)
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_sha1_files"], 1)
        self.assertEqual(self.client.offsets, [0])

    def test_refresh_invalidates_old_check_until_changed_file_is_verified(self):
        job = self.add()
        self.engine.transfer(self.store.claim())
        self.store.finish_jobs()
        remote = manifest(data=b"new contents")
        self.store.apply_refresh(job, difference(self.store, job, remote), paused=True)
        self.assertEqual(self.store.jobs(include_verification=True)[0]["verified_sha1_files"], 0)
        result = self.store.files(job)["files"][0]
        self.assertIsNone(result["verification_method"])
        self.assertIsNone(result["verification_at"])

    def test_legacy_completed_file_stays_unknown_without_rehashing(self):
        path = self.root / "legacy.sqlite3"
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE jobs (id TEXT PRIMARY KEY,identifier TEXT UNIQUE,title TEXT,
                    status TEXT,created REAL,mode TEXT,pattern TEXT,destination TEXT);
                CREATE TABLE files (id INTEGER PRIMARY KEY,job_id TEXT,name TEXT,size INTEGER,
                    algorithm TEXT,digest TEXT,status TEXT,downloaded INTEGER,speed REAL,
                    attempts INTEGER,available_at REAL,error TEXT,UNIQUE(job_id,name));
            """)
            db.execute(
                "INSERT INTO jobs VALUES ('old','old','Old','completed',1,'all','',?)",
                (str(self.downloads),),
            )
            db.execute(
                "INSERT INTO files VALUES (1,'old','old.zip',?,?,?,'completed',?,0,0,0,NULL)",
                (len(PAYLOAD), "sha1", hashlib.sha1(PAYLOAD).hexdigest(), len(PAYLOAD)),
            )
        for _ in range(2):
            migrated = Store(path)
            try:
                job = migrated.jobs(include_verification=True)[0]
                self.assertEqual(job["completed_files"], 1)
                self.assertEqual(job["downloaded"], len(PAYLOAD))
                self.assertEqual(job["verified_sha1_files"], 0)
                self.assertEqual(job["verification_unknown_files"], 1)
                report = render_report(job, {**self.settings.get(), "language": "en"}, time.time())
                self.assertIn("Check not recorded       : 1", report)
                self.assertIn("Older versions did not record", report)
            finally:
                migrated.close()

    def test_disk_report_refreshes_check_results_even_at_unchanged_progress(self):
        job = self.add()
        row = self.store.claim()
        self.store.update(row["id"], status="completed", downloaded=len(PAYLOAD))
        self.settings.update({"language": "fr"})
        reports = Reports(self.store, self.settings)
        reports.update()
        path = self.downloads / "test-item" / f"ArchiveStation-report-{job}.txt"
        self.assertIn("Contrôle non consigné    : 1", path.read_text())
        self.target().parent.mkdir(parents=True, exist_ok=True)
        self.target().write_bytes(PAYLOAD)
        self.engine.transfer(row)
        reports.update()
        text = path.read_text()
        self.assertIn("Vérifiés par hash        : 1 / 1", text)
        self.assertIn("Contrôle non consigné    : 0", text)
        self.assertIn("Tous les fichiers accessibles", text)
        self.assertNotIn("Tous les fichiers publics", text)
