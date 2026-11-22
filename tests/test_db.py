import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import db


class DbTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.original_path = db.DB_PATH
        self.addCleanup(setattr, db, "DB_PATH", self.original_path)
        db.DB_PATH = os.path.join(self.folder.name, "test.db")

    def save_dummy_scan(self):
        db.init_db()
        findings = [{"title": "Missing header", "severity": "Medium", "description": "test"}]
        return db.save_scan("url", "url", "https://example.com", findings)

    def test_init_db_creates_tables(self):
        db.init_db()
        conn = sqlite3.connect(db.DB_PATH)
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        conn.close()
        names = {row[0] for row in rows}
        self.assertEqual(names, {"targets", "scans", "vulnerabilities", "reports"})

    def test_save_scan_returns_valid_id(self):
        scan_id = self.save_dummy_scan()
        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

    def test_list_scans_contains_saved_scan(self):
        scan_id = self.save_dummy_scan()
        scans = db.list_scans()
        self.assertTrue(any(scan["id"] == scan_id for scan in scans))
        self.assertTrue(any(scan["value"] == "https://example.com" for scan in scans))

    def test_get_scan_returns_target(self):
        scan_id = self.save_dummy_scan()
        scan = db.get_scan(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["value"], "https://example.com")
        self.assertIsNone(scan["sbom_path"])

    def test_init_db_migrates_old_scans_table(self):
        conn = sqlite3.connect(db.DB_PATH)
        conn.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, "
            "scan_type TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute("INSERT INTO scans (target_id, scan_type) VALUES (1, 'url')")
        conn.commit()
        conn.close()

        db.init_db()
        db.init_db()

        conn = sqlite3.connect(db.DB_PATH)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(scans)")]
        row = conn.execute("SELECT id, scan_type, sbom_path FROM scans").fetchone()
        conn.close()
        self.assertIn("sbom_path", columns)
        self.assertEqual(row, (1, "url", None))

    def test_save_scan_stores_sbom_path(self):
        db.init_db()
        path = os.path.join(self.folder.name, "sbom.json")
        scan_id = db.save_scan("manifest", "sca", "requirements.txt", [], path)
        scan = db.get_scan(scan_id)
        self.assertEqual(scan["sbom_path"], path)


if __name__ == "__main__":
    unittest.main()
