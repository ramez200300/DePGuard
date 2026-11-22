import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import db


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.original_path = db.DB_PATH
        db.DB_PATH = os.path.join(cls.folder.name, "test.db")
        import app
        cls.client = app.app.test_client()

    @classmethod
    def tearDownClass(cls):
        db.DB_PATH = cls.original_path
        cls.folder.cleanup()

    def test_home_returns_200(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_new_scan_form_returns_200(self):
        response = self.client.get("/new")
        self.assertEqual(response.status_code, 200)

    def test_missing_scan_returns_404(self):
        response = self.client.get("/scan/9999")
        self.assertEqual(response.status_code, 404)

    def make_sbom_scan(self, filename):
        path = os.path.join(self.folder.name, filename)
        with open(path, "w", encoding="utf-8") as file:
            file.write('{"packages": []}')
        scan_id = db.save_scan("manifest", "sca", "requirements.txt", [], path)
        return scan_id, path

    def test_sbom_download_returns_file(self):
        scan_id, _ = self.make_sbom_scan("download.json")
        response = self.client.get("/sbom/" + str(scan_id))
        try:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, b'{"packages": []}')
            self.assertIn("attachment", response.headers.get("Content-Disposition", ""))
        finally:
            response.close()

    def test_sbom_missing_file_returns_404(self):
        path = os.path.join(self.folder.name, "missing.json")
        scan_id = db.save_scan("manifest", "sca", "requirements.txt", [], path)
        response = self.client.get("/sbom/" + str(scan_id))
        try:
            self.assertEqual(response.status_code, 404)
        finally:
            response.close()

    def test_sbom_without_path_returns_404(self):
        scan_id = db.save_scan("url", "url", "https://example.com", [])
        response = self.client.get("/sbom/" + str(scan_id))
        try:
            self.assertEqual(response.status_code, 404)
        finally:
            response.close()

    def test_scan_details_shows_sbom_link_only_for_sca(self):
        scan_id, _ = self.make_sbom_scan("details.json")
        response = self.client.get("/scan/" + str(scan_id))
        try:
            html = response.get_data(as_text=True)
        finally:
            response.close()
        self.assertIn('href="/sbom/' + str(scan_id) + '"', html)

        url_id = db.save_scan("url", "url", "https://example.com", [])
        response = self.client.get("/scan/" + str(url_id))
        try:
            url_html = response.get_data(as_text=True)
        finally:
            response.close()
        self.assertNotIn("Download SBOM", url_html)


if __name__ == "__main__":
    unittest.main()
