import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import scanner


class ScannerTests(unittest.TestCase):
    def test_clean_url_adds_https(self):
        self.assertEqual(scanner.clean_url("example.com"), "https://example.com")

    def test_clean_url_keeps_existing_scheme(self):
        self.assertEqual(scanner.clean_url("http://example.com"), "http://example.com")

    def test_check_headers_missing_headers(self):
        findings = scanner.check_headers({})
        self.assertEqual([item["title"] for item in findings], [
            "Missing header: Content-Security-Policy",
            "Missing header: X-Frame-Options",
            "Missing header: Strict-Transport-Security",
            "Missing header: X-Content-Type-Options",
        ])
        self.assertEqual([item["severity"] for item in findings],
                         ["Medium", "Medium", "Medium", "Low"])

    def test_check_headers_complete(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        self.assertEqual(scanner.check_headers(headers), [])


if __name__ == "__main__":
    unittest.main()
