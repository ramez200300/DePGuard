import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import sca


class ScaTests(unittest.TestCase):
    def test_parse_requirements_valid_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "requirements.txt")
            with open(path, "w", encoding="utf-8") as file:
                file.write("flask==2.0.0\nrequests>=2.28.0\n# comment\n")
            packages = sca.parse_requirements(path)
        self.assertEqual(packages, [("flask", "2.0.0"), ("requests", "2.28.0")])

    def test_empty_manifest_raises_value_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "requirements.txt")
            with open(path, "w", encoding="utf-8"):
                pass
            with self.assertRaisesRegex(ValueError, "Manifest file is empty or invalid"):
                sca.parse_manifest(path)

    def test_split_requirement(self):
        self.assertEqual(sca.split_requirement("flask==2.0.0"), ("flask", "2.0.0"))


if __name__ == "__main__":
    unittest.main()
