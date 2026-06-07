import unittest
import config

class TestConfig(unittest.TestCase):
    def test_software_name(self):
        self.assertEqual(config.SOFTWARE_NAME, "PersonalDAV")

    def test_version_not_empty(self):
        self.assertTrue(len(config.SOFTWARE_VERSION) > 0)

    def test_default_db_path(self):
        self.assertTrue(config.DEFAULT_DB_PATH.endswith(".db"))

    def test_default_log_level(self):
        self.assertIn(config.DEFAULT_LOG_LEVEL, ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])

if __name__ == "__main__":
    unittest.main()