import tempfile
import unittest
from pathlib import Path

from main import analyze_log, extract_ipv4


class LogAnalyzerTests(unittest.TestCase):
    def test_extracts_valid_ipv4(self):
        self.assertEqual(extract_ipv4("Failed login from 192.0.2.10"), "192.0.2.10")

    def test_rejects_invalid_ipv4_candidate(self):
        self.assertIsNone(extract_ipv4("Failed login from 999.999.999.999"))

    def test_counts_failed_logins_and_threshold_alert(self):
        content = "\n".join([
            "Information: service started",
            "Failed login for user a from 203.0.113.25",
            "Failed login for user b from 203.0.113.25",
            "Failed login for user c from 203.0.113.25",
            "Failed login for user d from 203.0.113.25",
            "LOGIN_SUCCESS for user a from 192.0.2.10",
            "Error: service unavailable",
        ])
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            log_path.write_text(content, encoding="utf-8")
            report = analyze_log(log_path, threshold=4)

        self.assertEqual(report["summary"]["total_events"], 7)
        self.assertEqual(report["summary"]["failed_logins"], 4)
        self.assertEqual(report["summary"]["successful_logins"], 1)
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["alerts"], [
            {"ip": "203.0.113.25", "failed_attempts": 4}
        ])

    def test_no_alert_below_threshold(self):
        content = "Failed login from 198.51.100.8\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            log_path.write_text(content, encoding="utf-8")
            report = analyze_log(log_path, threshold=4)
        self.assertEqual(report["alerts"], [])


if __name__ == "__main__":
    unittest.main()
