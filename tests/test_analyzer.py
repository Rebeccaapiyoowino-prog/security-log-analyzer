import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_log


class TestSecurityLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.log_data = """
Sep 30 08:11:02 server sshd[1201]: Failed password for invalid user admin from 203.0.113.45 port 52311 ssh2
Sep 30 08:11:15 server sshd[1202]: Failed password for invalid user admin from 203.0.113.45 port 52315 ssh2
Sep 30 08:11:29 server sshd[1203]: Failed password for invalid user root from 203.0.113.45 port 52319 ssh2
Sep 30 08:11:44 server sshd[1204]: Failed password for invalid user root from 203.0.113.45 port 52324 ssh2
Sep 30 08:12:01 server sshd[1205]: Failed password for invalid user test from 203.0.113.45 port 52330 ssh2
Sep 30 08:12:18 server sshd[1206]: Failed password for invalid user admin from 203.0.113.45 port 52336 ssh2
Sep 30 08:15:03 server sshd[1210]: Accepted password for rebecca from 192.0.2.18 port 51123 ssh2
"""

        temp = tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            encoding="utf-8"
        )

        temp.write(self.log_data)
        temp.close()

        self.log_file = Path(temp.name)

    def tearDown(self):
        self.log_file.unlink(missing_ok=True)

    def test_detects_failed_logins(self):
        results = analyze_log(str(self.log_file))

        self.assertEqual(
            results["failed_logins"]["203.0.113.45"],
            6
        )

    def test_flags_brute_force_source(self):
        results = analyze_log(str(self.log_file), threshold=5)

        self.assertIn(
            "203.0.113.45",
            results["suspicious_ips"]
        )

    def test_detects_successful_login(self):
        results = analyze_log(str(self.log_file))

        self.assertEqual(
            results["successful_logins"]["192.0.2.18"],
            1
        )

    def test_threshold_can_be_changed(self):
        results = analyze_log(str(self.log_file), threshold=7)

        self.assertNotIn(
            "203.0.113.45",
            results["suspicious_ips"]
        )

    def test_missing_file_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            analyze_log("missing-auth.log")


if __name__ == "__main__":
    unittest.main()
