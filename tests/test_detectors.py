import datetime as dt
import unittest


from main import (
    detect_failed_login_burst,
    detect_unusual_success,
    detect_privilege_escalation,
)

def _iso(y, m, d, H, M, S=0):
    return dt.datetime(y, m, d, H, M, S).isoformat()

class TestDetectors(unittest.TestCase):
    def test_failed_login_burst_by_user_ip(self):
        base = dt.datetime(2025, 3, 27, 10, 0, 0)
        events = [
            {
                "timestamp": (base + dt.timedelta(minutes=i)).isoformat(),
                "event_id": "4625",
                "user": "gaspar",
                "src_ip": "1.2.3.4",
                "host": "PC",
            }
            for i in range(5)
        ]
        findings = detect_failed_login_burst(events, threshold=5, window_minutes=10)
        self.assertTrue(any(f["rule"] == "failed_login_burst" for f in findings))

    def test_unusual_success_off_hours(self):
        e = [
            {
                "timestamp": _iso(2025, 3, 27, 23, 30),
                "event_id": "4624",
                "user": "gaspar",
                "src_ip": "192.168.1.50",
                "host": "PC",
            }
        ]
        f = detect_unusual_success(
            e,
            allowed_cidrs=["192.168.0.0/16"],
            enforce_business_hours=True,
            business_hours="08:00-20:00",
        )
        self.assertTrue(f)
        self.assertEqual(f[0]["rule"], "unusual_success")
        self.assertEqual(f[0]["severity"], "MEDIUM")

    def test_privilege_escalation_linux_sudo(self):
        e = [
            {
                "timestamp": _iso(2025, 3, 27, 12, 0),
                "event_id": "LINUX_SUDO",
                "event_type": "sudo",
                "user": "gaspar",
                "src_ip": None,
                "host": "host",
            }
        ]
        f = detect_privilege_escalation(e)
        self.assertTrue(f)
        self.assertEqual(f[0]["rule"], "privilege_escalation")

if __name__ == "__main__":
    unittest.main()
