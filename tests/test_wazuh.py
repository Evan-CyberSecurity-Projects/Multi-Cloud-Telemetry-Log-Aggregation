import unittest

from src.wazuh import normalize_wazuh_alert


class TestWazuhNormalizer(unittest.TestCase):
    def test_sysmon_alert_is_normalized(self):
        raw_event = {
            "@timestamp": "2026-09-19T02:10:00.000Z",
            "agent": {
                "name": "Windows-wazuh",
                "ip": "10.0.2.15",
            },
            "rule": {
                "id": "92219",
                "level": 6,
                "description": "Possible DLL search order hijack",
            },
            "location": "EventChannel",
        }

        normalized = normalize_wazuh_alert(raw_event)

        self.assertEqual(normalized.source, "wazuh_sysmon")
        self.assertEqual(normalized.actor, "Windows-wazuh")
        self.assertEqual(normalized.action, "wazuh_rule:92219")
        self.assertEqual(normalized.outcome, "alert")
        self.assertEqual(normalized.source_ip, "10.0.2.15")
