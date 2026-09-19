import unittest

from src.detections import detect
from src.schema import NormalizedEvent


class TestDetectionQuality(unittest.TestCase):
    def test_successful_aws_console_login_does_not_alert(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T03:00:00Z",
            source="aws_cloudtrail",
            actor="analyst@example.com",
            action="signin.amazonaws.com:ConsoleLogin",
            outcome="success",
            resource=None,
            source_ip="203.0.113.30",
            raw_event={},
        )

        self.assertEqual(detect(event), [])

    def test_azure_resource_group_creation_does_not_alert(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T03:01:00Z",
            source="azure_activity_log",
            actor="analyst@example.com",
            action=(
                "Microsoft.Resources/subscriptions/"
                "resourceGroups/write"
            ),
            outcome="success",
            resource="/subscriptions/example/resourceGroups/rg-lab",
            source_ip=None,
            raw_event={},
        )

        self.assertEqual(detect(event), [])

    def test_generic_wazuh_alert_does_not_alert(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T03:02:00Z",
            source="wazuh_sysmon",
            actor="Windows-wazuh",
            action="wazuh_rule:100001",
            outcome="alert",
            resource="EventChannel",
            source_ip="10.0.2.15",
            raw_event={},
        )

        self.assertEqual(detect(event), [])
