import unittest

from src.detections import detect
from src.schema import NormalizedEvent


class TestDetections(unittest.TestCase):
    def test_failed_aws_iam_user_creation_generates_detection(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T02:00:00Z",
            source="aws_cloudtrail",
            actor="arn:aws:iam::111122223333:root",
            action="iam.amazonaws.com:CreateUser",
            outcome="failure",
            resource=None,
            source_ip="203.0.113.10",
            raw_event={"errorCode": "AccessDenied"},
        )

        detections = detect(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "CLOUD-001")
        self.assertEqual(detections[0].severity, "medium")
        self.assertEqual(
            detections[0].mitre_technique,
            "T1136.003 Create Cloud Account",
        )

    def test_azure_role_assignment_generates_high_detection(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T02:01:00Z",
            source="azure_activity_log",
            actor="analyst@example.com",
            action="Microsoft.Authorization/roleAssignments/write",
            outcome="success",
            resource="/subscriptions/example/resourceGroups/rg-telemetry-lab",
            source_ip="203.0.113.20",
            raw_event={},
        )

        detections = detect(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "CLOUD-002")
        self.assertEqual(detections[0].severity, "high")
        self.assertEqual(
            detections[0].mitre_technique,
            "T1098 Account Manipulation",
        )

    def test_wazuh_dll_hijack_rule_generates_detection(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T02:10:00Z",
            source="wazuh_sysmon",
            actor="Windows-wazuh",
            action="wazuh_rule:92219",
            outcome="alert",
            resource="EventChannel",
            source_ip="10.0.2.15",
            raw_event={},
        )

        detections = detect(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "ENDPOINT-001")
        self.assertEqual(detections[0].severity, "medium")
        self.assertEqual(
            detections[0].mitre_technique,
            "T1574.001 DLL Search Order Hijacking",
        )
