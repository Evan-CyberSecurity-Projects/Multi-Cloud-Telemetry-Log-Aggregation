import unittest

from src.detections import Detection
from src.report import build_summary
from src.schema import NormalizedEvent


class TestReport(unittest.TestCase):
    def test_build_summary_counts_events_and_detections(self):
        aws_event = NormalizedEvent(
            timestamp="2026-09-19T02:00:00Z",
            source="aws_cloudtrail",
            actor="analyst@example.com",
            action="iam.amazonaws.com:CreateUser",
            outcome="failure",
            resource=None,
            source_ip="203.0.113.10",
            raw_event={},
        )

        wazuh_event = NormalizedEvent(
            timestamp="2026-09-19T02:10:00Z",
            source="wazuh_sysmon",
            actor="Windows-wazuh",
            action="wazuh_rule:92219",
            outcome="alert",
            resource="EventChannel",
            source_ip="10.0.2.15",
            raw_event={},
        )

        detections = [
            Detection(
                rule_id="CLOUD-001",
                severity="medium",
                title="Failed AWS IAM user creation attempt",
                description="Denied IAM user creation.",
                event=aws_event,
            ),
            Detection(
                rule_id="ENDPOINT-001",
                severity="medium",
                title="Possible DLL search order hijack",
                description="Review endpoint activity.",
                event=wazuh_event,
            ),
        ]

        summary = build_summary(
            [aws_event, wazuh_event],
            detections,
        )

        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["total_detections"], 2)
        self.assertEqual(
            summary["events_by_source"]["aws_cloudtrail"],
            1,
        )
        self.assertEqual(
            summary["detections_by_severity"]["medium"],
            2,
        )
