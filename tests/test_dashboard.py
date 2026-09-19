import unittest

from src.dashboard import render_dashboard
from src.detections import Detection
from src.schema import NormalizedEvent


class TestDashboard(unittest.TestCase):
    def test_dashboard_contains_detection_details(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T02:00:00Z",
            source="aws_cloudtrail",
            actor="analyst@example.com",
            action="iam.amazonaws.com:CreateUser",
            outcome="failure",
            resource=None,
            source_ip="203.0.113.10",
            raw_event={},
        )

        detection = Detection(
            rule_id="CLOUD-001",
            severity="medium",
            title="Failed AWS IAM user creation attempt",
            description="An IAM user creation attempt was denied.",
            event=event,
            mitre_tactic="Persistence",
            mitre_technique="T1136.003 Create Cloud Account",
            confidence="medium",
            recommended_action="Review related CloudTrail activity.",
        )

        summary = {
            "total_events": 1,
            "total_detections": 1,
            "events_by_source": {
                "aws_cloudtrail": 1,
            },
            "detections_by_source": {
                "aws_cloudtrail": 1,
            },
            "detections_by_severity": {
                "medium": 1,
            },
            "detections_by_tactic": {
                "Persistence": 1,
            },
            "detections_by_confidence": {
                "medium": 1,
            },
        }

        html = render_dashboard(summary, [detection])

        self.assertIn("Security Telemetry Dashboard", html)
        self.assertIn("CLOUD-001", html)
        self.assertIn("T1136.003 Create Cloud Account", html)
        self.assertIn("Review related CloudTrail activity.", html)
