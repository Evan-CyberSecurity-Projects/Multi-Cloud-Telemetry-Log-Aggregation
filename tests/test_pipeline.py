import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.detections import Detection
from src.pipeline import write_detections, write_events
from src.schema import NormalizedEvent


class TestPipeline(unittest.TestCase):
    def test_write_events_creates_ndjson(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T01:15:00Z",
            source="aws_cloudtrail",
            actor="analyst@example.com",
            action="signin.amazonaws.com:ConsoleLogin",
            outcome="success",
            resource=None,
            source_ip="203.0.113.10",
            raw_event={"eventName": "ConsoleLogin"},
        )

        with TemporaryDirectory() as temp_directory:
            output_path = Path(temp_directory) / "normalized.jsonl"

            write_events([event], output_path)

            lines = output_path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])

        self.assertEqual(len(lines), 1)
        self.assertEqual(record["source"], "aws_cloudtrail")
        self.assertEqual(
            record["action"],
            "signin.amazonaws.com:ConsoleLogin",
        )

    def test_write_detections_creates_ndjson(self):
        event = NormalizedEvent(
            timestamp="2026-09-19T01:20:00Z",
            source="aws_cloudtrail",
            actor="analyst@example.com",
            action="iam.amazonaws.com:CreateUser",
            outcome="failure",
            resource=None,
            source_ip="203.0.113.10",
            raw_event={"errorCode": "AccessDenied"},
        )

        detection = Detection(
            rule_id="CLOUD-001",
            severity="medium",
            title="Failed AWS IAM user creation attempt",
            description="An IAM user creation attempt was denied.",
            event=event,
        )

        with TemporaryDirectory() as temp_directory:
            output_path = Path(temp_directory) / "detections.jsonl"

            write_detections([detection], output_path)

            lines = output_path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])

        self.assertEqual(len(lines), 1)
        self.assertEqual(record["rule_id"], "CLOUD-001")
        self.assertEqual(record["event"]["outcome"], "failure")
