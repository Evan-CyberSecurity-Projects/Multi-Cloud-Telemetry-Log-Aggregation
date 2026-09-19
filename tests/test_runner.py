import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.runner import run_pipeline


class TestRunner(unittest.TestCase):
    def test_run_pipeline_processes_multiple_sources(self):
        aws_event = {
            "eventTime": "2026-09-19T02:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "errorCode": "AccessDenied",
            "userIdentity": {
                "arn": "arn:aws:iam::111122223333:root"
            },
        }

        azure_event = {
            "eventTimestamp": "2026-09-19T02:01:00Z",
            "caller": "analyst@example.com",
            "operationName": {
                "value": (
                    "Microsoft.Authorization/"
                    "roleAssignments/write"
                )
            },
            "status": {
                "value": "Succeeded"
            },
        }

        wazuh_event = {
            "@timestamp": "2026-09-19T02:10:00.000Z",
            "agent": {
                "name": "Windows-wazuh",
                "ip": "10.0.2.15",
            },
            "rule": {
                "id": "92219",
            },
            "location": "EventChannel",
        }

        with TemporaryDirectory() as temp_directory:
            temporary_path = Path(temp_directory)
            input_path = temporary_path / "input"
            output_path = temporary_path / "output"
            input_path.mkdir()

            (input_path / "aws.json").write_text(
                json.dumps(aws_event),
                encoding="utf-8",
            )
            (input_path / "azure.json").write_text(
                json.dumps(azure_event),
                encoding="utf-8",
            )
            (input_path / "wazuh.json").write_text(
                json.dumps(wazuh_event),
                encoding="utf-8",
            )

            events, detections, summary = run_pipeline(
                input_path,
                output_path,
            )

            self.assertEqual(len(events), 3)
            self.assertEqual(len(detections), 3)
            self.assertEqual(summary["total_events"], 3)
            self.assertTrue(
                (output_path / "dashboard.html").exists()
            )
