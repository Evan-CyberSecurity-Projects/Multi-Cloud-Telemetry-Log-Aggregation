import unittest

from src.azure import normalize_activity_log


class TestAzureActivityLogNormalizer(unittest.TestCase):
    def test_resource_group_creation_is_normalized(self):
        raw_event = {
            "eventTimestamp": "2026-09-19T01:10:00Z",
            "caller": "analyst@example.com",
            "operationName": {
                "value": "Microsoft.Resources/subscriptions/resourceGroups/write"
            },
            "status": {
                "value": "Succeeded"
            },
            "resourceId": (
                "/subscriptions/11111111-1111-1111-1111-111111111111"
                "/resourceGroups/rg-telemetry-lab"
            ),
            "httpRequest": {
                "clientIpAddress": "203.0.113.20"
            },
        }

        normalized = normalize_activity_log(raw_event)

        self.assertEqual(normalized.source, "azure_activity_log")
        self.assertEqual(normalized.outcome, "success")
        self.assertEqual(
            normalized.action,
            "Microsoft.Resources/subscriptions/resourceGroups/write",
        )
        self.assertEqual(
            normalized.resource,
            "/subscriptions/11111111-1111-1111-1111-111111111111"
            "/resourceGroups/rg-telemetry-lab",
        )
