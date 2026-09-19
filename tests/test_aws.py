import unittest

from src.aws import normalize_cloudtrail


class TestCloudTrailNormalizer(unittest.TestCase):
    def test_console_login_is_normalized(self):
        raw_event = {
            "eventTime": "2026-09-19T01:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.10",
            "userIdentity": {
                "arn": "arn:aws:iam::111122223333:root"
            },
        }

        normalized = normalize_cloudtrail(raw_event)

        self.assertEqual(normalized.source, "aws_cloudtrail")
        self.assertEqual(
            normalized.action,
            "signin.amazonaws.com:ConsoleLogin",
        )
        self.assertEqual(normalized.outcome, "success")
        self.assertEqual(normalized.resource, None)


    def test_event_with_error_is_failure(self):
        raw_event = {
            "eventTime": "2026-09-19T01:05:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "errorCode": "AccessDenied",
            "userIdentity": {
                "arn": "arn:aws:iam::111122223333:root"
            },
        }

        normalized = normalize_cloudtrail(raw_event)

        self.assertEqual(normalized.outcome, "failure")
        self.assertEqual(
            normalized.action,
            "iam.amazonaws.com:CreateUser",
        ) 
