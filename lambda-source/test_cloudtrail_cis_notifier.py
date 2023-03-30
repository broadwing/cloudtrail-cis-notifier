import unittest
from unittest.mock import MagicMock
import json
import gzip
import base64
import cloudtrail_cis_notifier

class TestLambdaFunction(unittest.TestCase):
    def setUp(self):
        with open("decoded-test-messages.json", "r") as file:
            self.test_messages = json.load(file)

        cloudtrail_cis_notifier.RESOURCE_NAME = "slack-notifier"

    def test_get_events(self):
        log_data = {
            "messageType": "DATA_MESSAGE",
            "owner": "123456789012",
            "logGroup": "testLogGroup",
            "logStream": "testLogStream",
            "subscriptionFilters": ["testFilter"],
            "logEvents": [
                {
                    "id": "eventId1",
                    "timestamp": 1627318394000,
                    "message": "{\"key\": \"value\"}"
                },
                {
                    "id": "eventId2",
                    "timestamp": 1627318394000,
                    "message": "{\"key\": \"value\"}"
                }
            ]
        }

        compressed_data = gzip.compress(json.dumps(log_data).encode('utf-8'))
        b64_data = base64.b64encode(compressed_data)

        event = {
            "awslogs": {
                "data": b64_data
            }
        }

        expected_events = [json.loads(e['message']) for e in log_data['logEvents']]
        result = cloudtrail_cis_notifier.get_events(event)
        self.assertEqual(result, expected_events)

    def test_match_event_unauthorized_api(self):
        event = {
            "errorCode": "UnauthorizedOperation"
        }
        result = cloudtrail_cis_notifier.match_event(event)
        self.assertEqual(result, "3.1 Unauthorized API Call")

    def test_format_slack_attachment(self):
        event = {
            "eventName": "TestEvent",
            "eventID": "testEventId",
            "eventSource": "test.amazonaws.com",
            "eventType": "TestType",
            "eventTime": "2021-07-26T19:59:54Z",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "testuser"
            },
            "userAgent": "TestAgent",
            "recipientAccountId": "123456789012"
        }
        matched_rule = "3.1 Unauthorized API Call"
        result = cloudtrail_cis_notifier.format_slack_attachment(event, matched_rule)
        self.assertEqual(result["fallback"], "AWS Event TestEvent - test.amazonaws.com by User testuser")

    def test_sample_events(self):
        tests = [
                    (0, "3.1 Unauthorized API Call"),
                    (1, "3.2 Console Login without MFA"),
                    (2, "3.3 Root Account Used"),
                    (3, "3.4 IAM Policy Changed"),
                    (4, "3.5 CloudTrail Configuration Changed"),
                    (5, "3.5 CIS Slack Notifier Lambda Code Changed"),
                    (6, "3.5 CIS Slack Notifier Log Group or Subscription Filter Changed"),
                    (7, "3.6 Console Login Failure - Failed Authentication"),
                    (8, "3.6 Console Login Failure"),
                    (9, "3.7 Scheduled Deletion of KMS"),
                    (10, "3.8 S3 Bucket Policy Changed"),
                    (11, "3.9 Config Service Changed"),
                    (12, "3.10 Security Group Changed"),
                    (13, "3.11 Network ACL Changed"),
                    (14, "3.12 Network Gateway Changed"),
                    (15, "3.13 Network Route Table Changed"),
                    (16, "3.14 VPC Changed"),
                    (17, "3.15 SNS Subscribers Changed"),
                    (18, False),
                    (19, False),
                ]
        for test in tests:
            id = self.test_messages["logEvents"][test[0]]["id"]
            message = self.test_messages["logEvents"][test[0]]["message"]
            event = json.loads(message)
            self.assertEqual(cloudtrail_cis_notifier.match_event(event), test[1], f"Failed test {id}")


if __name__ == "__main__":
    unittest.main()
