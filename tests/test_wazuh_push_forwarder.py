import base64
import gzip
import importlib.util
import json
import os
import pathlib
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "foundation" / "lambda" / "wazuh_push_forwarder.py"


class FakeSqs:
    def __init__(self):
        self.calls = []

    def send_message_batch(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "Successful": [{"Id": entry["Id"]} for entry in kwargs["Entries"]],
            "Failed": [],
        }


FAKE_SQS = FakeSqs()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.client = lambda service, region_name=None: FAKE_SQS
sys.modules["boto3"] = fake_boto3

spec = importlib.util.spec_from_file_location("wazuh_push_forwarder", MODULE_PATH)
forwarder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forwarder)


def subscription_event(payload):
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode("utf-8")))
    return {"awslogs": {"data": encoded.decode("ascii")}}


class WazuhPushForwarderTests(unittest.TestCase):
    def setUp(self):
        FAKE_SQS.calls.clear()
        os.environ.update(
            {
                "AWS_REGION": "ap-northeast-2",
                "EXPECTED_ACCOUNT_ID": "433048100798",
                "EXPECTED_LOG_GROUP": "/aws/eks/aws-topology-primary/dvwa",
                "QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/433048100798/test",
                "SCHEMA_VERSION": "1",
                "SOURCE_NAME": "dvwa",
            }
        )

    def test_forwards_every_data_event_without_detection_filtering(self):
        payload = {
            "owner": "433048100798",
            "logGroup": "/aws/eks/aws-topology-primary/dvwa",
            "logStream": "pod/example",
            "subscriptionFilters": ["aws-topology-wazuh-push-dvwa"],
            "messageType": "DATA_MESSAGE",
            "logEvents": [
                {
                    "id": "event-command",
                    "timestamp": 1786932000000,
                    "message": json.dumps(
                        {
                            "log": "must-not-cross-the-push-boundary",
                            "app_event": {
                                "event_type": "command.execution",
                                "result": "succeeded",
                                "route": "/vulnerabilities/exec/",
                                "take_id": "capital-one-reattack-20260818T082500Z-c0de1001",
                                "pod_name": "dvwa-84bf674cb6-h75c2",
                                "pod_uid": "069248dc-333f-4925-a8af-4f92f2e4e977",
                                "context": {
                                    "action": "shell_command",
                                    "resource": "ec2_imds",
                                    "security_level": "low",
                                    "stage": "imds_credential_fetch",
                                    "status": "output_returned",
                                    "command": "must-not-cross-the-push-boundary",
                                    "credential_role": "must-not-cross-the-push-boundary",
                                },
                            },
                            "password": "must-not-cross-the-push-boundary",
                        }
                    ),
                },
                {
                    "id": "event-health",
                    "timestamp": 1786932001000,
                    "message": json.dumps(
                        {"event_type": "http.access", "route": "/health"}
                    ),
                },
            ],
        }

        result = forwarder.lambda_handler(subscription_event(payload), None)

        self.assertEqual({"received": 2, "forwarded": 2}, result)
        self.assertEqual(1, len(FAKE_SQS.calls))
        bodies = [
            json.loads(entry["MessageBody"])
            for entry in FAKE_SQS.calls[0]["Entries"]
        ]
        self.assertEqual(
            ["command.execution", "http.access"],
            [body["payload"]["event_type"] for body in bodies],
        )
        self.assertTrue(all(body["source"] == "dvwa" for body in bodies))
        self.assertTrue(all(body["transport"] == "push" for body in bodies))
        self.assertNotEqual(bodies[0]["event_id"], bodies[1]["event_id"])
        self.assertEqual(
            {
                "event_type": "command.execution",
                "result": "succeeded",
                "route": "/vulnerabilities/exec/",
                "take_id": "capital-one-reattack-20260818T082500Z-c0de1001",
                "pod_name": "dvwa-84bf674cb6-h75c2",
                "pod_uid": "069248dc-333f-4925-a8af-4f92f2e4e977",
                "context": {
                    "action": "shell_command",
                    "resource": "ec2_imds",
                    "security_level": "low",
                    "stage": "imds_credential_fetch",
                    "status": "output_returned",
                },
                "normalized": True,
            },
            bodies[0]["payload"],
        )
        self.assertNotIn("log", bodies[0]["payload"])
        self.assertNotIn("password", bodies[0]["payload"])
        self.assertNotIn("command", bodies[0]["payload"]["context"])
        self.assertNotIn("credential_role", bodies[0]["payload"]["context"])

    def test_unstructured_log_keeps_only_a_non_sensitive_marker(self):
        payload = {
            "owner": "433048100798",
            "logGroup": "/aws/eks/aws-topology-primary/dvwa",
            "logStream": "pod/example",
            "subscriptionFilters": ["aws-topology-wazuh-push-dvwa"],
            "messageType": "DATA_MESSAGE",
            "logEvents": [
                {
                    "id": "event-unstructured",
                    "timestamp": 1786932000000,
                    "message": "password=SYNTHETIC_SECRET cookie=SYNTHETIC_COOKIE",
                }
            ],
        }

        result = forwarder.lambda_handler(subscription_event(payload), None)

        self.assertEqual({"received": 1, "forwarded": 1}, result)
        body = json.loads(FAKE_SQS.calls[0]["Entries"][0]["MessageBody"])
        self.assertEqual({"normalized": False}, body["payload"])
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(body))
        self.assertNotIn("SYNTHETIC_COOKIE", json.dumps(body))

    def test_rejects_an_unapproved_log_group(self):
        payload = {
            "owner": "433048100798",
            "logGroup": "/aws/lambda/aws-topology-wazuh-push-primary",
            "logStream": "recursive",
            "messageType": "DATA_MESSAGE",
            "logEvents": [],
        }

        with self.assertRaisesRegex(ValueError, "EXPECTED_LOG_GROUP"):
            forwarder.lambda_handler(subscription_event(payload), None)

        self.assertEqual([], FAKE_SQS.calls)

    def test_ignores_cloudwatch_control_messages(self):
        payload = {
            "owner": "433048100798",
            "logGroup": "/aws/eks/aws-topology-primary/dvwa",
            "logStream": "control",
            "messageType": "CONTROL_MESSAGE",
        }

        result = forwarder.lambda_handler(subscription_event(payload), None)

        self.assertEqual({"received": 0, "forwarded": 0}, result)
        self.assertEqual([], FAKE_SQS.calls)


if __name__ == "__main__":
    unittest.main()
