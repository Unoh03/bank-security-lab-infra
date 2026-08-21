from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT_PATH = (
    ROOT
    / "observability"
    / "wazuh"
    / "integrations"
    / "custom-shuffle-soc"
)
LOADER = importlib.machinery.SourceFileLoader("custom_shuffle_soc", str(SCRIPT_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
MODULE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(MODULE)

VALIDATOR_PATH = (
    ROOT
    / "observability"
    / "shuffle"
    / "apps"
    / "aws-topology-soc-validator"
    / "1.0.0"
    / "src"
    / "validator.py"
)
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "soc_validator_from_sanitizer_test", VALIDATOR_PATH
)
assert VALIDATOR_SPEC is not None and VALIDATOR_SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


FULL_LOG = '{"eventName":"GetObject","sensitive":"must-not-be-forwarded"}'
EVENT_ID = "123e4567-e89b-12d3-a456-426614174000"
PRINCIPAL_ID = "AROAEXAMPLE:capital-one-demo-session"


def valid_alert() -> dict[str, object]:
    return {
        "id": "1787000000.123456",
        "timestamp": "2026-08-20T01:02:03.000+0000",
        "rule": {
            "id": "100104",
            "level": 12,
            "description": "high confidence S3 access",
        },
        "data": {
            "aws": {
                "source": "cloudtrail",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "recipientAccountId": "433048100798",
                "awsRegion": "ap-northeast-2",
                "eventID": EVENT_ID,
                "eventTime": "2026-08-20T01:02:03.000Z",
                "errorCode": "",
                "requestParameters": {
                    "bucketName": "aws-topology-primary-bd56288914d9d31c4d07225deb",
                    "key": "validation/capital-one-demo.csv",
                },
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": PRINCIPAL_ID,
                    "sessionContext": {
                        "sessionIssuer": {
                            "userName": "aws-topology-primary-karpenter-node",
                        }
                    },
                },
                "additionalEventData": {"httpStatusCode": "200"},
            }
        },
        "full_log": FULL_LOG,
    }


class CustomShuffleSocTest(unittest.TestCase):
    def test_builds_exact_v2_blueprint_without_raw_fields_or_take_id(self) -> None:
        result = MODULE.build_sanitized_alert(
            valid_alert(),
            now=datetime(2026, 8, 20, 1, 3, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(
            set(result),
            {
                "schema_version",
                "source_system",
                "sent_at_utc",
                "account_alias",
                "aws_account_id",
                "aws_region",
                "scenario_id",
                "rule",
                "incident",
                "integrity",
            },
        )
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["rule"], {
            "id": "100104",
            "level": 12,
            "role": "high_confidence_s3_access",
        })
        self.assertEqual(
            result["incident"],
            {
                "cloudtrail_event_id": EVENT_ID,
                "wazuh_alert_id": "1787000000.123456",
                "event_time_utc": "2026-08-20T01:02:03.000Z",
                "event_source": "s3.amazonaws.com",
                "event_name": "GetObject",
                "principal_role_name": "aws-topology-primary-karpenter-node",
                "principal_session_id_sha256": hashlib.sha256(
                    PRINCIPAL_ID.encode("utf-8")
                ).hexdigest(),
                "bucket_alias": "primary-application-data",
                "object_key": "validation/capital-one-demo.csv",
                "result": "success",
            },
        )
        self.assertEqual(
            result["integrity"]["raw_message_sha256"],
            hashlib.sha256(FULL_LOG.encode("utf-8")).hexdigest(),
        )
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in (
            "full_log",
            "principalId",
            "session-token",
            "must-not-be-forwarded",
            "take_id",
        ):
            self.assertNotIn(forbidden.lower(), encoded.lower())

    def test_body_hash_covers_the_schema_before_the_hash_field(self) -> None:
        result = MODULE.build_sanitized_alert(
            valid_alert(),
            now=datetime(2026, 8, 20, 1, 3, 0, tzinfo=timezone.utc),
        )
        body_hash = result["integrity"].pop("body_sha256")

        self.assertEqual(
            body_hash,
            hashlib.sha256(MODULE.canonical_json(result)).hexdigest(),
        )

    def test_actual_sanitizer_output_is_accepted_by_validator(self) -> None:
        result = MODULE.build_sanitized_alert(
            valid_alert(),
            now=datetime(2026, 8, 20, 1, 3, 0, tzinfo=timezone.utc),
        )
        validation = VALIDATOR.validate_sanitized_alert(result)
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["cloudtrail_event_id"], EVENT_ID)
        self.assertEqual(
            validation["dedupe_key"], f"CAPITAL-ONE:433048100798:{EVENT_ID}"
        )

    def test_canonicalizes_uppercase_cloudtrail_event_id(self) -> None:
        alert = valid_alert()
        alert["data"]["aws"]["eventID"] = EVENT_ID.upper()
        result = MODULE.build_sanitized_alert(alert)
        self.assertEqual(result["incident"]["cloudtrail_event_id"], EVENT_ID)

    def test_accepts_only_integer_200_or_exact_string_200_status(self) -> None:
        for value in (200, "200"):
            with self.subTest(value=value):
                alert = valid_alert()
                alert["data"]["aws"]["additionalEventData"]["httpStatusCode"] = value
                MODULE.build_sanitized_alert(alert)
        for value in (True, False, 200.0, "0200", "200.0", "201", None):
            with self.subTest(value=value):
                alert = valid_alert()
                alert["data"]["aws"]["additionalEventData"]["httpStatusCode"] = value
                with self.assertRaises(MODULE.ContractError):
                    MODULE.build_sanitized_alert(alert)

    def test_rejects_wrong_tuple_or_failed_event(self) -> None:
        mutations = (
            lambda value: value["data"]["aws"].__setitem__(
                "source", "other"
            ),
            lambda value: value["data"]["aws"].__setitem__(
                "recipientAccountId", "000000000000"
            ),
            lambda value: value["data"]["aws"].__setitem__(
                "awsRegion", "us-east-1"
            ),
            lambda value: value["data"]["aws"].__setitem__(
                "eventSource", "ec2.amazonaws.com"
            ),
            lambda value: value["data"]["aws"].__setitem__(
                "eventName", "PutObject"
            ),
            lambda value: value["data"]["aws"]["requestParameters"].__setitem__(
                "bucketName", "other-bucket"
            ),
            lambda value: value["data"]["aws"]["requestParameters"].__setitem__(
                "key", "web/capital-one-demo.csv"
            ),
            lambda value: value["data"]["aws"]["userIdentity"][
                "sessionContext"
            ]["sessionIssuer"].__setitem__(
                "userName", "other-role"
            ),
            lambda value: value["data"]["aws"]["userIdentity"].__setitem__(
                "type", "IAMUser"
            ),
            lambda value: value["data"]["aws"]["additionalEventData"].__setitem__(
                "httpStatusCode", "403"
            ),
            lambda value: value["data"]["aws"].__setitem__(
                "errorCode", "AccessDenied"
            ),
            lambda value: value["data"]["aws"].__setitem__(
                "eventID", "not-a-uuid"
            ),
            lambda value: value["rule"].__setitem__("id", "100103"),
            lambda value: value["rule"].__setitem__("level", 10),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                alert = valid_alert()
                mutate(alert)
                with self.assertRaises(MODULE.ContractError):
                    MODULE.build_sanitized_alert(alert)

    def test_rejects_unbounded_raw_or_principal_input(self) -> None:
        alert = valid_alert()
        alert["full_log"] = "x" * (MODULE.MAX_FULL_LOG_BYTES + 1)
        with self.assertRaisesRegex(MODULE.ContractError, "full_log"):
            MODULE.build_sanitized_alert(alert)

        alert = valid_alert()
        alert["data"]["aws"]["userIdentity"]["principalId"] = (
            "x" * (MODULE.MAX_PRINCIPAL_ID_BYTES + 1)
        )
        with self.assertRaisesRegex(MODULE.ContractError, "principalId"):
            MODULE.build_sanitized_alert(alert)

    def test_webhook_url_is_https_and_host_allowlisted(self) -> None:
        webhook_id = "22222222-2222-4222-8222-222222222222"
        for path in (
            f"/api/v1/hooks/{webhook_id}",
            f"/api/v1/hooks/webhook_{webhook_id}",
            f"/api/v1/webhooks/webhook_{webhook_id}",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    MODULE.validate_webhook_url(f"https://shuffler.io{path}"),
                    ("shuffler.io", path),
                )
        for rejected in (
            f"http://shuffler.io/api/v1/hooks/{webhook_id}",
            f"https://example.com/api/v1/hooks/{webhook_id}",
            f"https://shuffler.io/api/v1/hooks/{webhook_id}?redirect=1",
            f"https://shuffler.io.evil.example/api/v1/hooks/{webhook_id}",
            "https://shuffler.io/api/v1/hooks/" + ("abcd" * 4),
            f"https://shuffler.io/api/v1/webhooks/{webhook_id}",
        ):
            with self.subTest(rejected=rejected):
                with self.assertRaises(MODULE.ContractError):
                    MODULE.validate_webhook_url(rejected)


if __name__ == "__main__":
    unittest.main()
