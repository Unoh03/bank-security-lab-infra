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


def valid_alert() -> dict[str, object]:
    return {
        "id": "1787000000.123456",
        "timestamp": "2026-08-18T01:02:03.000+0000",
        "rule": {
            "id": "100103",
            "level": 10,
            "description": "not forwarded",
        },
        "data": {
            "schema_version": 1,
            "event_id": (
                "cwl:433048100798:/aws/eks/aws-topology-primary/"
                "application:stream-name:0123456789abcdef"
            ),
            "source": "dvwa",
            "aws_account_id": "433048100798",
            "aws_region": "ap-northeast-2",
            "event_time": "2026-08-18T01:02:03.000Z",
            "transport": "push",
            "raw_message_sha256": "a" * 64,
            "payload": {
                "normalized": True,
                "take_id": "capital-one-20260818T010000Z-deadbeef",
                "event_type": "command.execution",
                "result": "succeeded",
                "route": "/vulnerabilities/exec/",
                "source_ip": "must-not-be-forwarded",
                "user_id": "must-not-be-forwarded",
                "request_id": "must-not-be-forwarded",
                "context": {
                    "action": "shell_command",
                    "resource": "ec2_imds",
                    "security_level": "low",
                    "status": "output_returned",
                },
            },
        },
        "full_log": "must-not-be-forwarded",
    }


class CustomShuffleSocTest(unittest.TestCase):
    def test_builds_only_the_frozen_sanitized_schema(self) -> None:
        result = MODULE.build_sanitized_alert(
            valid_alert(),
            now=datetime(2026, 8, 18, 1, 3, 0, tzinfo=timezone.utc),
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
        self.assertEqual(result["rule"], {"id": "100103", "level": 10})
        self.assertEqual(
            result["incident"]["take_id"],
            "capital-one-20260818T010000Z-deadbeef",
        )
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in (
            "full_log",
            "source_ip",
            "user_id",
            "request_id",
            "command",
            "cookie",
            "token",
            "must-not-be-forwarded",
        ):
            self.assertNotIn(forbidden, encoded.lower())

    def test_body_hash_covers_the_schema_before_the_hash_field(self) -> None:
        result = MODULE.build_sanitized_alert(
            valid_alert(),
            now=datetime(2026, 8, 18, 1, 3, 0, tzinfo=timezone.utc),
        )
        body_hash = result["integrity"].pop("body_sha256")

        self.assertEqual(
            body_hash,
            hashlib.sha256(MODULE.canonical_json(result)).hexdigest(),
        )

    def test_rejects_alert_without_valid_take_id(self) -> None:
        alert = valid_alert()
        del alert["data"]["payload"]["take_id"]
        with self.assertRaisesRegex(MODULE.ContractError, "take_id"):
            MODULE.build_sanitized_alert(alert)

        alert = valid_alert()
        alert["data"]["payload"]["take_id"] = "capital-one-legacy"
        with self.assertRaisesRegex(MODULE.ContractError, "take_id"):
            MODULE.build_sanitized_alert(alert)

    def test_rejects_non_allowlisted_alert_contracts(self) -> None:
        mutations = (
            (lambda value: value["rule"].__setitem__("id", "100100")),
            (lambda value: value["data"].__setitem__("source", "cloudtrail")),
            (lambda value: value["data"].__setitem__("transport", "poll")),
            (lambda value: value["data"].__setitem__("aws_region", "us-east-1")),
            (
                lambda value: value["data"]["payload"].__setitem__(
                    "route", "/other"
                )
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                alert = valid_alert()
                mutate(alert)
                with self.assertRaises(MODULE.ContractError):
                    MODULE.build_sanitized_alert(alert)

    def test_webhook_url_is_https_and_host_allowlisted(self) -> None:
        webhook_id = "22222222-2222-4222-8222-222222222222"
        for path in (
            f"/api/v1/hooks/{webhook_id}",
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
