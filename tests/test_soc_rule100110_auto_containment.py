from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "observability"
    / "shuffle"
    / "apps"
    / "aws-topology-soc-rule100110-auto-containment"
    / "1.0.1"
    / "src"
    / "autocontainment.py"
)
API_PATH = MODULE_PATH.parents[1] / "api.yaml"
SPEC = importlib.util.spec_from_file_location("soc_rule100110_auto", MODULE_PATH)
autocontainment = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = autocontainment
SPEC.loader.exec_module(autocontainment)


TOKEN = "github_pat_" + ("a" * 80)
NOW = datetime(2026, 8, 21, 9, 7, 20, tzinfo=timezone.utc)
S3_NOW = datetime(2026, 8, 21, 9, 15, 30, tzinfo=timezone.utc)


def valid_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 3,
        "source_system": "wazuh",
        "sent_at_utc": "2026-08-21T09:07:20.000Z",
        "account_alias": "primary-lab",
        "aws_account_id": "433048100798",
        "aws_region": "ap-northeast-2",
        "scenario_id": "CAPITAL-ONE",
        "rule": {
            "id": "100110",
            "level": 12,
            "role": "imds_credential_access",
        },
        "incident": {
            "wazuh_alert_id": "1787000001.654321",
            "event_time_utc": "2026-08-21T09:07:02.418Z",
            "event_id_sha256": "b" * 64,
            "take_id": "capital-one-20260821T090624Z-55904626",
            "pod_name": "dvwa-86759c6f4d-jhl7x",
            "pod_uid": "390dd796-a52c-4f00-8767-944f4916d396",
            "event_type": "command.execution",
            "stage": "imds_credential_fetch",
            "status": "output_returned",
            "route": "/vulnerabilities/exec/",
            "result": "succeeded",
        },
        "integrity": {"raw_message_sha256": "c" * 64},
    }
    payload["integrity"]["body_sha256"] = hashlib.sha256(
        autocontainment._canonical(payload)
    ).hexdigest()
    return payload


def valid_rule100111_payload() -> dict[str, object]:
    return {
        "rule_id": "100111",
        "event_time_utc": "2026-08-21T09:07:05.000Z",
        "wazuh_alert_id": "1787000002.777777",
        "event_id_sha256": "d" * 64,
        "raw_message_sha256": "e" * 64,
    }


class FakeResponse:
    def __init__(self, payload: object, status: int = 200):
        self.payload = json.dumps(payload).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getcode(self):
        return self.status

    def read(self, _limit):
        return self.payload


class AutoContainmentTests(unittest.TestCase):
    def test_valid_payload_dispatches_only_fixed_workflow_and_inputs(self):
        observed = {}

        def opener(request, timeout):
            observed["url"] = request.full_url
            observed["method"] = request.get_method()
            observed["timeout"] = timeout
            observed["headers"] = dict(request.header_items())
            observed["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(
                {
                    "workflow_run_id": 32466516094,
                    "run_url": autocontainment.RUN_API_PREFIX + "32466516094",
                    "html_url": autocontainment.RUN_HTML_PREFIX + "32466516094",
                }
            )

        result = autocontainment.dispatch_rule_100110(
            TOKEN, valid_payload(), opener=opener, now=NOW
        )
        self.assertTrue(result["success"])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(observed["url"], autocontainment.DISPATCH_URL)
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["timeout"], 30)
        self.assertEqual(observed["body"]["ref"], "main")
        self.assertIs(observed["body"]["return_run_details"], True)
        self.assertEqual(
            set(observed["body"]["inputs"]),
            {
                "take_id",
                "scenario_id",
                "rule_id",
                "event_id_sha256",
                "pod_name",
                "pod_uid",
                "alert_body_sha256",
            },
        )
        self.assertEqual(
            observed["headers"]["Authorization"], f"Bearer {TOKEN}"
        )

    def test_rule100111_dispatches_only_fixed_hardening_workflow(self):
        observed = {}

        def opener(request, timeout):
            observed["url"] = request.full_url
            observed["timeout"] = timeout
            observed["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(
                {
                    "workflow_run_id": 32509999999,
                    "run_url": autocontainment.RUN_API_PREFIX + "32509999999",
                    "html_url": autocontainment.RUN_HTML_PREFIX + "32509999999",
                }
            )

        result = autocontainment.dispatch_rule_100110(
            TOKEN, valid_rule100111_payload(), opener=opener, now=S3_NOW
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["rule_id"], "100111")
        self.assertEqual(observed["url"], autocontainment.HARDEN_DISPATCH_URL)
        self.assertEqual(observed["timeout"], 30)
        self.assertEqual(
            set(observed["body"]["inputs"]),
            {
                "rule_id",
                "event_id_sha256",
                "alert_body_sha256",
            },
        )
        self.assertNotIn("take_id", observed["body"]["inputs"])
        self.assertNotIn("pod_name", observed["body"]["inputs"])
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_rule100111_rejects_tampering_and_stale_collection(self):
        def never(*_args, **_kwargs):
            self.fail("network must not run for rejected input")

        mutations = (
            lambda value: value.__setitem__("rule_id", "100110"),
            lambda value: value.__setitem__(
                "event_time_utc", "2026-08-21T08:55:29.000Z"
            ),
            lambda value: value.__setitem__("aws_account_id", "433048100798"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                payload = valid_rule100111_payload()
                mutate(payload)
                result = autocontainment.dispatch_rule_100110(
                    TOKEN, payload, opener=never, now=S3_NOW
                )
                self.assertFalse(result["success"])

    def test_rejects_tampering_wrong_tuple_and_extra_keys_before_network(self):
        def never(*_args, **_kwargs):
            self.fail("network must not run for rejected input")

        mutations = (
            lambda value: value["integrity"].__setitem__("body_sha256", "d" * 64),
            lambda value: value["rule"].__setitem__("id", "100111"),
            lambda value: value["incident"].__setitem__("stage", "other"),
            lambda value: value["incident"].__setitem__("route", "/health"),
            lambda value: value["incident"].__setitem__("pod_name", "other-pod"),
            lambda value: value.__setitem__("extra", True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                payload = valid_payload()
                mutate(payload)
                result = autocontainment.dispatch_rule_100110(
                    TOKEN, payload, opener=never, now=NOW
                )
                self.assertFalse(result["success"])

    def test_rejects_stale_future_and_excess_delivery_latency(self):
        def never(*_args, **_kwargs):
            self.fail("network must not run for rejected input")

        for event_time, sent_at in (
            (NOW - timedelta(seconds=181), NOW),
            (NOW + timedelta(milliseconds=1), NOW),
            (NOW - timedelta(seconds=121), NOW),
        ):
            with self.subTest(event_time=event_time, sent_at=sent_at):
                payload = valid_payload()
                payload["incident"]["event_time_utc"] = (
                    event_time.isoformat(timespec="milliseconds").replace("+00:00", "Z")
                )
                payload["sent_at_utc"] = sent_at.isoformat(
                    timespec="milliseconds"
                ).replace("+00:00", "Z")
                payload["integrity"].pop("body_sha256")
                payload["integrity"]["body_sha256"] = hashlib.sha256(
                    autocontainment._canonical(payload)
                ).hexdigest()
                result = autocontainment.dispatch_rule_100110(
                    TOKEN, payload, opener=never, now=NOW
                )
                self.assertFalse(result["success"])

    def test_rejects_broad_oauth_token_before_network(self):
        result = autocontainment.dispatch_rule_100110(
            "gho_" + ("a" * 40),
            valid_payload(),
            opener=lambda *_args, **_kwargs: self.fail("network must not run"),
            now=NOW,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["reason_code"], "github_token")

    def test_http_failure_does_not_echo_secret_or_response(self):
        def opener(request, timeout):
            self.assertEqual(timeout, 30)
            raise urllib.error.HTTPError(
                request.full_url, 403, "Forbidden", {}, io.BytesIO(b"secret body")
            )

        result = autocontainment.dispatch_rule_100110(
            TOKEN, valid_payload(), opener=opener, now=NOW
        )
        encoded = json.dumps(result)
        self.assertEqual(result["reason_code"], "github_http_403")
        self.assertNotIn(TOKEN, encoded)
        self.assertNotIn("secret body", encoded)

    def test_rejects_unexpected_run_reference(self):
        def opener(_request, timeout):
            self.assertEqual(timeout, 30)
            return FakeResponse(
                {
                    "workflow_run_id": 12345,
                    "run_url": "https://example.invalid/run/12345",
                    "html_url": autocontainment.RUN_HTML_PREFIX + "12345",
                }
            )

        result = autocontainment.dispatch_rule_100110(
            TOKEN, valid_payload(), opener=opener, now=NOW
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["reason_code"], "github_run_url")

    def test_api_contract_uses_serialized_string_output(self):
        api = API_PATH.read_text(encoding="utf-8")
        self.assertIn("name: dispatch_rule_100110", api)
        self.assertNotIn("type: object", api)


if __name__ == "__main__":
    unittest.main()
