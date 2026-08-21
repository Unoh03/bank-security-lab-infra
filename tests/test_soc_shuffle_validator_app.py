from __future__ import annotations

import ast
import importlib.util
import json
import re
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).parents[1]
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
API_PATH = VALIDATOR_PATH.parents[1] / "api.yaml"
PAYLOAD_PATH = ROOT / "observability" / "shuffle" / "soc_gate_b5_payload.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_module("soc_validator", VALIDATOR_PATH)
PAYLOADS = load_module("soc_gate_b5_payload_for_validator", PAYLOAD_PATH)
TAKE = "capital-one-20260818T010000Z-deadbeef"


class SocShuffleValidatorAppTest(unittest.TestCase):
    def valid_payload(self):
        return PAYLOADS.build_payload(TAKE, "validator", "valid")

    def test_accepts_v2_payload_and_returns_event_id_dedupe_metadata(self):
        payload = self.valid_payload()
        original = json.loads(json.dumps(payload))
        result = VALIDATOR.validate_sanitized_alert(payload)
        self.assertTrue(result["valid"])
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["rule_id"], "100104")
        self.assertEqual(result["rule_level"], 12)
        self.assertEqual(result["rule_role"], "high_confidence_s3_access")
        event_id = payload["incident"]["cloudtrail_event_id"]
        self.assertEqual(result["cloudtrail_event_id"], event_id)
        self.assertEqual(
            result["dedupe_key"], f"CAPITAL-ONE:433048100798:{event_id}"
        )
        self.assertFalse(result["active_take_in_payload"])
        self.assertNotIn("incident", result)
        self.assertNotIn("integrity", result)
        self.assertEqual(payload, original)
        self.assertEqual(
            set(result),
            {
                "valid", "rejection", "schema_version", "source_system",
                "sent_at_utc", "account_alias", "aws_account_id", "aws_region",
                "scenario_id", "rule_id", "rule_level", "rule_role",
                "cloudtrail_event_id", "wazuh_alert_id", "event_time_utc",
                "event_source", "event_name", "principal_role_name",
                "principal_session_id_sha256", "bucket_alias", "object_key",
                "result", "raw_message_sha256", "body_sha256", "dedupe_key",
                "active_take_in_payload",
            },
        )

    def test_classifies_exact_datastore_claim_to_a_scalar(self):
        payload = self.valid_payload()
        validation = VALIDATOR.validate_sanitized_alert(payload)
        key = validation["dedupe_key"]
        self.assertEqual(len(key), 61)
        claim = {
            "success": True,
            "keys_existed": [{"key": key, "existed": False}],
        }
        self.assertEqual(
            VALIDATOR.classify_dedupe_claim(claim, key),
            {"valid": True, "existed": False, "reason_code": ""},
        )
        claim["keys_existed"][0]["existed"] = True
        self.assertEqual(
            VALIDATOR.classify_dedupe_claim(json.dumps(claim), key),
            {"valid": True, "existed": True, "reason_code": ""},
        )

    def test_malformed_dedupe_claims_fail_closed_to_safety_scalar(self):
        payload = self.valid_payload()
        key = VALIDATOR.validate_sanitized_alert(payload)["dedupe_key"]
        malformed = (
            {"success": False, "keys_existed": [{"key": key, "existed": False}]},
            {"success": True, "keys_existed": []},
            {"success": True, "keys_existed": [{"key": key, "existed": False}, {"key": key, "existed": True}]},
            {"success": True, "keys_existed": [{"key": key.upper(), "existed": False}]},
            {"success": True, "keys_existed": [{"key": key, "existed": 0}]},
            {"success": True, "keys_existed": [{"key": key, "existed": False}], "extra": "reject"},
            "{\"success\":true,\"keys_existed\":[{\"key\":\"" + key + "\",\"existed\":false},{\"key\":\"" + key + "\",\"existed\":true}]} ",
            '{"success":true,"success":true,"keys_existed":[]}',
            '{"success":NaN,"keys_existed":[]}',
            "[]",
            [],
            None,
            " " * 65537,
        )
        expected = {"valid": False, "existed": True, "reason_code": "dedupe_claim_invalid"}
        for claim in malformed:
            with self.subTest(claim=repr(claim)):
                self.assertEqual(VALIDATOR.classify_dedupe_claim(claim, key), expected)

        self.assertEqual(
            VALIDATOR.classify_dedupe_claim(
                {"success": True, "keys_existed": [{"key": key, "existed": False}]},
                "CAPITAL-ONE:433048100798:123e4567-e89b-12d3-a456-42661417400",
            ),
            expected,
        )
        self.assertEqual(
            VALIDATOR.classify_dedupe_claim(
                {"success": True, "keys_existed": [{"key": key, "existed": False}]},
                key + "x",
            ),
            expected,
        )

    def test_string_input_and_duplicate_keys_are_handled_strictly(self):
        payload = self.valid_payload()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.assertTrue(VALIDATOR.validate_sanitized_alert(encoded)["valid"])
        duplicate = encoded[:-1] + ',"schema_version":2}'
        result = VALIDATOR.validate_sanitized_alert(duplicate)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason_code"], "duplicate_json_key")

    def test_rejects_extra_fields_at_every_object_boundary(self):
        mutations = (
            lambda value: value.__setitem__("command", "must-not-return"),
            lambda value: value.__setitem__("cookie", "must-not-return"),
            lambda value: value["rule"].__setitem__("description", "extra"),
            lambda value: value["incident"].__setitem__("source_ip", "extra"),
            lambda value: value["incident"].__setitem__("full_log", "extra"),
            lambda value: value["integrity"].__setitem__("token", "extra"),
            lambda value: value["incident"].__setitem__("take_id", TAKE),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                payload = self.valid_payload()
                mutate(payload)
                result = VALIDATOR.validate_sanitized_alert(payload)
                self.assertFalse(result["valid"])
                self.assertEqual(result["rejection"], "REJECTED_SCHEMA")
                self.assertNotIn("must-not-return", json.dumps(result))

    def test_rejects_wrong_body_hash_and_invalid_types(self):
        wrong_hash = PAYLOADS.build_payload(TAKE, "hash", "wrong-body-hash")
        self.assertEqual(
            VALIDATOR.validate_sanitized_alert(wrong_hash)["reason_code"],
            "body_sha256_mismatch",
        )
        payload = self.valid_payload()
        payload["rule"]["level"] = True
        result = VALIDATOR.validate_sanitized_alert(payload)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason_code"], "rule_level")

    def test_rejects_uppercase_event_id_and_recursive_json_as_schema(self):
        payload = self.valid_payload()
        payload["incident"]["cloudtrail_event_id"] = (
            payload["incident"]["cloudtrail_event_id"].upper()
        )
        PAYLOADS._refresh_body_hash(payload)
        result = VALIDATOR.validate_sanitized_alert(payload)
        self.assertFalse(result["valid"])
        self.assertEqual(result["rejection"], "REJECTED_SCHEMA")
        self.assertEqual(result["reason_code"], "cloudtrail_event_id")

        with patch.object(VALIDATOR.json, "loads", side_effect=RecursionError):
            result = VALIDATOR.validate_sanitized_alert("{}")
        self.assertFalse(result["valid"])
        self.assertEqual(result["rejection"], "REJECTED_SCHEMA")
        self.assertEqual(result["reason_code"], "invalid_json")

    def test_schema_failures_are_fixed_and_cover_size_types_formats_and_time(self):
        direct_cases = (
            ([], "payload_not_object"),
            ("[]", "payload_not_object"),
            ("{", "invalid_json"),
            ('{"value":NaN}', "non_finite_number"),
            (" " * 65537, "payload_too_large"),
        )
        for value, reason in direct_cases:
            with self.subTest(reason=reason):
                result = VALIDATOR.validate_sanitized_alert(value)
                self.assertEqual(
                    result,
                    {
                        "valid": False,
                        "rejection": "REJECTED_SCHEMA",
                        "reason_code": reason,
                    },
                )

        mutations = (
            ("schema_version", lambda value: value.__setitem__("schema_version", True)),
            ("source_system", lambda value: value.__setitem__("source_system", 1)),
            ("sent_at_utc", lambda value: value.__setitem__("sent_at_utc", "2026-02-30T00:00:00.000Z")),
            ("rule_id", lambda value: value["rule"].__setitem__("id", 100104)),
            ("event_time_utc", lambda value: value["incident"].__setitem__("event_time_utc", "2026-08-18T00:00:00Z")),
            ("principal_role_name", lambda value: value["incident"].__setitem__("principal_role_name", "")),
            ("object_key", lambda value: value["incident"].__setitem__("object_key", "validation/")),
            ("raw_message_sha256", lambda value: value["integrity"].__setitem__("raw_message_sha256", "A" * 64)),
        )
        for reason, mutate in mutations:
            with self.subTest(reason=reason):
                payload = self.valid_payload()
                mutate(payload)
                PAYLOADS._refresh_body_hash(payload)
                result = VALIDATOR.validate_sanitized_alert(payload)
                self.assertEqual(result["rejection"], "REJECTED_SCHEMA")
                self.assertEqual(result["reason_code"], reason)

    def test_rejects_wrong_region_rule_level_and_account_alias(self):
        mutations = (
            ("aws_region", lambda payload: payload.__setitem__("aws_region", "us-east-1")),
            ("rule_level", lambda payload: payload["rule"].__setitem__("level", 11)),
            ("account_alias", lambda payload: payload.__setitem__("account_alias", "other-lab")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                payload = self.valid_payload()
                mutate(payload)
                PAYLOADS._refresh_body_hash(payload)
                result = VALIDATOR.validate_sanitized_alert(payload)
                self.assertFalse(result["valid"])
                self.assertEqual(result["rejection"], "REJECTED_ALLOWLIST")
                self.assertNotIn("dedupe_key", result)

    def test_control_take_id_does_not_change_cloudtrail_payload(self):
        first = PAYLOADS.build_payload("take-a", "same-nonce", "valid")
        second = PAYLOADS.build_payload("take-b", "same-nonce", "valid")
        self.assertEqual(first, second)
        self.assertNotIn("take_id", first["incident"])

    def test_fixed_allowlist_mismatches_are_rejected_without_side_effect_metadata(self):
        for case in (
            "wrong-account",
            "wrong-scenario",
            "wrong-rule",
            "wrong-role",
            "wrong-bucket",
            "wrong-key",
            "wrong-event-source",
            "wrong-event-name",
            "wrong-result",
        ):
            with self.subTest(case=case):
                result = VALIDATOR.validate_sanitized_alert(
                    PAYLOADS.build_payload(TAKE, case, case)
                )
                self.assertFalse(result["valid"])
                self.assertEqual(result["rejection"], "REJECTED_ALLOWLIST")
                self.assertNotIn("dedupe_key", result)

    def test_source_has_no_dynamic_code_or_process_execution(self):
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        for forbidden in ("exec(", "eval(", "subprocess", "os.system", "shell=True"):
            self.assertNotIn(forbidden, source)

    def test_source_is_cloud_minimal_stdlib_logic(self):
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        self.assertLess(len(source.encode("utf-8")), 8700)
        for forbidden in (
            "from __future__",
            "from typing",
            "import typing",
            "import hmac",
            "dataclass",
            "class ValidationError",
            "class AllowlistError",
        ):
            self.assertNotIn(forbidden, source)
        tree = ast.parse(source)
        imported = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for name in node.names:
                    imported.add(name.name)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(imported, {"hashlib", "json", "re", "datetime"})
        self.assertFalse(
            any(
                isinstance(
                    node,
                    (ast.ClassDef, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
                )
                for node in ast.walk(tree)
            )
        )

    def test_shuffle_api_contract_uses_serialized_string_io(self):
        api = API_PATH.read_text(encoding="utf-8")
        self.assertIn("name: validate_sanitized_alert", api)
        self.assertIn("name: classify_dedupe_claim", api)
        self.assertIn("set_datastore_value", api)
        self.assertIn("sanitized CloudTrail S3 alert v2", api)
        self.assertNotIn("type: object", api)

    def test_api_actions_match_appbase_methods_and_parameter_order(self):
        api_lines = API_PATH.read_text(encoding="utf-8").splitlines()
        api_actions: list[tuple[str, tuple[str, ...]]] = []
        current_name: str | None = None
        current_parameters: list[str] = []
        for line in api_lines:
            action_match = re.fullmatch(r"  - name: ([A-Za-z0-9_]+)", line)
            if action_match:
                if current_name is not None:
                    api_actions.append((current_name, tuple(current_parameters)))
                current_name = action_match.group(1)
                current_parameters = []
                continue
            if current_name is not None:
                parameter_match = re.fullmatch(
                    r"      - name: ([A-Za-z0-9_]+)", line
                )
                if parameter_match:
                    current_parameters.append(parameter_match.group(1))
        if current_name is not None:
            api_actions.append((current_name, tuple(current_parameters)))

        app_tree = ast.parse(
            (VALIDATOR_PATH.parent / "app.py").read_text(encoding="utf-8")
        )
        app_classes = [
            node
            for node in app_tree.body
            if isinstance(node, ast.ClassDef)
            and any(
                isinstance(base, ast.Name) and base.id == "AppBase"
                for base in node.bases
            )
        ]
        self.assertEqual(len(app_classes), 1)
        methods = {
            node.name: node
            for node in app_classes[0].body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        normalized_actions = [
            (str(name), tuple(str(parameter) for parameter in parameters))
            for name, parameters in api_actions
        ]
        self.assertEqual(
            list(methods), [name for name, _parameters in normalized_actions]
        )
        for name, expected_parameters in normalized_actions:
            method = methods[name]
            self.assertGreaterEqual(len(method.args.args), 1)
            actual_parameters = tuple(
                argument.arg for argument in method.args.args[1:]
            )
            self.assertEqual(actual_parameters, expected_parameters, name)


if __name__ == "__main__":
    unittest.main()
