from __future__ import annotations

import importlib.util
import json
import unittest
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

    def test_accepts_real_sanitizer_output_and_returns_only_branch_fields(self):
        result = VALIDATOR.validate_sanitized_alert(self.valid_payload())
        self.assertTrue(result["valid"])
        self.assertEqual(result["take_id"], TAKE)
        self.assertEqual(result["rule_id"], "100103")
        self.assertEqual(result["scenario_id"], "CAPITAL-ONE")
        self.assertNotIn("incident", result)
        self.assertNotIn("integrity", result)

    def test_string_input_and_duplicate_keys_are_handled_strictly(self):
        payload = self.valid_payload()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.assertTrue(VALIDATOR.validate_sanitized_alert(encoded)["valid"])
        duplicate = encoded[:-1] + ',"schema_version":1}'
        result = VALIDATOR.validate_sanitized_alert(duplicate)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason_code"], "duplicate_json_key")

    def test_rejects_extra_fields_at_every_object_boundary(self):
        mutations = (
            lambda value: value.__setitem__("command", "must-not-return"),
            lambda value: value["rule"].__setitem__("description", "extra"),
            lambda value: value["incident"].__setitem__("source_ip", "extra"),
            lambda value: value["integrity"].__setitem__("token", "extra"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                payload = self.valid_payload()
                mutate(payload)
                result = VALIDATOR.validate_sanitized_alert(payload)
                self.assertFalse(result["valid"])
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

    def test_allowlist_mismatches_remain_structurally_valid(self):
        wrong_account = PAYLOADS.build_payload(TAKE, "account", "wrong-account")
        account_result = VALIDATOR.validate_sanitized_alert(wrong_account)
        self.assertTrue(account_result["valid"])
        self.assertEqual(account_result["aws_account_id"], "000000000000")

        for case in ("wrong-scenario", "wrong-rule", "wrong-take"):
            with self.subTest(case=case):
                result = VALIDATOR.validate_sanitized_alert(
                    PAYLOADS.build_payload(TAKE, case, case)
                )
                self.assertTrue(result["valid"])

    def test_source_has_no_dynamic_code_or_process_execution(self):
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        for forbidden in ("exec(", "eval(", "subprocess", "os.system", "shell=True"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
