#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


PATH = Path(__file__).parents[1] / "observability" / "shuffle" / "soc_gate_b5_payload.py"
CONTRACT_PATH = (
    Path(__file__).parents[1]
    / "observability"
    / "shuffle"
    / "shuffle-soc-workflow-contract.json"
)
SPEC = importlib.util.spec_from_file_location("soc_gate_b5_payload", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TAKE = "capital-one-20260818T010000Z-deadbeef"
CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


class SocGateB5PayloadTest(unittest.TestCase):
    def test_cases_and_mutation_table_are_exact(self) -> None:
        expected = {
            "valid",
            "wrong-account",
            "wrong-scenario",
            "wrong-rule",
            "wrong-role",
            "wrong-bucket",
            "wrong-key",
            "wrong-event-source",
            "wrong-event-name",
            "wrong-result",
            "wrong-body-hash",
        }
        self.assertEqual(set(MODULE.CASES), expected)
        self.assertEqual(set(MODULE.CASE_MUTATIONS), expected)

    def test_valid_case_is_v2_and_never_contains_take_id(self) -> None:
        payload = MODULE.build_payload(TAKE, "same-payload", "valid")
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(
            payload["rule"],
            {"id": "100104", "level": 12, "role": "high_confidence_s3_access"},
        )
        self.assertNotIn("take_id", payload)
        self.assertNotIn("event_id", payload["incident"])
        self.assertIn("cloudtrail_event_id", payload["incident"])
        body_hash = payload["integrity"].pop("body_sha256")
        self.assertEqual(
            body_hash,
            MODULE.hashlib.sha256(MODULE.canonical_json(payload)).hexdigest(),
        )

    def test_valid_generator_matches_contract_allowlist_exactly(self) -> None:
        payload = MODULE.build_payload("control-a", "contract-payload", "valid")
        allow = CONTRACT["input_contract"]["allowlist"]
        self.assertEqual(payload["account_alias"], allow["account_alias"])
        self.assertEqual(payload["aws_account_id"], allow["aws_account_id"])
        self.assertEqual(payload["aws_region"], allow["aws_region"])
        self.assertEqual(payload["scenario_id"], allow["scenario_id"])
        self.assertEqual(payload["source_system"], allow["source_system"])
        self.assertEqual(payload["rule"]["id"], allow["rule_id"])
        self.assertEqual(payload["rule"]["level"], allow["rule_level"])
        self.assertEqual(payload["rule"]["role"], allow["rule_role"])
        for field in (
            "event_source",
            "event_name",
            "principal_role_name",
            "bucket_alias",
            "object_key",
            "result",
        ):
            self.assertEqual(payload["incident"][field], allow[field])

    def test_control_identifier_never_changes_cloudtrail_payload(self) -> None:
        first = MODULE.build_payload("control-a", "same-event", "valid")
        second = MODULE.build_payload("control-b", "same-event", "valid")
        self.assertEqual(first, second)
        self.assertNotIn("take_id", MODULE.json.dumps(first))

    def test_allowlist_mutations_keep_a_valid_integrity_hash(self) -> None:
        cases = (
            "wrong-account",
            "wrong-scenario",
            "wrong-role",
            "wrong-bucket",
            "wrong-key",
            "wrong-event-source",
            "wrong-event-name",
            "wrong-result",
        )
        for case in cases:
            with self.subTest(case=case):
                payload = MODULE.build_payload(TAKE, case, case)
                body_hash = payload["integrity"].pop("body_sha256")
                self.assertEqual(
                    body_hash,
                    MODULE.hashlib.sha256(MODULE.canonical_json(payload)).hexdigest(),
                )

    def test_each_negative_case_matches_its_declared_mutation(self) -> None:
        def read_path(value: dict, path: str):
            current = value
            for part in path.split("."):
                current = current[part]
            return current

        for case, mutation in MODULE.CASE_MUTATIONS.items():
            if case == "valid":
                continue
            with self.subTest(case=case):
                path, expected = mutation
                payload = MODULE.build_payload(TAKE, f"mutation-{case}", case)
                self.assertEqual(read_path(payload, path), expected)
                baseline = MODULE.build_payload(TAKE, f"mutation-{case}", "valid")
                self.assertNotEqual(payload, baseline)

    def test_rule_and_hash_negative_cases_are_distinct(self) -> None:
        wrong_rule = MODULE.build_payload(TAKE, "rule", "wrong-rule")
        wrong_hash = MODULE.build_payload(TAKE, "hash", "wrong-body-hash")
        self.assertEqual(wrong_rule["rule"]["id"], "100999")
        self.assertEqual(wrong_hash["integrity"]["body_sha256"], "0" * 64)
        self.assertNotEqual(
            wrong_rule["incident"]["cloudtrail_event_id"],
            wrong_hash["incident"]["cloudtrail_event_id"],
        )

    def test_payload_never_contains_forbidden_source_fields(self) -> None:
        text = MODULE.json.dumps(MODULE.build_payload(TAKE, "safe"), sort_keys=True)
        for forbidden in (
            '"take_id"',
            '"event_id"',
            "soc:v1",
            "full_log",
            "source_ip",
            "user_id",
            "command",
            "cookie",
            "token",
        ):
            self.assertNotIn(forbidden, text.lower())


if __name__ == "__main__":
    unittest.main()
