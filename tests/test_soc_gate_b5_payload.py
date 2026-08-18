#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


PATH = Path(__file__).parents[1] / "observability" / "shuffle" / "soc_gate_b5_payload.py"
SPEC = importlib.util.spec_from_file_location("soc_gate_b5_payload", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TAKE = "capital-one-20260818T010000Z-deadbeef"


class SocGateB5PayloadTest(unittest.TestCase):
    def test_valid_case_is_real_sanitizer_output(self) -> None:
        payload = MODULE.build_payload(TAKE, "same-payload", "valid")
        self.assertEqual(payload["incident"]["take_id"], TAKE)
        self.assertEqual(payload["rule"], {"id": "100103", "level": 10})
        body_hash = payload["integrity"].pop("body_sha256")
        self.assertEqual(
            body_hash,
            MODULE.hashlib.sha256(MODULE.SANITIZER.canonical_json(payload)).hexdigest(),
        )

    def test_allowlist_mutations_keep_a_valid_integrity_hash(self) -> None:
        expected = {
            "wrong-account": ("aws_account_id", "000000000000"),
            "wrong-scenario": ("scenario_id", "OTHER-SCENARIO"),
        }
        for case, (field, value) in expected.items():
            with self.subTest(case=case):
                payload = MODULE.build_payload(TAKE, case, case)
                self.assertEqual(payload[field], value)
                if case == "wrong-account":
                    self.assertTrue(
                        payload["incident"]["event_id"].startswith(
                            "cwl:000000000000:"
                        )
                    )
                body_hash = payload["integrity"].pop("body_sha256")
                self.assertEqual(
                    body_hash,
                    MODULE.hashlib.sha256(
                        MODULE.SANITIZER.canonical_json(payload)
                    ).hexdigest(),
                )

    def test_rule_take_and_hash_negative_cases_are_distinct(self) -> None:
        wrong_rule = MODULE.build_payload(TAKE, "rule", "wrong-rule")
        wrong_take = MODULE.build_payload(TAKE, "take", "wrong-take")
        wrong_hash = MODULE.build_payload(TAKE, "hash", "wrong-body-hash")
        self.assertEqual(wrong_rule["rule"]["id"], "999999")
        self.assertNotEqual(wrong_take["incident"]["take_id"], TAKE)
        self.assertRegex(
            wrong_take["incident"]["take_id"],
            MODULE.SANITIZER.TAKE_ID_PATTERN,
        )
        self.assertEqual(wrong_hash["integrity"]["body_sha256"], "0" * 64)

    def test_payload_never_contains_forbidden_source_fields(self) -> None:
        text = MODULE.json.dumps(MODULE.build_payload(TAKE, "safe"), sort_keys=True)
        for forbidden in ("full_log", "source_ip", "user_id", "command", "cookie", "token"):
            self.assertNotIn(forbidden, text.lower())


if __name__ == "__main__":
    unittest.main()
