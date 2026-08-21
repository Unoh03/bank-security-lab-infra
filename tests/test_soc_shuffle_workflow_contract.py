from __future__ import annotations

import json
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
CONTRACT_PATH = (
    ROOT / "observability" / "shuffle" / "shuffle-soc-workflow-contract.json"
)
SCHEMA_PATH = ROOT / "observability" / "shuffle" / "sanitized-alert.schema.json"
VALIDATOR_API_PATH = (
    ROOT
    / "observability"
    / "shuffle"
    / "apps"
    / "aws-topology-soc-validator"
    / "1.0.0"
    / "api.yaml"
)
PAYLOAD_PATH = ROOT / "observability" / "shuffle" / "soc_gate_b5_payload.py"
PAYLOAD_SPEC = importlib.util.spec_from_file_location("soc_gate_b5_payload", PAYLOAD_PATH)
assert PAYLOAD_SPEC is not None and PAYLOAD_SPEC.loader is not None
PAYLOAD = importlib.util.module_from_spec(PAYLOAD_SPEC)
PAYLOAD_SPEC.loader.exec_module(PAYLOAD)


class ShuffleWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_is_a_v2_review_contract_not_an_unverified_import(self) -> None:
        self.assertEqual(self.contract["schema_version"], 2)
        self.assertEqual(
            self.contract["artifact_kind"], "shuffle-soc-workflow-contract"
        )
        self.assertIs(self.contract["importable_shuffle_workflow"], False)
        self.assertEqual(
            self.contract["workflow"]["name"], "CAPITAL-ONE-SOC-CONTAINMENT-v2"
        )
        self.assertEqual(self.contract["workflow"]["sharing"], "private")

    def test_v2_allowlist_and_take_binding_are_explicit(self) -> None:
        allow = self.contract["input_contract"]["allowlist"]
        self.assertEqual(allow["rule_id"], "100104")
        self.assertEqual(allow["rule_level"], 12)
        self.assertEqual(allow["rule_role"], "high_confidence_s3_access")
        self.assertEqual(allow["event_source"], "s3.amazonaws.com")
        self.assertEqual(allow["event_name"], "GetObject")
        self.assertFalse(
            self.contract["input_contract"]["take_binding"][
                "required_in_alert_payload"
            ]
        )
        self.assertFalse(self.contract["gate_b5"]["active_take_in_payload"])

    def test_schema_has_exact_v2_incident_shape(self) -> None:
        self.assertEqual(self.schema["properties"]["schema_version"]["const"], 2)
        self.assertEqual(
            self.schema["properties"]["rule"]["required"],
            ["id", "level", "role"],
        )
        incident = self.schema["properties"]["incident"]
        self.assertEqual(
            set(incident["required"]),
            {
                "cloudtrail_event_id",
                "wazuh_alert_id",
                "event_time_utc",
                "event_source",
                "event_name",
                "principal_role_name",
                "principal_session_id_sha256",
                "bucket_alias",
                "object_key",
                "result",
            },
        )
        self.assertNotIn("take_id", incident["properties"])
        self.assertNotIn("event_id", incident["properties"])
        self.assertNotIn("route", incident["properties"])

    def test_covers_v2_result_branches_without_implicit_external_write(self) -> None:
        outcomes = [branch["result"] for branch in self.contract["branches"]]
        self.assertEqual(
            set(outcomes),
            {
                "REJECTED_SCHEMA",
                "REJECTED_ALLOWLIST",
                "OBSERVE_ONLY",
                "DUPLICATE_SUPPRESSED",
                "SAFETY_GATE_BLOCKED",
                "CONTAINMENT_SUCCEEDED",
                "CONTAINMENT_FAILED",
            },
        )
        observe = next(
            branch for branch in self.contract["branches"] if branch["result"] == "OBSERVE_ONLY"
        )
        self.assertEqual(observe["dedupe_claim"], 0)
        self.assertEqual(observe["external_action_count"], 0)
        blocked = next(
            branch
            for branch in self.contract["branches"]
            if branch["result"] == "SAFETY_GATE_BLOCKED"
        )
        self.assertEqual(blocked["external_action_count"], 0)

    def test_gate_b5_is_side_effect_free_and_event_id_based(self) -> None:
        gate = self.contract["gate_b5"]
        self.assertEqual(gate["dispatch_action_stage"], "stub")
        self.assertEqual(gate["stub"]["app"], "Shuffle Tools")
        self.assertEqual(gate["stub"]["action"], "repeat_back_to_me")
        self.assertEqual(gate["same_exact_body_concurrency"], 10)
        self.assertEqual(gate["expected_new_claim_count"], 1)
        self.assertEqual(gate["expected_duplicate_claim_count"], 9)
        self.assertEqual(gate["expected_external_action_count"], 0)
        self.assertEqual(gate["expected_real_github_dispatch_count"], 0)
        self.assertFalse(gate["observe_only_consumes_containment_dedupe"])
        self.assertEqual(
            self.contract["datastore"]["dedupe_key"],
            "CAPITAL-ONE:<aws_account_id>:<cloudtrail_event_id>",
        )

    def test_gate_b5_action_labels_and_branches_are_unique_and_exact(self) -> None:
        gate = self.contract["gate_b5"]
        labels = gate["action_labels_exact"]
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(
            labels,
            [
                "validate_payload",
                "claim_event_dedupe",
                "classify_dedupe_claim",
                "write_duplicate_suppressed",
                "write_observe_only",
                "write_rejected_schema",
                "write_rejected_allowlist",
                "write_safety_gate_blocked",
                "repeat_back_to_me",
            ],
        )
        self.assertEqual(len(gate["forbidden_action_labels"]), len(set(gate["forbidden_action_labels"])))
        self.assertTrue(set(labels).isdisjoint(gate["forbidden_action_labels"]))
        branches = self.contract["branches"]
        whens = [branch["when"] for branch in branches]
        results = [branch["result"] for branch in branches]
        self.assertEqual(len(whens), len(set(whens)))
        self.assertEqual(len(results), len(set(results)))
        self.assertTrue(all("external_action_count" in branch for branch in branches))

    def test_gate_b5_stub_and_ingress_contract_are_exact(self) -> None:
        stub = self.contract["gate_b5"]["stub"]
        self.assertEqual(stub["label"], "repeat_back_to_me")
        self.assertEqual(stub["app"], "Shuffle Tools")
        self.assertEqual(stub["action"], "repeat_back_to_me")
        self.assertEqual(stub["fixed_marker"], "GATE_B5_REPEAT_STUB")
        ingress = self.contract["gate_b5"]["webhook_ingress_smoke"]
        self.assertEqual(ingress, {"valid_required_header": "accepted", "invalid_required_header": "rejected"})
        self.assertEqual(self.contract["gate_b5"]["expected_external_action_count"], 0)

    def test_gate_b5_safe_action_mapping_and_dedupe_branch_are_exact(self) -> None:
        gate = self.contract["gate_b5"]
        mapping = gate["safe_action_mapping"]
        claim = mapping["claim_event_dedupe"]
        self.assertEqual(
            claim,
            {
                "app": "Shuffle Tools",
                "app_version": "1.2.0",
                "action": "set_datastore_value",
                "parameters": {
                    "category": "soc-v2",
                    "key": "$validate_payload.dedupe_key",
                    "value": "$validate_payload.body_sha256",
                },
            },
        )
        self.assertEqual(
            mapping["classify_dedupe_claim"],
            {
                "app": "AWS Topology SOC Validator",
                "app_version": "1.0.0",
                "action": "classify_dedupe_claim",
                "parameters": {
                    "claim_result": "$claim_event_dedupe",
                    "expected_key": "$validate_payload.dedupe_key",
                },
            },
        )
        for label in (
            "write_duplicate_suppressed",
            "write_observe_only",
            "write_rejected_schema",
            "write_rejected_allowlist",
            "write_safety_gate_blocked",
        ):
            self.assertEqual(mapping[label]["app"], "Shuffle Tools")
            self.assertEqual(mapping[label]["app_version"], "1.2.0")
            self.assertEqual(mapping[label]["action"], "repeat_back_to_me")
            self.assertEqual(mapping[label]["parameters"], {"call": label})
        self.assertEqual(
            gate["dedupe_branch_condition"],
            {
                "source": "$classify_dedupe_claim.existed",
                "operator": "equals",
                "value": False,
            },
        )
        self.assertEqual(len(gate["branch_graph"]), 8)
        expected_graph = [
            ("__WEBHOOK_TRIGGER__", "validate_payload", ()),
            ("validate_payload", "claim_event_dedupe", (("$validate_payload.valid", "true"),)),
            ("validate_payload", "write_rejected_schema", (("$validate_payload.rejection", "REJECTED_SCHEMA"),)),
            ("validate_payload", "write_rejected_allowlist", (("$validate_payload.rejection", "REJECTED_ALLOWLIST"),)),
            ("claim_event_dedupe", "classify_dedupe_claim", ()),
            ("classify_dedupe_claim", "write_safety_gate_blocked", (("$classify_dedupe_claim.valid", "false"),)),
            (
                "classify_dedupe_claim",
                "repeat_back_to_me",
                (("$classify_dedupe_claim.valid", "true"), ("$classify_dedupe_claim.existed", "false")),
            ),
            (
                "classify_dedupe_claim",
                "write_duplicate_suppressed",
                (("$classify_dedupe_claim.valid", "true"), ("$classify_dedupe_claim.existed", "true")),
            ),
        ]

        def normalize_branch(branch: dict[str, object]) -> tuple[object, object, tuple[tuple[object, object], ...]]:
            if "conditions" in branch:
                conditions = tuple(
                    (condition["condition_source"], condition["condition_destination"])
                    for condition in branch["conditions"]
                )
            elif "condition_source" in branch:
                conditions = ((branch["condition_source"], branch["condition_destination"]),)
            else:
                conditions = ()
            return branch["source_label"], branch["destination_label"], conditions

        actual_graph = [normalize_branch(branch) for branch in gate["branch_graph"]]
        self.assertEqual(actual_graph, expected_graph)
        self.assertEqual(len(actual_graph), len(set(actual_graph)))
        condition_shape = gate["condition_shape"]
        self.assertEqual(set(condition_shape), {"source", "condition", "destination"})
        self.assertEqual(condition_shape["source"]["id"], "<uuid>")
        self.assertEqual(condition_shape["source"]["name"], "source")
        self.assertEqual(condition_shape["source"]["variant"], "STATIC_VALUE")
        self.assertEqual(condition_shape["condition"], {"id": "<uuid>", "name": "condition", "value": "equals"})
        self.assertEqual(condition_shape["destination"]["id"], "<uuid>")
        self.assertEqual(condition_shape["destination"]["name"], "destination")
        self.assertEqual(condition_shape["destination"]["variant"], "STATIC_VALUE")

    def test_generator_cases_and_contract_allowlist_are_cross_checked(self) -> None:
        self.assertEqual(
            set(self.contract["gate_b5"]["negative_cases"]),
            set(PAYLOAD.CASES) - {"valid"},
        )
        payload = PAYLOAD.build_payload("control-only", "contract-test", "valid")
        allow = self.contract["input_contract"]["allowlist"]
        self.assertEqual(
            {
                "account_alias": payload["account_alias"],
                "aws_account_id": payload["aws_account_id"],
                "aws_region": payload["aws_region"],
                "scenario_id": payload["scenario_id"],
                "rule_id": payload["rule"]["id"],
                "rule_level": payload["rule"]["level"],
                "rule_role": payload["rule"]["role"],
                "source_system": payload["source_system"],
                "event_source": payload["incident"]["event_source"],
                "event_name": payload["incident"]["event_name"],
                "principal_role_name": payload["incident"]["principal_role_name"],
                "bucket_alias": payload["incident"]["bucket_alias"],
                "object_key": payload["incident"]["object_key"],
                "result": payload["incident"]["result"],
            },
            allow,
        )

    def test_gt09_remediation_is_explicitly_outside_this_contract(self) -> None:
        self.assertEqual(self.contract["containment_targets"]["gt09"]["status"], "out_of_scope")
        self.assertIn(
            "low-to-impossible",
            self.contract["containment_targets"]["gt09"]["description"],
        )
        self.assertEqual(
            self.contract["production_only_action_labels"],
            ["quarantine_fixed_dvwa", "restrict_validation_prefix"],
        )

    def test_contract_contains_no_secret_value(self) -> None:
        encoded = CONTRACT_PATH.read_text(encoding="utf-8").lower()
        for marker in (
            "ghp_",
            "github_pat=",
            "api_key=",
            "bearer ",
            "x-soc-webhook-key:",
            "aws_secret_access_key",
        ):
            self.assertNotIn(marker, encoded)

    def test_validator_api_describes_v2_string_io(self) -> None:
        api = VALIDATOR_API_PATH.read_text(encoding="utf-8")
        self.assertIn("sanitized CloudTrail S3 alert v2", api)
        self.assertIn("without returning the original payload", api)
        self.assertNotIn("type: object", api)


if __name__ == "__main__":
    unittest.main()
