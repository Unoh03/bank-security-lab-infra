from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
CONTRACT_PATH = (
    ROOT / "observability" / "shuffle" / "shuffle-soc-workflow-contract.json"
)
SCHEMA_PATH = ROOT / "observability" / "shuffle" / "sanitized-alert.schema.json"
VALIDATOR_ROOT = (
    ROOT
    / "observability"
    / "shuffle"
    / "apps"
    / "aws-topology-soc-validator"
    / "1.0.0"
)
DISPATCHER_ROOT = (
    ROOT
    / "observability"
    / "shuffle"
    / "apps"
    / "aws-topology-soc-github-dispatcher"
    / "1.0.0"
)
DISPATCHER_MODULE_PATH = DISPATCHER_ROOT / "src" / "dispatcher.py"
DISPATCHER_SPEC = importlib.util.spec_from_file_location(
    "soc_contract_dispatcher", DISPATCHER_MODULE_PATH
)
dispatcher = importlib.util.module_from_spec(DISPATCHER_SPEC)
assert DISPATCHER_SPEC.loader is not None
sys.modules[DISPATCHER_SPEC.name] = dispatcher
DISPATCHER_SPEC.loader.exec_module(dispatcher)


class ShuffleWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_is_a_review_contract_not_an_unverified_import(self) -> None:
        self.assertEqual(self.contract["schema_version"], 1)
        self.assertEqual(
            self.contract["artifact_kind"], "shuffle-soc-workflow-contract"
        )
        self.assertIs(self.contract["importable_shuffle_workflow"], False)
        self.assertEqual(
            self.contract["workflow"]["name"],
            "CAPITAL-ONE-SOC-CONTAINMENT-v1",
        )
        self.assertEqual(self.contract["workflow"]["sharing"], "private")

    def test_covers_every_frozen_result_branch_once(self) -> None:
        outcomes = [branch["result"] for branch in self.contract["branches"]]
        self.assertEqual(
            set(outcomes),
            {
                "REJECTED_SCHEMA",
                "REJECTED_ALLOWLIST",
                "REJECTED_TAKE",
                "OBSERVE_ONLY",
                "DUPLICATE_SUPPRESSED",
                "RESPONSE_DISPATCHED",
                "RESPONSE_FAILED",
            },
        )
        self.assertEqual(len(outcomes), len(set(outcomes)))
        failed = next(
            branch
            for branch in self.contract["branches"]
            if branch["result"] == "RESPONSE_FAILED"
        )
        self.assertEqual(failed["github_dispatch_count"], 0)
        self.assertEqual(
            failed["dispatch_acceptance"],
            "unverified_no_automatic_retry",
        )

    def test_gate_b5_cannot_dispatch_real_github(self) -> None:
        gate = self.contract["gate_b5"]
        self.assertEqual(gate["dispatch_action_stage"], "stub")
        self.assertEqual(gate["stress_transport"], "authenticated_execute_api")
        self.assertEqual(
            gate["webhook_ingress_smoke"],
            {
                "valid_required_header": "accepted",
                "invalid_required_header": "rejected",
            },
        )
        self.assertEqual(gate["stub"]["app"], "Shuffle Tools")
        self.assertEqual(gate["stub"]["action"], "repeat_back_to_me")
        self.assertEqual(gate["same_exact_body_concurrency"], 10)
        self.assertEqual(gate["expected_new_claim_count"], 1)
        self.assertEqual(gate["expected_duplicate_claim_count"], 9)
        self.assertEqual(gate["expected_stub_execution_count"], 1)
        self.assertEqual(gate["expected_real_github_dispatch_count"], 0)
        self.assertIs(gate["atomicity_claim_allowed_only_after_runtime_stress"], True)

    def test_production_target_and_inputs_are_fixed(self) -> None:
        dispatch = self.contract["production_dispatch"]
        self.assertEqual(dispatch["repository"], "Unoh03/Uns-DVWA")
        self.assertEqual(
            dispatch["workflow"], ".github/workflows/soc-contain-dvwa.yml"
        )
        self.assertEqual(dispatch["ref"], "main")
        self.assertIs(dispatch["return_run_details"], True)
        self.assertEqual(
            dispatch["dispatch_response"],
            "github-api-2026-03-10-returns-workflow-run-id-and-urls",
        )
        self.assertEqual(dispatch["github_api_version"], "2026-03-10")
        self.assertEqual(dispatch["app"], "AWS Topology SOC GitHub Dispatcher")
        self.assertEqual(dispatch["app_version"], "1.0.0")
        self.assertEqual(dispatch["action"], "dispatch_containment")
        self.assertIs(dispatch["private_org_app"], True)
        self.assertEqual(
            dispatch["fixed_url_in_app_source"],
            "https://api.github.com/repos/Unoh03/Uns-DVWA/actions/"
            "workflows/soc-contain-dvwa.yml/dispatches",
        )
        self.assertEqual(
            dispatch["inputs"],
            ["take_id", "scenario_id", "rule_id", "alert_body_sha256"],
        )
        self.assertEqual(dispatcher.REPOSITORY, dispatch["repository"])
        self.assertEqual(dispatcher.WORKFLOW, Path(dispatch["workflow"]).name)
        self.assertEqual(dispatcher.REF, dispatch["ref"])
        self.assertEqual(dispatcher.API_VERSION, dispatch["github_api_version"])
        self.assertEqual(dispatcher.DISPATCH_URL, dispatch["fixed_url_in_app_source"])
        self.assertIn("repository", dispatch["forbidden_dynamic_inputs"])
        self.assertIn("shell_command", dispatch["forbidden_dynamic_inputs"])
        self.assertEqual(self.contract["production_only_action_labels"], [])
        self.assertIs(dispatch["result"]["secret_or_raw_response_returned"], False)
        for relative in (
            "api.yaml",
            "Dockerfile",
            "requirements.txt",
            "src/app.py",
            "src/dispatcher.py",
        ):
            self.assertTrue((DISPATCHER_ROOT / relative).is_file(), relative)

    def test_validator_is_a_versioned_private_app_not_execute_python(self) -> None:
        validator = self.contract["input_contract"]["validator_app"]
        self.assertEqual(validator["name"], "AWS Topology SOC Validator")
        self.assertEqual(validator["version"], "1.0.0")
        self.assertEqual(validator["action"], "validate_sanitized_alert")
        self.assertEqual(validator["input"], "$exec")
        self.assertIs(validator["private_org_app"], True)
        self.assertEqual(
            validator["forbidden_replacement"], "Shuffle Tools execute_python"
        )
        for relative in (
            "api.yaml",
            "Dockerfile",
            "requirements.txt",
            "src/app.py",
            "src/validator.py",
        ):
            self.assertTrue((VALIDATOR_ROOT / relative).is_file(), relative)

    def test_schema_separates_shape_from_the_fixed_allowlist(self) -> None:
        allow = self.contract["input_contract"]["allowlist"]
        properties = self.schema["properties"]
        for name in ("account_alias", "aws_account_id", "aws_region", "scenario_id"):
            self.assertNotIn("const", properties[name])
            self.assertRegex(allow[name], properties[name]["pattern"])
        rule_properties = properties["rule"]["properties"]
        self.assertNotIn("const", rule_properties["id"])
        self.assertRegex(allow["rule_id"], rule_properties["id"]["pattern"])
        self.assertGreaterEqual(allow["rule_level"], rule_properties["level"]["minimum"])
        self.assertLessEqual(allow["rule_level"], rule_properties["level"]["maximum"])

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


if __name__ == "__main__":
    unittest.main()
