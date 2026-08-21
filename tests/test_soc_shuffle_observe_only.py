import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import unittest
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "soc_shuffle_observe_only.py"
SPEC = importlib.util.spec_from_file_location("soc_shuffle_observe_only", MODULE_PATH)
M = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


ORG = "11111111-1111-4111-8111-111111111111"
WORKFLOW = "22222222-2222-4222-8222-222222222222"
WEBHOOK = "33333333-3333-4333-8333-333333333333"
ACTION = "44444444-4444-4444-8444-444444444444"
BRANCH = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EXECUTION = "55555555-5555-4555-8555-555555555555"
AUTHORIZATION = "66666666-6666-4666-8666-666666666666"
HEADER_SECRET = "header-secret-value-never-persist"
API_SECRET = "api-secret-value-never-persist"
WEBHOOK_URI = f"https://shuffler.io/api/v1/hooks/{WEBHOOK}"
FIXED_NOW = datetime(2026, 8, 18, 1, 2, 3, tzinfo=timezone.utc)


@contextmanager
def workspace_tempdir():
    """Avoid tempfile's Windows chmod, which breaks managed-workspace ACLs."""
    path = ROOT / f".soc-shuffle-test-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield str(path)
    finally:
        shutil.rmtree(path)


def config():
    return M.Configuration("https://shuffler.io", ORG, WORKFLOW, WEBHOOK)


def workflow(call="before", *, label="repeat_back_to_me"):
    return {
        "id": WORKFLOW,
        "name": "OBSERVE_ONLY",
        "sharing": "private",
        "is_valid": True,
        "triggers": [
            {
                "id": WEBHOOK,
                "trigger_type": "WEBHOOK",
                "status": "RUNNING",
                "parameters": [
                    {"name": "auth_headers", "value": f"{M.HEADER_NAME}={HEADER_SECRET}"}
                ],
            }
        ],
        "actions": [
            {
                "id": ACTION,
                "label": label,
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "name": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": call}],
                "position": {"x": 10, "y": 20},
            }
        ],
        "branches": [
            {"id": BRANCH, "source_id": WEBHOOK, "destination_id": ACTION, "conditions": []}
        ],
        "description": "preserved full object",
    }


def add_allowed_server_metadata(value, marker="server-managed"):
    value["edited"] = marker
    value["suborg_distribution"] = [{"marker": marker}]
    value["validation"] = {
        "changed_at": marker,
        "execution_id": marker,
        "last_valid": marker,
    }


class FakeSecrets:
    def __init__(
        self,
        root: Path,
        original=None,
        *,
        corrupt_roundtrip=False,
    ):
        self.secret_root = root
        self.values = {
            M.API_KEY_NAME: API_SECRET,
            M.WEBHOOK_URI_NAME: WEBHOOK_URI,
            M.WEBHOOK_HEADER_NAME: HEADER_SECRET,
        }
        self.original = original
        self.corrupt_roundtrip = corrupt_roundtrip

    def record_path(self, name):
        return self.secret_root / f"{name}.dpapi.json"

    def protect_new(self, name, plaintext):
        self.original = json.loads(plaintext)
        self.values[name] = "{}" if self.corrupt_roundtrip else plaintext
        path = self.record_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"protected":"opaque-ciphertext"}', encoding="utf-8")
        return path

    def unprotect(self, name):
        if name in self.values:
            return self.values[name]
        if self.original is not None:
            return M.canonical_bytes(self.original).decode()
        raise AssertionError(name)


class ScriptedHttp:
    def __init__(self, current):
        self.current = copy.deepcopy(current)
        self.calls = []
        self.fail_readback = False
        self.fail_first_put = False
        self._put_count = 0
        self._get_count = 0
        self.server_metadata_change = False
        self.semantic_drift = False

    def api(self, method, path, api_key, org_id, body=None, **_kwargs):
        self.calls.append((method, path, copy.deepcopy(body)))
        self.assert_headers(api_key, org_id)
        if path.endswith("/executions?top=100"):
            return {"success": True, "executions": []}
        if method == "GET":
            self._get_count += 1
            if self.fail_readback and self._get_count == 2:
                bad = copy.deepcopy(self.current)
                bad["actions"].append({"name": "Dispatcher"})
                return bad
            result = copy.deepcopy(self.current)
            if self._put_count >= 1 and self.server_metadata_change:
                add_allowed_server_metadata(result, f"server-managed-{self._put_count}")
            if self._get_count == 2 and self.semantic_drift:
                result["actions"][0]["app_version"] = "9.9.9"
            return result
        if method == "PUT":
            self._put_count += 1
            if self.fail_first_put and self._put_count == 1:
                raise M.Refusal("simulated ambiguous PUT failure")
            self.current = copy.deepcopy(body)
            return {"success": True}
        raise AssertionError((method, path))

    @staticmethod
    def assert_headers(api_key, org_id):
        if api_key != API_SECRET or org_id != ORG:
            raise AssertionError("API auth contract changed")


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class GateHttp:
    def __init__(
        self,
        payload,
        *,
        duplicate=False,
        delayed_duplicate_at=0,
        negative_execution=False,
        server_metadata_change=False,
        recovery_failure_stage=None,
        argument_transform=None,
        repeat_transform=None,
        results_transform=None,
        result_response_transform=None,
    ):
        self.payload = payload
        self.duplicate = duplicate
        self.negative_execution = negative_execution
        self.delayed_duplicate_at = delayed_duplicate_at
        self.server_metadata_change = server_metadata_change
        self.recovery_failure_stage = recovery_failure_stage
        self.argument_transform = argument_transform
        self.repeat_transform = repeat_transform
        self.results_transform = results_transform
        self.result_response_transform = result_response_transform
        self.put_count = 0
        self.valid_execution_reads = 0
        self.phase = "valid-before"
        self.webhooks = []
        self.result_requests = []
        self.current_workflow = workflow("$exec")

    def api(self, method, path, api_key, org_id, body=None, **_kwargs):
        ScriptedHttp.assert_headers(api_key, org_id)
        if path == f"/api/v1/workflows/{WORKFLOW}":
            if method == "PUT":
                self.put_count += 1
                if self.recovery_failure_stage == "put":
                    raise M.Refusal(
                        f"malicious recovery error\n{WEBHOOK_URI}\n{HEADER_SECRET}"
                    )
                self.current_workflow = copy.deepcopy(body)
                return {"success": True}
            if self.put_count and self.recovery_failure_stage == "get":
                raise M.Refusal(
                    f"malicious recovery error\n{WEBHOOK_URI}\n{HEADER_SECRET}"
                )
            result = copy.deepcopy(self.current_workflow)
            if self.put_count and self.server_metadata_change:
                add_allowed_server_metadata(result, f"server-managed-{self.put_count}")
            if self.put_count and self.recovery_failure_stage == "proof":
                result["updated_at"] = "outside-closed-allowlist"
            return result
        if path.endswith("/executions?top=100"):
            base = [{"execution_id": "77777777-7777-4777-8777-777777777777"}]
            if self.phase == "valid-after":
                self.valid_execution_reads += 1
                base.append({"execution_id": EXECUTION, "authorization": AUTHORIZATION})
                if self.duplicate or (
                    self.delayed_duplicate_at and
                    self.valid_execution_reads >= self.delayed_duplicate_at
                ):
                    base.append(
                        {"execution_id": "88888888-8888-4888-8888-888888888888", "authorization": AUTHORIZATION}
                    )
            elif self.phase.endswith("after") and self.negative_execution:
                base.append({"execution_id": "99999999-9999-4999-8999-999999999999"})
            return {"executions": base}
        if path == "/api/v1/streams/results":
            self.result_requests.append(copy.deepcopy(body))
            result_index = len(self.result_requests) - 1
            argument = M.canonical_bytes(self.payload).decode()
            if self.argument_transform is not None:
                argument = self.argument_transform(copy.deepcopy(self.payload))
            repeat = copy.deepcopy(self.payload)
            if self.repeat_transform is not None:
                repeat = self.repeat_transform(copy.deepcopy(self.payload))
            results = [
                {
                    "action": {"id": ACTION, "label": "repeat_back_to_me"},
                    "status": "SUCCESS",
                    "result": repeat,
                }
            ]
            if self.results_transform is not None:
                results = self.results_transform(copy.deepcopy(results))
            response = {
                "execution_id": EXECUTION,
                "status": "FINISHED",
                "execution_argument": argument,
                "started_at": "2026-08-18T01:02:03.000Z",
                "completed_at": "2026-08-18T01:02:04.000Z",
                "results": results,
            }
            if self.result_response_transform is not None:
                response = self.result_response_transform(response, result_index)
            return response
        raise AssertionError((method, path))

    def webhook(self, url, payload, header, **_kwargs):
        self.webhooks.append((url, copy.deepcopy(payload), header))
        if header == HEADER_SECRET:
            self.payload = copy.deepcopy(payload)
            self.phase = "valid-after"
            return M.HttpResponse(200, {"execution_id": EXECUTION, "authorization": AUTHORIZATION})
        if header is None:
            self.phase = "missing-after"
        else:
            self.phase = "wrong-after"
        return M.HttpResponse(401, None)


def create_snapshot(tmp: Path, original=None):
    original = original or workflow()
    secrets_backend = FakeSecrets(tmp, original)
    name = "rollback_record"
    record = secrets_backend.record_path(name)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text('{"protected":"opaque-ciphertext"}', encoding="utf-8")
    secrets_backend.values[name] = M.canonical_bytes(original).decode()
    evidence = {
        "schema_version": 1,
        "artifact_kind": "shuffle-observe-only-g0-snapshot",
        "api_origin": "https://shuffler.io",
        "organization_id": ORG,
        "workflow_id": WORKFLOW,
        "webhook_id": WEBHOOK,
        "rollback": {
            "secret_reference": name,
            "record_path_sha256": M.sha256_bytes(str(record.resolve()).encode()),
            "record_sha256": M.sha256_bytes(record.read_bytes()),
            "canonical_workflow_sha256": M.canonical_sha256(original),
        },
    }
    path = tmp / "g0-snapshot.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    return path, secrets_backend


class WorkflowContractTests(unittest.TestCase):
    def test_safe_projection_accepts_actual_shuffle_fields_and_empty_conditions(self):
        result = M.inspect_workflow(workflow(), config(), HEADER_SECRET)
        self.assertEqual(result["repeat_action_id"], ACTION)
        self.assertEqual(result["effective_unconditional_branch_count"], 1)
        self.assertEqual(result["unexpected_action_count"], 0)
        self.assertEqual(result["workflow_name"], "OBSERVE_ONLY")
        self.assertEqual(result["sharing"], "private")
        self.assertEqual(result["trigger_id"], WEBHOOK)
        self.assertEqual(result["action_id"], ACTION)
        self.assertEqual(result["branch_id"], BRANCH)
        self.assertEqual(result["app_version"], "1.2.0")
        self.assertEqual(result["action_label"], "repeat_back_to_me")
        self.assertEqual(result["call_classification"], "non-exec")
        self.assertNotEqual(result["call_sha256"], "before")

    def test_auth_headers_accepts_actual_equals_and_legacy_colon_only(self):
        M.inspect_workflow(workflow(), config(), HEADER_SECRET)
        colon = workflow()
        colon["triggers"][0]["parameters"][0]["value"] = (
            f"{M.HEADER_NAME}: {HEADER_SECRET}"
        )
        M.inspect_workflow(colon, config(), HEADER_SECRET)
        for bad in (
            f"{M.HEADER_NAME}:={HEADER_SECRET}",
            f"{M.HEADER_NAME}={HEADER_SECRET}\nOther=bad",
            f"{M.HEADER_NAME}={HEADER_SECRET}\n{M.HEADER_NAME}={HEADER_SECRET}",
        ):
            value = workflow()
            value["triggers"][0]["parameters"][0]["value"] = bad
            with self.assertRaises(M.Refusal):
                M.inspect_workflow(value, config(), HEADER_SECRET)

    def test_field_aliases_and_edge_alias_are_supported(self):
        value = workflow()
        value["workflow_id"] = value.pop("id")
        value["is_private"] = True
        value.pop("sharing")
        trigger = value["triggers"][0]
        trigger["type"] = trigger.pop("trigger_type")
        action = value["actions"][0]
        action["app"] = action.pop("app_name")
        action["action_name"] = action.pop("name")
        value["edges"] = [
            {"branch_id": BRANCH, "source": WEBHOOK, "destination": ACTION, "condition": ""}
        ]
        value.pop("branches")
        self.assertEqual(
            M.inspect_workflow(value, config(), HEADER_SECRET)["action_count"], 1
        )

    def test_forbidden_or_extra_action_is_refused(self):
        for bad in (
            {"app_name": "GitHub", "name": "dispatch"},
            {"app_name": "Shuffle Tools", "name": "execute_python"},
        ):
            value = workflow()
            value["actions"][0].update(bad)
            with self.assertRaises(M.Refusal):
                M.inspect_workflow(value, config(), HEADER_SECRET)
        value = workflow()
        value["actions"].append({"name": "Dispatcher"})
        with self.assertRaises(M.Refusal):
            M.inspect_workflow(value, config(), HEADER_SECRET)

    def test_header_and_branch_must_be_exact(self):
        for mutate in (
            lambda value: value["triggers"][0]["parameters"][0].update(value="wrong"),
            lambda value: value["branches"][0].update(conditions=[{"value": True}]),
            lambda value: value["branches"].append(copy.deepcopy(value["branches"][0])),
        ):
            value = workflow()
            mutate(value)
            with self.assertRaises(M.Refusal):
                M.inspect_workflow(value, config(), HEADER_SECRET)

    def test_mutation_is_exactly_one_scalar(self):
        original = workflow()
        updated = M.mutate_call_only(original)
        self.assertEqual(
            M.structural_diff(original, updated),
            [("actions[0].parameters[0].value", "before", "$exec")],
        )
        self.assertEqual(original["actions"][0]["parameters"][0]["value"], "before")

    def test_readback_allows_only_the_five_observed_metadata_paths(self):
        expected = workflow()
        readback = copy.deepcopy(expected)
        add_allowed_server_metadata(readback)
        self.assertEqual(
            set(M.structural_diff_paths(expected, readback)),
            set(M.SERVER_METADATA_DRIFT_PATHS),
        )
        proof = M.prove_workflow_readback(
            expected, readback, config(), HEADER_SECRET
        )
        self.assertTrue(proof.restored_semantically)
        self.assertFalse(proof.full_exact)
        self.assertTrue(proof.server_metadata_drift_only)

    def test_readback_rejects_outside_metadata_action_and_call_drift(self):
        mutations = (
            lambda value: value.update(updated_at="not-allowlisted"),
            lambda value: value["actions"][0].update(app_version="9.9.9"),
            lambda value: value["actions"][0]["parameters"][0].update(value="changed"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                readback = workflow()
                mutate(readback)
                with self.assertRaises(M.ReadbackProofFailure):
                    M.prove_workflow_readback(
                        workflow(), readback, config(), HEADER_SECRET
                    )


class DpapiAndEvidenceTests(unittest.TestCase):
    def test_dpapi_plaintext_uses_only_captured_stdin_stdout_not_argv(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            output = "C:\\private\\rollback.dpapi.json" if kwargs["input"] else API_SECRET
            return type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()

        with workspace_tempdir() as directory:
            root = Path(directory)
            backend = M.DpapiSecrets(
                root,
                module_path=ROOT / "automation" / "SocLab.Security.psm1",
                run=fake_run,
            )
            self.assertEqual(backend.unprotect(M.API_KEY_NAME), API_SECRET)
            plaintext = "top-secret-full-workflow"
            expected = backend.record_path("rollback")
            # Make the fake subprocess return the exact expected path.
            def protect_run(args, **kwargs):
                calls.append((args, kwargs))
                expected.write_text("opaque", encoding="utf-8")
                return type("Result", (), {"returncode": 0, "stdout": str(expected), "stderr": ""})()
            backend.run = protect_run
            backend.protect_new("rollback", plaintext)
            args, kwargs = calls[-1]
            self.assertEqual(kwargs["input"], plaintext)
            self.assertNotIn(plaintext, " ".join(args))
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["capture_output"])

    def test_dpapi_nonzero_diagnostics_are_stage_specific_and_stderr_safe(self):
        safe_stderr = json.dumps(
            {
                "sentinel": M.PS_DIAGNOSTIC_SENTINEL,
                "exception_type": "System.Management.Automation.RuntimeException",
                "fqid": "RuntimeException",
            },
            separators=(",", ":"),
        )

        def failed_unprotect(args, **kwargs):
            return type(
                "Result",
                (),
                {
                    "returncode": 31,
                    "stdout": API_SECRET,
                    "stderr": safe_stderr,
                },
            )()

        malicious_stderr = (
            f"raw PowerShell message\n{WEBHOOK_URI}\n"
            f"{M.HEADER_NAME}: {HEADER_SECRET}\nC:\\private\\secret.dpapi.json"
        )

        def failed_protect(args, **kwargs):
            return type(
                "Result",
                (),
                {
                    "returncode": 31,
                    "stdout": "plaintext-echo-must-not-appear",
                    "stderr": malicious_stderr,
                },
            )()

        with workspace_tempdir() as directory:
            root = Path(directory)
            backend = M.DpapiSecrets(
                root,
                run=failed_unprotect,
            )
            with self.assertRaises(M.Refusal) as unprotect_error:
                backend.unprotect(M.API_KEY_NAME)
            unprotect_text = str(unprotect_error.exception)
            self.assertIn("stage=unprotect", unprotect_text)
            self.assertIn("returncode_category=powershell_exception", unprotect_text)
            self.assertIn(
                "exception_type=System.Management.Automation.RuntimeException",
                unprotect_text,
            )
            self.assertIn("fqid=RuntimeException", unprotect_text)
            self.assertNotIn(API_SECRET, unprotect_text)
            self.assertNotIn(M.API_KEY_NAME, unprotect_text)

            backend.run = failed_protect
            protected_plaintext = "protected-workflow-plaintext-must-not-appear"
            with self.assertRaises(M.Refusal) as protect_error:
                backend.protect_new("rollback_record", protected_plaintext)
            protect_text = str(protect_error.exception)
            self.assertIn("stage=protect_new", protect_text)
            self.assertIn("returncode_category=powershell_exception", protect_text)
            for forbidden in (
                protected_plaintext,
                "plaintext-echo-must-not-appear",
                WEBHOOK_URI,
                HEADER_SECRET,
                "raw PowerShell message",
                "secret.dpapi.json",
                "rollback_record",
                "\n",
            ):
                self.assertNotIn(forbidden, protect_text)

    def test_dpapi_timeout_is_fixed_stage_safe_and_uses_thirty_seconds(self):
        calls = []

        def timed_out(args, **kwargs):
            calls.append((args, kwargs))
            raise subprocess.TimeoutExpired(
                args,
                kwargs["timeout"],
                output=API_SECRET,
                stderr=f"{WEBHOOK_URI}\n{HEADER_SECRET}",
            )

        with workspace_tempdir() as directory:
            backend = M.DpapiSecrets(Path(directory), run=timed_out)
            for stage, operation in (
                ("unprotect", lambda: backend.unprotect(M.API_KEY_NAME)),
                ("protect_new", lambda: backend.protect_new("rollback", "plaintext")),
            ):
                with self.subTest(stage=stage):
                    with self.assertRaises(M.Refusal) as caught:
                        operation()
                    message = str(caught.exception)
                    self.assertIn(f"stage={stage}", message)
                    self.assertIn("returncode_category=timeout", message)
                    for forbidden in (API_SECRET, WEBHOOK_URI, HEADER_SECRET, "plaintext"):
                        self.assertNotIn(forbidden, message)
            self.assertTrue(all(call[1]["timeout"] == 30 for call in calls))

    def test_runner_has_no_pseudo_protection(self):
        source = MODULE_PATH.read_text(encoding="utf-8").lower()
        self.assertNotIn("b64encode", source)
        self.assertNotIn("b64decode", source)
        self.assertNotIn("import base64", source)

    def test_snapshot_persists_hashes_not_uri_header_api_key_or_full_export(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            backend = FakeSecrets(root)
            evidence_path = root / "evidence.json"
            M.snapshot(
                config(), evidence_path, backend, ScriptedHttp(workflow()),
                rollback_name="rollback", now=lambda: FIXED_NOW,
            )
            text = evidence_path.read_text(encoding="utf-8")
            for forbidden in (API_SECRET, HEADER_SECRET, WEBHOOK_URI, "preserved full object"):
                self.assertNotIn(forbidden, text)
            self.assertNotIn('"before"', text)
            value = json.loads(text)
            self.assertEqual(value["webhook"]["uri_sha256"], M.sha256_bytes(WEBHOOK_URI.encode()))
            self.assertIn("record_path_sha256", value["rollback"])
            self.assertIn("record_sha256", value["rollback"])
            self.assertTrue(value["rollback"]["dpapi_roundtrip_proven"])
            self.assertIn("rollback", backend.values)

    def test_snapshot_refuses_failed_dpapi_roundtrip(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            backend = FakeSecrets(root, corrupt_roundtrip=True)
            with self.assertRaisesRegex(M.Refusal, "canonical round-trip"):
                M.snapshot(
                    config(), root / "evidence.json", backend,
                    ScriptedHttp(workflow()),
                    rollback_name="rollback", now=lambda: FIXED_NOW,
                )

    def test_evidence_writer_rejects_nested_raw_secret_keys_but_allows_hashes(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            for key in M.FORBIDDEN_EVIDENCE_KEYS:
                with self.assertRaisesRegex(M.Refusal, "forbidden raw field"):
                    M.write_evidence(root / "bad.json", {"nested": [{key: "x"}]})
            M.write_evidence(
                root / "good.json",
                {"webhook_uri_sha256": "a" * 64, "api_key_reference": "shuffle_api_key"},
            )


class ApplyRollbackTests(unittest.TestCase):
    def test_apply_sends_full_get_derived_workflow(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            http = ScriptedHttp(workflow())
            evidence = M.apply_minimal(
                config(), snapshot_path, root / "apply.json", backend, http,
                now=lambda: FIXED_NOW,
            )
            puts = [call for call in http.calls if call[0] == "PUT"]
            self.assertEqual(len(puts), 1)
            sent = puts[0][2]
            self.assertEqual(sent["description"], "preserved full object")
            self.assertEqual(sent["actions"][0]["parameters"][0]["value"], "$exec")
            self.assertEqual(M.structural_diff(workflow(), sent)[0][0], "actions[0].parameters[0].value")
            self.assertTrue(evidence["precondition_full_exact"])
            self.assertFalse(evidence["precondition_server_metadata_drift_only"])
            self.assertTrue(evidence["full_exact"])
            self.assertFalse(evidence["server_metadata_drift_only"])

    def test_apply_precondition_accepts_current_metadata_only_drift(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            current = workflow()
            add_allowed_server_metadata(current, "fresh-server-metadata")
            http = ScriptedHttp(current)
            evidence = M.apply_minimal(
                config(), snapshot_path, root / "apply.json", backend, http,
                now=lambda: FIXED_NOW,
            )
            puts = [call for call in http.calls if call[0] == "PUT"]
            self.assertEqual(len(puts), 1)
            submitted = puts[0][2]
            self.assertEqual(
                M.structural_diff(current, submitted),
                [("actions[0].parameters[0].value", "before", "$exec")],
            )
            self.assertFalse(evidence["precondition_full_exact"])
            self.assertTrue(evidence["precondition_server_metadata_drift_only"])

    def test_apply_precondition_rejects_all_non_allowlisted_drift_before_put(self):
        mutations = (
            (
                "action",
                lambda value: value["actions"][0].update(
                    id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                ),
            ),
            (
                "call",
                lambda value: value["actions"][0]["parameters"][0].update(
                    value="changed"
                ),
            ),
            (
                "header",
                lambda value: value["triggers"][0]["parameters"][0].update(
                    value=f"{M.HEADER_NAME}=wrong-header-value"
                ),
            ),
            ("unknown-metadata", lambda value: value.update(updated_at="not-allowed")),
        )
        for name, mutation in mutations:
            with self.subTest(drift=name):
                with workspace_tempdir() as directory:
                    root = Path(directory)
                    snapshot_path, backend = create_snapshot(root)
                    current = workflow()
                    mutation(current)
                    http = ScriptedHttp(current)
                    with self.assertRaisesRegex(M.Refusal, "semantic precondition"):
                        M.apply_minimal(
                            config(), snapshot_path, root / "apply.json", backend, http,
                            now=lambda: FIXED_NOW,
                        )
                    self.assertEqual(
                        [call for call in http.calls if call[0] == "PUT"], []
                    )
                    self.assertFalse((root / "apply.json").exists())
                    self.assertFalse((root / "g1-recovery.json").exists())

    def test_apply_accepts_a_copied_snapshot_with_the_same_hash_binding(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            copied_snapshot = root / "copied-g0.json"
            shutil.copyfile(snapshot_path, copied_snapshot)
            http = ScriptedHttp(copy.deepcopy(workflow()))
            evidence = M.apply_minimal(
                config(), copied_snapshot, root / "apply.json", backend, http,
                now=lambda: FIXED_NOW,
            )
            self.assertTrue(evidence["precondition_full_exact"])
            self.assertFalse(evidence["precondition_server_metadata_drift_only"])
            self.assertEqual(
                len([call for call in http.calls if call[0] == "PUT"]), 1
            )

    def test_readback_failure_immediately_restores_and_proves_exact_original(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            http = ScriptedHttp(workflow())
            http.fail_readback = True
            with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
                M.apply_minimal(
                    config(), snapshot_path, root / "apply.json", backend, http,
                )
            puts = [call[2] for call in http.calls if call[0] == "PUT"]
            self.assertEqual(len(puts), 2)
            self.assertEqual(puts[-1], workflow())
            self.assertEqual(http.current, workflow())

    def test_explicit_rollback_accepts_only_five_server_metadata_paths(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            http = ScriptedHttp(workflow("$exec"))
            http.server_metadata_change = True
            evidence = M.rollback(
                config(), snapshot_path, root / "rollback.json", backend, http,
                now=lambda: FIXED_NOW,
            )
            self.assertEqual(http.current, workflow())
            self.assertFalse(evidence["full_exact"])
            self.assertTrue(evidence["server_metadata_drift_only"])
            self.assertTrue(evidence["restored_semantically"])

    def test_readback_tolerates_server_metadata_but_rejects_semantic_drift(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            metadata_http = ScriptedHttp(workflow())
            metadata_http.server_metadata_change = True
            metadata_evidence = M.apply_minimal(
                config(), snapshot_path, root / "apply.json", backend,
                metadata_http,
                now=lambda: FIXED_NOW,
            )
            self.assertFalse(metadata_evidence["full_exact"])
            self.assertTrue(metadata_evidence["server_metadata_drift_only"])
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            drift_http = ScriptedHttp(workflow())
            drift_http.semantic_drift = True
            drift_http.server_metadata_change = True
            with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
                M.apply_minimal(
                    config(), snapshot_path, root / "apply.json", backend,
                    drift_http,
                    now=lambda: FIXED_NOW,
                )
            recovery = json.loads((root / "g1-recovery.json").read_text(encoding="utf-8"))
            self.assertEqual(recovery["failure_gate"], "G1")
            self.assertTrue(recovery["recovery_proof_succeeded"])
            self.assertTrue(recovery["mutation_attempted"])
            self.assertFalse(recovery["full_exact"])
            self.assertTrue(recovery["server_metadata_drift_only"])

    def test_ambiguous_put_failure_also_restores_and_proves_original(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            http = ScriptedHttp(workflow())
            http.fail_first_put = True
            with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
                M.apply_minimal(
                    config(), snapshot_path, root / "apply.json", backend, http,
                )
            puts = [call[2] for call in http.calls if call[0] == "PUT"]
            self.assertEqual(puts, [M.mutate_call_only(workflow()), workflow()])
            self.assertEqual(http.current, workflow())


class TransportTests(unittest.TestCase):
    def test_url_allowlist_and_webhook_id(self):
        self.assertEqual(M.validate_origin("https://shuffler.io/", base=True), "https://shuffler.io")
        self.assertEqual(M.validate_webhook_uri(WEBHOOK_URI, WEBHOOK), WEBHOOK_URI)
        for url in (
            "http://shuffler.io/",
            "https://evil.example/",
            "https://shuffler.io:443/",
            "https://shuffler.io/api?q=1",
            "https://shuffler.io.evil.example/",
        ):
            with self.assertRaises(M.Refusal):
                M.validate_origin(url)
        with self.assertRaises(M.Refusal):
            M.validate_webhook_uri(WEBHOOK_URI, WORKFLOW)

    def test_redirect_handler_refuses(self):
        handler = M.NoRedirect()
        with self.assertRaises(M.Refusal):
            handler.redirect_request(None, None, 302, "Found", {}, "https://shuffler.io/next")

    def test_api_transport_has_org_and_bearer_headers(self):
        captured = {}

        class Response:
            status = 200
            def read(self, amount): return b"{}"
            def __enter__(self): return self
            def __exit__(self, *args): return False

        class Opener:
            def open(self, request, timeout):
                captured["headers"] = dict(request.header_items())
                captured["timeout"] = timeout
                return Response()

        client = M.SafeHttp("https://shuffler.io", opener=Opener())
        client.api("GET", f"/api/v1/workflows/{WORKFLOW}", API_SECRET, ORG)
        headers = {key.lower(): value for key, value in captured["headers"].items()}
        self.assertEqual(headers["authorization"], f"Bearer {API_SECRET}")
        self.assertEqual(headers["org-id"], ORG)

    def test_http_deadline_uses_remaining_budget_and_refuses_late_open(self):
        captured = []

        class Response:
            status = 200
            def read(self, amount): return b"{}"
            def __enter__(self): return self
            def __exit__(self, *args): return False

        class Opener:
            def open(self, request, timeout):
                captured.append(timeout)
                return Response()

        client = M.SafeHttp("https://shuffler.io", timeout=20, opener=Opener())
        client.api(
            "GET", f"/api/v1/workflows/{WORKFLOW}", API_SECRET, ORG,
            deadline=7.0, clock=lambda: 5.0,
        )
        self.assertEqual(captured, [2.0])
        with self.assertRaisesRegex(M.Refusal, "deadline expired"):
            client.api(
                "GET", f"/api/v1/workflows/{WORKFLOW}", API_SECRET, ORG,
                deadline=5.0, clock=lambda: 5.0,
            )
        self.assertEqual(captured, [2.0])

    def test_poll_helpers_never_call_after_case_deadline(self):
        class CountingHttp:
            def __init__(self): self.calls = 0
            def api(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("deadline-expired call")

        http = CountingHttp()
        clock = lambda: 10.0
        with self.assertRaises(M.Refusal):
            M._wait_for_one_execution(
                http, config(), API_SECRET, set(), 10.0,
                clock=clock, sleep=lambda _: None, interval=1,
            )
        self.assertEqual(
            "case_deadline",
            self._category_from(
                lambda: M._observe_zero_new(
                    http, config(), API_SECRET, set(), 10.0, 10.0,
                    clock=clock, sleep=lambda _: None, interval=1,
                )
            ),
        )
        self.assertEqual(
            "case_deadline",
            self._category_from(
                lambda: M._observe_singleton_execution(
                    http, config(), API_SECRET, set(), EXECUTION, 10.0, 10.0,
                    clock=clock, sleep=lambda _: None, interval=1,
                )
            ),
        )
        self.assertEqual(http.calls, 0)

    @staticmethod
    def _category_from(operation):
        try:
            operation()
        except M.Gate2CategoryFailure as error:
            return error.category
        raise AssertionError("expected Gate2CategoryFailure")

    def test_observation_final_get_and_eventual_consistency_rules(self):
        class SequenceHttp:
            def __init__(self, responses, clock, latencies=None):
                self.responses = list(responses)
                self.clock = clock
                self.latencies = list(latencies or [0] * len(responses))
                self.calls = 0

            def api(self, *args, **kwargs):
                index = self.calls
                self.calls += 1
                self.clock.value += self.latencies[index]
                return {
                    "executions": [
                        {"execution_id": execution_id}
                        for execution_id in self.responses[index]
                    ]
                }

        with self.subTest("request crosses observation end but final passes"):
            clock = FakeClock()
            http = SequenceHttp(
                [[EXECUTION], [EXECUTION]], clock, latencies=[6, 0]
            )
            observations = M._observe_singleton_execution(
                http, config(), API_SECRET, set(), EXECUTION, 5.0, 20.0,
                clock=clock, sleep=clock.sleep, interval=1,
            )
            self.assertEqual(observations, 2)
            self.assertEqual(http.calls, 2)

        with self.subTest("transient empty is tolerated"):
            clock = FakeClock()
            http = SequenceHttp(
                [[], [EXECUTION], [EXECUTION]], clock
            )
            observations = M._observe_singleton_execution(
                http, config(), API_SECRET, set(), EXECUTION, 2.0, 10.0,
                clock=clock, sleep=clock.sleep, interval=1,
            )
            self.assertEqual(observations, 3)

        with self.subTest("final singleton missing is rejected"):
            clock = FakeClock()
            http = SequenceHttp([[EXECUTION], []], clock)
            self.assertEqual(
                self._category_from(
                    lambda: M._observe_singleton_execution(
                        http, config(), API_SECRET, set(), EXECUTION, 1.0, 10.0,
                        clock=clock, sleep=clock.sleep, interval=1,
                    )
                ),
                "singleton_final_missing",
            )

        with self.subTest("negative final GET is enforced"):
            clock = FakeClock()
            http = SequenceHttp([[], [EXECUTION]], clock)
            self.assertEqual(
                self._category_from(
                    lambda: M._observe_zero_new(
                        http, config(), API_SECRET, set(), 1.0, 10.0,
                        clock=clock, sleep=clock.sleep, interval=1,
                    )
                ),
                "negative_execution_observed",
            )

    def test_execution_window_refuses_top_100_truncation_boundary(self):
        class FullWindow:
            def api(self, method, path, api_key, org_id, body=None, **_kwargs):
                return {
                    "executions": [
                        {"execution_id": f"{index:08x}-0000-4000-8000-000000000000"}
                        for index in range(100)
                    ]
                }
        with self.assertRaisesRegex(M.Refusal, "may be truncated"):
            M._api_executions(FullWindow(), config(), API_SECRET)


class Gate2Tests(unittest.TestCase):
    def _payload(self):
        return M.build_synthetic_payload(now=FIXED_NOW, nonce="unit-test")

    def test_synthetic_payload_matches_v2_fixed_incident_contract(self):
        payload = self._payload()
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(
            payload["rule"],
            {
                "id": "100104",
                "level": 12,
                "role": "high_confidence_s3_access",
            },
        )
        self.assertEqual(
            set(payload["incident"]),
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
        self.assertRegex(
            payload["incident"]["cloudtrail_event_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.assertEqual(payload["incident"]["event_source"], "s3.amazonaws.com")
        self.assertEqual(payload["incident"]["event_name"], "GetObject")
        self.assertEqual(
            payload["incident"]["principal_role_name"],
            "aws-topology-primary-karpenter-node",
        )
        self.assertEqual(
            payload["incident"]["bucket_alias"], "primary-application-data"
        )
        self.assertEqual(
            payload["incident"]["object_key"], "validation/capital-one-demo.csv"
        )
        self.assertEqual(payload["incident"]["result"], "success")
        self.assertNotIn("take_id", payload["incident"])
        self.assertNotIn("event_id", payload["incident"])
        self.assertNotIn("route", payload["incident"])

    def test_synthetic_payload_uuid_and_hashes_are_deterministic(self):
        first = self._payload()
        second = self._payload()
        self.assertEqual(first, second)
        self.assertRegex(first["incident"]["wazuh_alert_id"], r"^[0-9]+\.[0-9]+$")
        self.assertRegex(
            first["incident"]["principal_session_id_sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertRegex(first["integrity"]["raw_message_sha256"], r"^[0-9a-f]{64}$")

    def test_semantic_diagnostic_allows_current_v2_incident_paths(self):
        changed = copy.deepcopy(self._payload())
        changed["incident"]["object_key"] = "validation/other-demo.csv"
        summary = M.semantic_diff_summary(self._payload(), changed)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["entries"][0]["path"], "/incident/object_key")

    def test_legacy_incident_fields_are_rejected(self):
        legacy = copy.deepcopy(self._payload())
        legacy["incident"]["take_id"] = "legacy"
        with self.assertRaisesRegex(M.Refusal, "top-level fields|legacy incident"):
            M.validate_synthetic_payload(legacy, M.load_json_file(M.SCHEMA_PATH))

    def test_body_hash_uses_payload_before_hash_insertion(self):
        payload = self._payload()
        without = copy.deepcopy(payload)
        supplied = without["integrity"].pop("body_sha256")
        self.assertEqual(supplied, M.canonical_sha256(without))

    def test_global_deadline_refuses_before_any_http_call(self):
        class NoCallHttp:
            timeout = 20
            def __init__(self): self.calls = 0
            def api(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("global-deadline call")
            def webhook(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("global-deadline webhook")

        with workspace_tempdir() as directory:
            root = Path(directory)
            http = NoCallHttp()
            clock = FakeClock()
            with self.assertRaisesRegex(M.Gate2StageFailure, "stage=preflight"):
                M._gate2(
                    config(), root / "unused.json", root / "unused-evidence.json",
                    FakeSecrets(root), http, poll_timeout=10, poll_interval=1,
                    now=lambda: FIXED_NOW, clock=clock, sleep=clock.sleep,
                    snapshot_verified=True, total_deadline=clock(),
                    secret_material=(API_SECRET, WEBHOOK_URI, HEADER_SECRET),
                )
            self.assertEqual(http.calls, 0)

    def test_decode_at_most_once_and_reject_double_encoding(self):
        value = {"a": 1}
        self.assertEqual(M.decode_json_once(json.dumps(value), "x"), value)
        double = json.dumps(json.dumps(value))
        with self.assertRaisesRegex(M.Refusal, "double-encoded"):
            M.decode_json_once(double, "x")

    def test_gate2_valid_one_execution_and_both_negative_zero(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            payload = self._payload()
            http = GateHttp(payload)
            clock = FakeClock()
            evidence = M.gate2(
                config(), snapshot_path, root / "gate2.json", backend, http,
                poll_timeout=10, poll_interval=1, now=lambda: FIXED_NOW,
                clock=clock, sleep=clock.sleep,
            )
            self.assertEqual(len(http.webhooks), 3)
            self.assertEqual(http.webhooks[0][2], HEADER_SECRET)
            self.assertIsNone(http.webhooks[2][2])
            self.assertEqual(evidence["valid_header"]["new_execution_count"], 1)
            self.assertGreater(evidence["valid_header"]["execution_observation_count"], 1)
            self.assertEqual(
                evidence["valid_header"]["result_readiness_observation_count"], 1
            )
            self.assertTrue(evidence["valid_header"]["result_ready"])
            self.assertEqual(clock.value, 30)
            self.assertLessEqual(clock.value, evidence["total_wall_cap_seconds"])
            self.assertEqual(evidence["total_wall_cap_seconds"], 470.0)
            self.assertEqual(evidence["poll_timeout_seconds_per_window"], 10)
            self.assertEqual(
                [case["new_execution_count"] for case in evidence["authentication_negative_cases"]],
                [0, 0],
            )
            self.assertEqual(
                http.result_requests,
                [{"execution_id": EXECUTION, "authorization": AUTHORIZATION}],
            )
            text = (root / "gate2.json").read_text(encoding="utf-8")
            for forbidden in (API_SECRET, HEADER_SECRET, WEBHOOK_URI, AUTHORIZATION):
                self.assertNotIn(forbidden, text)

    def test_repeat_result_rejects_unidentified_or_unexpected_entries(self):
        for extra in (
            {"status": "SUCCESS", "result": {}},
            {"action_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "status": "SUCCESS"},
        ):
            execution = {
                "results": [
                    {"action_id": ACTION, "status": "SUCCESS", "result": {}},
                    extra,
                ]
            }
            with self.assertRaisesRegex(M.Refusal, "unexpected Action result"):
                M._repeat_result(execution, ACTION, "repeat_back_to_me", WEBHOOK)
        allowed = {
            "results": [
                {"action_id": WEBHOOK, "status": "SUCCESS"},
                {"action_id": ACTION, "status": "SUCCESS", "result": {"ok": True}},
            ]
        }
        self.assertEqual(
            M._repeat_result(allowed, ACTION, "repeat_back_to_me", WEBHOOK),
            {"ok": True},
        )

    def test_actual_configured_action_label_is_used_for_result_matching(self):
        def actual_result_label(response, _index):
            response["results"][0]["action"]["label"] = "Change Me"
            return response

        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(
                root, original=workflow(label="Change Me")
            )
            http = GateHttp(
                self._payload(), result_response_transform=actual_result_label
            )
            http.current_workflow = workflow("$exec", label="Change Me")
            clock = FakeClock()
            evidence = M.gate2(
                config(), snapshot_path, root / "gate2.json", backend, http,
                poll_timeout=10, poll_interval=1, now=lambda: FIXED_NOW,
                clock=clock, sleep=clock.sleep,
            )
            self.assertEqual(evidence["valid_header"]["repeat_status"], "SUCCESS")
            self.assertEqual(len(http.result_requests), 1)

    def test_repeat_result_retryable_states_are_narrow(self):
        retryable = (
            {},
            {"results": []},
            {"results": [{"action_id": WEBHOOK, "status": "SUCCESS"}]},
            {"results": [{"action_id": ACTION, "status": "RUNNING"}]},
            {"results": [{"action_id": ACTION, "status": "SUCCESS"}]},
        )
        for execution in retryable:
            with self.subTest(execution_shape=tuple(execution)):
                with self.assertRaises(M.RepeatResultNotReady):
                    M._repeat_result(
                        execution, ACTION, "repeat_back_to_me", WEBHOOK
                    )

    def test_repeat_result_hard_failures_are_not_retryable(self):
        base = {
            "action": {"id": ACTION, "label": "repeat_back_to_me"},
            "status": "SUCCESS",
            "result": {},
        }
        hard = (
            {"results": [None]},
            {"results": [copy.deepcopy(base), copy.deepcopy(base)]},
            {
                "results": [
                    {
                        "action_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                        "status": "SUCCESS",
                        "result": {},
                    }
                ]
            },
            {
                "results": [
                    {
                        **copy.deepcopy(base),
                        "action": {"id": ACTION, "label": "wrong-label"},
                    }
                ]
            },
            {"results": [{**copy.deepcopy(base), "status": "FAILED"}]},
        )
        for execution in hard:
            with self.subTest(results=execution["results"]):
                with self.assertRaises(M.Refusal) as caught:
                    M._repeat_result(
                        execution, ACTION, "repeat_back_to_me", WEBHOOK
                    )
                self.assertNotIsInstance(caught.exception, M.RepeatResultNotReady)

    def test_finished_result_readiness_retries_only_incomplete_states(self):
        def absent(response):
            response.pop("results")

        def empty(response):
            response["results"] = []

        def nonterminal(response):
            response["results"][0]["status"] = "RUNNING"

        def result_missing(response):
            response["results"][0].pop("result")

        for name, mutation in (
            ("absent", absent),
            ("empty", empty),
            ("nonterminal", nonterminal),
            ("result-missing", result_missing),
        ):
            with self.subTest(state=name):
                def transform(response, index, mutation=mutation):
                    if index == 0:
                        mutation(response)
                    return response

                with workspace_tempdir() as directory:
                    root = Path(directory)
                    snapshot_path, backend = create_snapshot(root)
                    clock = FakeClock()
                    http = GateHttp(
                        self._payload(), result_response_transform=transform
                    )
                    evidence = M.gate2(
                        config(), snapshot_path, root / "gate2.json", backend, http,
                        poll_timeout=10, poll_interval=1, now=lambda: FIXED_NOW,
                        clock=clock, sleep=clock.sleep,
                    )
                    self.assertEqual(len(http.result_requests), 2)
                    self.assertEqual(len(http.webhooks), 3)
                    self.assertEqual(
                        evidence["valid_header"]["result_readiness_observation_count"],
                        2,
                    )
                    self.assertTrue(evidence["valid_header"]["result_ready"])

    def test_repeat_contract_hard_failures_are_immediate_and_recovered(self):
        def malformed(response):
            response["results"] = [None]

        def duplicate(response):
            response["results"].append(copy.deepcopy(response["results"][0]))

        def unexpected(response):
            response["results"][0]["action"]["id"] = (
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            )

        def label(response):
            response["results"][0]["action"]["label"] = "wrong-label"

        def terminal(response):
            response["results"][0]["status"] = "FAILED"

        for name, mutation in (
            ("malformed", malformed),
            ("duplicate", duplicate),
            ("unexpected", unexpected),
            ("label", label),
            ("terminal", terminal),
        ):
            with self.subTest(state=name):
                def transform(response, _index, mutation=mutation):
                    mutation(response)
                    return response

                with workspace_tempdir() as directory:
                    evidence, http = self._semantic_failure(
                        Path(directory),
                        return_http=True,
                        result_response_transform=transform,
                    )
                    self.assertEqual(
                        evidence["initial_failure_category"],
                        "repeat_contract_failed",
                    )
                    self.assertEqual(evidence["initial_failure_stage"], "valid_result_ready")
                    self.assertEqual(len(http.result_requests), 1)
                    self.assertEqual(len(http.webhooks), 1)

    def test_repeat_contract_timeout_makes_no_request_after_deadline(self):
        class NoCallHttp:
            def __init__(self):
                self.calls = 0

            def api(self, *_args, **_kwargs):
                self.calls += 1
                raise AssertionError("post-deadline result request")

        initial = {
            "execution_id": EXECUTION,
            "status": "FINISHED",
            "results": [],
        }
        clock = FakeClock()
        http = NoCallHttp()
        with self.assertRaises(M.Gate2CategoryFailure) as caught:
            M._wait_for_repeat_result_ready(
                http,
                config(),
                API_SECRET,
                initial,
                AUTHORIZATION,
                ACTION,
                "repeat_back_to_me",
                WEBHOOK,
                10.0,
                0.0,
                clock=clock,
                sleep=clock.sleep,
                interval=1,
            )
        self.assertEqual(caught.exception.category, "repeat_contract_timeout")
        self.assertEqual(caught.exception.result_readiness["observation_count"], 1)
        self.assertEqual(http.calls, 0)
        self.assertEqual(clock.value, 0)

    def test_repeat_contract_timeout_category_is_durable_after_recovery(self):
        def always_empty(response, _index):
            response["results"] = []
            return response

        with workspace_tempdir() as directory:
            evidence, http = self._semantic_failure(
                Path(directory),
                return_http=True,
                result_response_transform=always_empty,
            )
            self.assertEqual(evidence["initial_failure_stage"], "valid_result_ready")
            self.assertEqual(
                evidence["initial_failure_category"], "repeat_contract_timeout"
            )
            self.assertFalse(evidence["result_readiness"]["repeat_ready"])
            self.assertGreater(evidence["result_readiness"]["observation_count"], 1)
            self.assertEqual(len(http.webhooks), 1)

    def _semantic_failure(self, root, *, return_http=False, **http_options):
        snapshot_path, backend = create_snapshot(root)
        clock = FakeClock()
        http = GateHttp(self._payload(), **http_options)
        with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
            M.gate2(
                config(), snapshot_path, root / "gate2.json", backend, http,
                poll_timeout=10, poll_interval=1, now=lambda: FIXED_NOW,
                clock=clock, sleep=clock.sleep,
            )
        evidence = json.loads(
            (root / "gate2-recovery.json").read_text(encoding="utf-8")
        )
        return (evidence, http) if return_http else evidence

    def test_semantic_failure_categories_are_fixed_and_ordered(self):
        def changed(value):
            value["incident"]["result"] = "failed"
            return value

        cases = (
            (
                "argument_decode_failed",
                {"argument_transform": lambda _value: "{not-json"},
            ),
            (
                "repeat_contract_failed",
                {"results_transform": lambda _results: [{"status": "SUCCESS"}]},
            ),
            (
                "repeat_decode_failed",
                {"repeat_transform": lambda _value: json.dumps(json.dumps({"ok": True}))},
            ),
            (
                "request_argument_mismatch",
                {"argument_transform": changed, "repeat_transform": changed},
            ),
            (
                "argument_repeat_mismatch",
                {"repeat_transform": changed},
            ),
        )
        for expected_category, options in cases:
            with self.subTest(category=expected_category):
                with workspace_tempdir() as directory:
                    evidence = self._semantic_failure(Path(directory), **options)
                    expected_stage = (
                        "valid_result_ready"
                        if expected_category == "repeat_contract_failed"
                        else "valid_semantic"
                    )
                    self.assertEqual(evidence["initial_failure_stage"], expected_stage)
                    self.assertEqual(
                        evidence["initial_failure_category"], expected_category
                    )
                    self.assertTrue(evidence["recovery_proof_succeeded"])
                    readiness = evidence["result_readiness"]
                    self.assertTrue(readiness["execution_finished_seen"])
                    if expected_category == "repeat_contract_failed":
                        self.assertFalse(readiness["repeat_ready"])
                        self.assertEqual(readiness["observation_count"], 1)
                        self.assertNotIn("semantic_diagnostic", evidence)
                        continue
                    self.assertTrue(readiness["repeat_ready"])
                    diagnostic = evidence["semantic_diagnostic"]
                    self.assertRegex(
                        diagnostic["request_canonical_sha256"], r"^[0-9a-f]{64}$"
                    )
                    if expected_category == "argument_decode_failed":
                        self.assertNotIn("argument_canonical_sha256", diagnostic)
                    else:
                        self.assertRegex(
                            diagnostic["argument_canonical_sha256"],
                            r"^[0-9a-f]{64}$",
                        )
                    if expected_category in {
                        "argument_decode_failed",
                        "repeat_contract_failed",
                        "repeat_decode_failed",
                    }:
                        self.assertNotIn("repeat_canonical_sha256", diagnostic)
                    else:
                        self.assertRegex(
                            diagnostic["repeat_canonical_sha256"],
                            r"^[0-9a-f]{64}$",
                        )
                    if expected_category == "request_argument_mismatch":
                        self.assertFalse(diagnostic["request_equals_argument"])
                        self.assertNotIn("argument_equals_repeat", diagnostic)
                        self.assertNotIn("argument_repeat_diff", diagnostic)
                    if expected_category == "argument_repeat_mismatch":
                        self.assertTrue(diagnostic["request_equals_argument"])
                        self.assertFalse(diagnostic["argument_equals_repeat"])

    def test_semantic_diagnostic_exposes_only_approved_paths_and_types(self):
        unknown_key = "unknown-" + HEADER_SECRET

        def changed(value):
            value["incident"]["result"] = "failed"
            value[unknown_key] = WEBHOOK_URI
            return value

        with workspace_tempdir() as directory:
            root = Path(directory)
            evidence = self._semantic_failure(
                root, argument_transform=changed, repeat_transform=changed
            )
            diagnostic = evidence["semantic_diagnostic"]
            summary = diagnostic["request_argument_diff"]
            self.assertEqual(summary["total"], 2)
            self.assertFalse(summary["truncated"])
            self.assertIn(
                {
                    "kind": "value_mismatch",
                    "left_type": "string",
                    "right_type": "string",
                    "path": "/incident/result",
                },
                summary["entries"],
            )
            unknown = [entry for entry in summary["entries"] if "path_sha256" in entry]
            self.assertEqual(len(unknown), 1)
            self.assertRegex(unknown[0]["path_sha256"], r"^[0-9a-f]{64}$")
            raw = (root / "gate2-recovery.json").read_text(encoding="utf-8")
            for forbidden in (
                unknown_key, WEBHOOK_URI, HEADER_SECRET, API_SECRET,
                "failed", "unknown-",
            ):
                self.assertNotIn(forbidden, raw)
            for entry in summary["entries"]:
                self.assertIn(entry["kind"], M.SEMANTIC_DIFF_KINDS)
                self.assertIn(entry["left_type"], M.SEMANTIC_JSON_TYPES)
                self.assertIn(entry["right_type"], M.SEMANTIC_JSON_TYPES)

    def test_semantic_diff_is_bounded_and_hashes_unknown_paths(self):
        sensitive = "do-not-persist-value"
        right = {f"unknown-{index}-{sensitive}": sensitive for index in range(70)}
        summary = M.semantic_diff_summary({}, right)
        self.assertEqual(summary["total"], 70)
        self.assertTrue(summary["truncated"])
        self.assertEqual(len(summary["entries"]), M.SEMANTIC_DIFF_LIMIT)
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn(sensitive, serialized)
        self.assertTrue(
            all(
                set(entry) == {"kind", "left_type", "right_type", "path_sha256"}
                for entry in summary["entries"]
            )
        )

    def test_delayed_duplicate_during_valid_observation_is_rejected_and_recovered(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            clock = FakeClock()
            http = GateHttp(
                self._payload(), delayed_duplicate_at=3,
                server_metadata_change=True,
            )
            with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
                M.gate2(
                    config(), snapshot_path, root / "gate2.json", backend, http,
                    poll_timeout=10, poll_interval=1, now=lambda: FIXED_NOW,
                    clock=clock, sleep=clock.sleep,
                )
            recovery = json.loads(
                (root / "gate2-recovery.json").read_text(encoding="utf-8")
            )
            self.assertEqual(recovery["failure_gate"], "G2")
            self.assertEqual(
                recovery["initial_failure_category"], "singleton_set_changed"
            )
            self.assertTrue(recovery["recovery_proof_succeeded"])
            self.assertTrue(recovery["mutation_attempted"])
            self.assertFalse(recovery["full_exact"])
            self.assertTrue(recovery["server_metadata_drift_only"])
            recovery_text = (root / "gate2-recovery.json").read_text(encoding="utf-8")
            for forbidden in (API_SECRET, HEADER_SECRET, WEBHOOK_URI, AUTHORIZATION):
                self.assertNotIn(forbidden, recovery_text)

    def test_recovery_failure_evidence_uses_only_fixed_stages_and_booleans(self):
        for recovery_stage in ("put", "get", "proof"):
            with self.subTest(recovery_stage=recovery_stage):
                with workspace_tempdir() as directory:
                    root = Path(directory)
                    snapshot_path, backend = create_snapshot(root)
                    clock = FakeClock()
                    http = GateHttp(
                        self._payload(), duplicate=True,
                        recovery_failure_stage=recovery_stage,
                    )
                    with self.assertRaisesRegex(M.RecoveryFailure, "not proven"):
                        M.gate2(
                            config(), snapshot_path, root / "gate2.json", backend,
                            http, poll_timeout=10, poll_interval=1,
                            now=lambda: FIXED_NOW, clock=clock,
                            sleep=clock.sleep,
                        )
                    evidence_path = root / "gate2-recovery.json"
                    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                    self.assertEqual(evidence["initial_failure_stage"], "valid_execution")
                    self.assertEqual(evidence["initial_failure_category"], "stage_failure")
                    self.assertEqual(evidence["recovery_failure_stage"], recovery_stage)
                    self.assertTrue(evidence["mutation_attempted"])
                    self.assertFalse(evidence["recovery_proof_succeeded"])
                    self.assertEqual(
                        evidence["restored_semantically"], recovery_stage == "proof"
                    )
                    self.assertFalse(evidence["full_exact"])
                    self.assertFalse(evidence["server_metadata_drift_only"])
                    raw = evidence_path.read_text(encoding="utf-8")
                    for forbidden in (
                        API_SECRET, HEADER_SECRET, WEBHOOK_URI, AUTHORIZATION,
                        "malicious recovery error", "updated_at",
                    ):
                        self.assertNotIn(forbidden, raw)

    def test_valid_cardinality_rejects_two_new_executions(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            clock = FakeClock()
            http = GateHttp(self._payload(), duplicate=True)
            with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
                M.gate2(
                    config(), snapshot_path, root / "gate2.json", backend, http,
                    poll_timeout=10,
                    poll_interval=1, now=lambda: FIXED_NOW, clock=clock, sleep=clock.sleep,
                )
            self.assertEqual(http.current_workflow, workflow())

    def test_negative_cardinality_rejects_any_new_execution(self):
        with workspace_tempdir() as directory:
            root = Path(directory)
            snapshot_path, backend = create_snapshot(root)
            clock = FakeClock()
            http = GateHttp(self._payload(), negative_execution=True)
            with self.assertRaisesRegex(M.Refusal, "Workflow recovery was proven"):
                M.gate2(
                    config(), snapshot_path, root / "gate2.json", backend, http,
                    poll_timeout=10,
                    poll_interval=1, now=lambda: FIXED_NOW, clock=clock, sleep=clock.sleep,
                )
            self.assertEqual(http.current_workflow, workflow())


if __name__ == "__main__":
    unittest.main()
