import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "observability"
    / "shuffle"
    / "apps"
    / "aws-topology-soc-github-dispatcher"
    / "1.0.0"
    / "src"
    / "dispatcher.py"
)
API_PATH = MODULE_PATH.parents[1] / "api.yaml"
SPEC = importlib.util.spec_from_file_location("soc_github_dispatcher", MODULE_PATH)
dispatcher = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = dispatcher
SPEC.loader.exec_module(dispatcher)


TOKEN = "github_pat_" + ("a" * 80)
TAKE = "capital-one-20260818T010000Z-deadbeef"
HASH = "b" * 64


class FakeResponse:
    def __init__(self, payload, status=200):
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


class DispatcherTests(unittest.TestCase):
    def test_dispatch_is_fixed_and_sanitized(self):
        observed = {}

        def opener(request, timeout):
            observed["url"] = request.full_url
            observed["method"] = request.get_method()
            observed["timeout"] = timeout
            observed["headers"] = dict(request.header_items())
            observed["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(
                {
                    "workflow_run_id": 12345,
                    "run_url": dispatcher.RUN_API_PREFIX + "12345",
                    "html_url": dispatcher.RUN_HTML_PREFIX + "12345",
                }
            )

        result = dispatcher.dispatch_containment(
            TOKEN, TAKE, "CAPITAL-ONE", "100103", HASH, opener=opener
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["workflow_run_id"], 12345)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(observed["url"], dispatcher.DISPATCH_URL)
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["timeout"], 30)
        self.assertEqual(observed["body"]["ref"], "main")
        self.assertIs(observed["body"]["return_run_details"], True)
        self.assertEqual(
            set(observed["body"]),
            {"ref", "return_run_details", "inputs"},
        )
        self.assertEqual(
            set(observed["body"]["inputs"]),
            {"take_id", "scenario_id", "rule_id", "alert_body_sha256"},
        )
        self.assertEqual(observed["headers"]["Authorization"], f"Bearer {TOKEN}")

    def test_rejects_wrong_allowlist_before_network(self):
        def never(*_args, **_kwargs):
            self.fail("network must not run for rejected input")

        for scenario, rule in (("OTHER", "100103"), ("CAPITAL-ONE", "100102")):
            result = dispatcher.dispatch_containment(
                TOKEN, TAKE, scenario, rule, HASH, opener=never
            )
            self.assertFalse(result["success"])

    def test_rejects_malformed_take_and_hash_before_network(self):
        def never(*_args, **_kwargs):
            self.fail("network must not run for rejected input")

        self.assertFalse(
            dispatcher.dispatch_containment(
                TOKEN, "bad", "CAPITAL-ONE", "100103", HASH, opener=never
            )["success"]
        )
        self.assertFalse(
            dispatcher.dispatch_containment(
                TOKEN, TAKE, "CAPITAL-ONE", "100103", "BAD", opener=never
            )["success"]
        )

    def test_http_failure_does_not_echo_secret_or_body(self):
        def opener(request, timeout):
            self.assertEqual(timeout, 30)
            raise urllib.error.HTTPError(
                request.full_url, 403, "Forbidden", {}, io.BytesIO(b"secret body")
            )

        result = dispatcher.dispatch_containment(
            TOKEN, TAKE, "CAPITAL-ONE", "100103", HASH, opener=opener
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
                    "html_url": dispatcher.RUN_HTML_PREFIX + "12345",
                }
            )

        result = dispatcher.dispatch_containment(
            TOKEN, TAKE, "CAPITAL-ONE", "100103", HASH, opener=opener
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["reason_code"], "github_run_url")

    def test_unexpected_exception_cannot_echo_token(self):
        def opener(_request, timeout):
            self.assertEqual(timeout, 30)
            raise RuntimeError(TOKEN)

        result = dispatcher.dispatch_containment(
            TOKEN, TAKE, "CAPITAL-ONE", "100103", HASH, opener=opener
        )
        self.assertEqual(result["reason_code"], "dispatcher_internal_error")
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_classic_pat_shape_is_rejected(self):
        result = dispatcher.dispatch_containment(
            "ghp_" + ("a" * 40),
            TAKE,
            "CAPITAL-ONE",
            "100103",
            HASH,
            opener=lambda *_args, **_kwargs: self.fail("network must not run"),
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["reason_code"], "github_token")

    def test_shuffle_api_contract_uses_serialized_string_output(self):
        api = API_PATH.read_text(encoding="utf-8")
        self.assertIn("name: dispatch_containment", api)
        self.assertNotIn("type: object", api)


if __name__ == "__main__":
    unittest.main()
