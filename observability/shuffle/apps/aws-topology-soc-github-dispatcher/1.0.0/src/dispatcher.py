"""Fixed-target GitHub Actions dispatcher for the SOC containment workflow."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable


API_VERSION = "2026-03-10"
REPOSITORY = "Unoh03/Uns-DVWA"
WORKFLOW = "soc-contain-dvwa.yml"
REF = "main"
DISPATCH_URL = (
    "https://api.github.com/repos/Unoh03/Uns-DVWA/actions/workflows/"
    "soc-contain-dvwa.yml/dispatches"
)
RUN_API_PREFIX = "https://api.github.com/repos/Unoh03/Uns-DVWA/actions/runs/"
RUN_HTML_PREFIX = "https://github.com/Unoh03/Uns-DVWA/actions/runs/"
TAKE_ID_PATTERN = re.compile(
    r"^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$"
)
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
TOKEN_PATTERN = re.compile(r"^github_pat_[A-Za-z0-9_]{20,500}$")


class DispatchError(ValueError):
    """The fixed dispatch contract was rejected before or during GitHub access."""


def _require_fullmatch(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DispatchError(label)
    return value


def _read_json_response(response: Any) -> dict[str, Any]:
    data = response.read(65537)
    if len(data) > 65536:
        raise DispatchError("github_response_too_large")
    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DispatchError("github_response_invalid_json") from error
    if not isinstance(decoded, dict):
        raise DispatchError("github_response_not_object")
    return decoded


def dispatch_containment(
    github_token: Any,
    take_id: Any,
    scenario_id: Any,
    rule_id: Any,
    alert_body_sha256: Any,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    """Call one fixed workflow endpoint and return no credential or response body."""

    try:
        token = _require_fullmatch(github_token, TOKEN_PATTERN, "github_token")
        take = _require_fullmatch(take_id, TAKE_ID_PATTERN, "take_id")
        if scenario_id != "CAPITAL-ONE":
            raise DispatchError("scenario_id")
        if rule_id != "100103":
            raise DispatchError("rule_id")
        body_hash = _require_fullmatch(
            alert_body_sha256, SHA256_PATTERN, "alert_body_sha256"
        )

        body = {
            "ref": REF,
            "return_run_details": True,
            "inputs": {
                "take_id": take,
                "scenario_id": "CAPITAL-ONE",
                "rule_id": "100103",
                "alert_body_sha256": body_hash,
            },
        }
        request = urllib.request.Request(
            DISPATCH_URL,
            data=json.dumps(
                body, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "aws-topology-soc-dispatcher/1.0",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        with opener(request, timeout=30) as response:
            status = int(response.getcode())
            if status != 200:
                raise DispatchError(f"github_http_{status}")
            result = _read_json_response(response)

        run_id = result.get("workflow_run_id")
        if type(run_id) is not int or run_id <= 0:
            raise DispatchError("github_workflow_run_id")
        expected_api_url = f"{RUN_API_PREFIX}{run_id}"
        expected_html_url = f"{RUN_HTML_PREFIX}{run_id}"
        if result.get("run_url") != expected_api_url:
            raise DispatchError("github_run_url")
        if result.get("html_url") != expected_html_url:
            raise DispatchError("github_html_url")

        return {
            "success": True,
            "status": "DISPATCHED",
            "workflow_run_id": run_id,
            "take_id": take,
            "scenario_id": "CAPITAL-ONE",
            "rule_id": "100103",
            "alert_body_sha256": body_hash,
        }
    except urllib.error.HTTPError as error:
        try:
            return {
                "success": False,
                "status": "RESPONSE_FAILED",
                "reason_code": f"github_http_{int(error.code)}",
            }
        finally:
            error.close()
    except (urllib.error.URLError, TimeoutError):
        return {
            "success": False,
            "status": "RESPONSE_FAILED",
            "reason_code": "github_transport_error",
        }
    except DispatchError as error:
        reason = str(error)
        if re.fullmatch(r"[a-z0-9_]{1,64}", reason) is None:
            reason = "dispatch_contract"
        return {
            "success": False,
            "status": "RESPONSE_FAILED",
            "reason_code": reason,
        }
    except Exception:
        return {
            "success": False,
            "status": "RESPONSE_FAILED",
            "reason_code": "dispatcher_internal_error",
        }
