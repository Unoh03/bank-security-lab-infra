"""Fail-closed Rule 100110/100111 validator and fixed workflow dispatcher."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable


API_VERSION = "2026-03-10"
DISPATCH_URL = (
    "https://api.github.com/repos/Unoh03/Uns-DVWA/actions/workflows/"
    "soc-contain-dvwa.yml/dispatches"
)
HARDEN_DISPATCH_URL = (
    "https://api.github.com/repos/Unoh03/Uns-DVWA/actions/workflows/"
    "soc-harden-dvwa.yml/dispatches"
)
RUN_API_PREFIX = "https://api.github.com/repos/Unoh03/Uns-DVWA/actions/runs/"
RUN_HTML_PREFIX = "https://github.com/Unoh03/Uns-DVWA/actions/runs/"
TOKEN_PATTERN = re.compile(r"^github_pat_[A-Za-z0-9_]{20,500}$")
TAKE_ID_PATTERN = re.compile(
    r"^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$"
)
POD_NAME_PATTERN = re.compile(r"^dvwa-[a-z0-9]{8,16}-[a-z0-9]{5}$")
POD_UID_PATTERN = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
ALERT_ID_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")
UTC_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
ROOT_KEYS = (
    "schema_version",
    "source_system",
    "sent_at_utc",
    "account_alias",
    "aws_account_id",
    "aws_region",
    "scenario_id",
    "rule",
    "incident",
    "integrity",
)
RULE_KEYS = ("id", "level", "role")
INCIDENT_KEYS = (
    "wazuh_alert_id",
    "event_time_utc",
    "event_id_sha256",
    "take_id",
    "pod_name",
    "pod_uid",
    "event_type",
    "stage",
    "status",
    "route",
    "result",
)
INTEGRITY_KEYS = ("raw_message_sha256", "body_sha256")
CONFIRMED_S3_KEYS = (
    "rule_id",
    "event_time_utc",
    "wazuh_alert_id",
    "event_id_sha256",
    "raw_message_sha256",
)


class ContractError(ValueError):
    """The fixed validation or dispatch contract was rejected."""


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ContractError("non_finite_number")


def _parse(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as error:
            raise ContractError("invalid_json") from error
        if len(encoded) > 65536:
            raise ContractError("payload_too_large")
        try:
            value = json.loads(
                value,
                object_pairs_hook=_duplicate_safe_object,
                parse_constant=_reject_constant,
            )
        except (ValueError, RecursionError) as error:
            if isinstance(error, ContractError):
                raise
            raise ContractError("invalid_json") from error
    if type(value) is not dict:
        raise ContractError("payload_not_object")
    return value


def _exact(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(keys):
        raise ContractError(label + "_keys")
    return value


def _text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(label)
    return value


def _timestamp(value: Any, label: str) -> datetime:
    text = _text(value, UTC_PATTERN, label)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ContractError(label) from error


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def validate_rule_100110_payload(
    input_data: Any, now: datetime | None = None
) -> dict[str, str]:
    payload = _exact(_parse(input_data), ROOT_KEYS, "root")
    rule = _exact(payload["rule"], RULE_KEYS, "rule")
    incident = _exact(payload["incident"], INCIDENT_KEYS, "incident")
    integrity = _exact(payload["integrity"], INTEGRITY_KEYS, "integrity")

    fixed = (
        (payload["schema_version"], 3, "schema_version"),
        (payload["source_system"], "wazuh", "source_system"),
        (payload["account_alias"], "primary-lab", "account_alias"),
        (payload["aws_account_id"], "433048100798", "aws_account_id"),
        (payload["aws_region"], "ap-northeast-2", "aws_region"),
        (payload["scenario_id"], "CAPITAL-ONE", "scenario_id"),
        (rule["id"], "100110", "rule_id"),
        (rule["level"], 12, "rule_level"),
        (rule["role"], "imds_credential_access", "rule_role"),
        (incident["event_type"], "command.execution", "event_type"),
        (incident["stage"], "imds_credential_fetch", "stage"),
        (incident["status"], "output_returned", "status"),
        (incident["route"], "/vulnerabilities/exec/", "route"),
        (incident["result"], "succeeded", "result"),
    )
    for actual, expected, label in fixed:
        if type(actual) is not type(expected) or actual != expected:
            raise ContractError(label)

    _text(incident["wazuh_alert_id"], ALERT_ID_PATTERN, "wazuh_alert_id")
    event_hash = _text(
        incident["event_id_sha256"], SHA256_PATTERN, "event_id_sha256"
    )
    take_id = _text(incident["take_id"], TAKE_ID_PATTERN, "take_id")
    pod_name = _text(incident["pod_name"], POD_NAME_PATTERN, "pod_name")
    pod_uid = _text(incident["pod_uid"], POD_UID_PATTERN, "pod_uid")
    _text(integrity["raw_message_sha256"], SHA256_PATTERN, "raw_message_sha256")
    body_hash = _text(
        integrity["body_sha256"], SHA256_PATTERN, "body_sha256"
    )

    covered = dict(payload)
    covered["integrity"] = dict(integrity)
    del covered["integrity"]["body_sha256"]
    if hashlib.sha256(_canonical(covered)).hexdigest() != body_hash:
        raise ContractError("body_sha256_mismatch")

    sent_at = _timestamp(payload["sent_at_utc"], "sent_at_utc")
    event_time = _timestamp(incident["event_time_utc"], "event_time_utc")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ContractError("now_not_aware")
    current = current.astimezone(timezone.utc)
    if event_time > current or sent_at > current:
        raise ContractError("future_timestamp")
    if (current - event_time).total_seconds() > 180:
        raise ContractError("event_stale")
    if (current - sent_at).total_seconds() > 180:
        raise ContractError("delivery_stale")
    if sent_at < event_time or (sent_at - event_time).total_seconds() > 120:
        raise ContractError("delivery_latency")

    return {
        "take_id": take_id,
        "scenario_id": "CAPITAL-ONE",
        "rule_id": "100110",
        "event_id_sha256": event_hash,
        "pod_name": pod_name,
        "pod_uid": pod_uid,
        "alert_body_sha256": body_hash,
    }


def validate_rule_100111_payload(
    input_data: Any, now: datetime | None = None
) -> dict[str, str]:
    payload = _exact(_parse(input_data), CONFIRMED_S3_KEYS, "root")
    if payload["rule_id"] != "100111":
        raise ContractError("rule_id")
    _text(payload["wazuh_alert_id"], ALERT_ID_PATTERN, "wazuh_alert_id")
    event_hash = _text(
        payload["event_id_sha256"], SHA256_PATTERN, "event_id_sha256"
    )
    _text(
        payload["raw_message_sha256"], SHA256_PATTERN, "raw_message_sha256"
    )
    body_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    event_time = _timestamp(payload["event_time_utc"], "event_time_utc")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ContractError("now_not_aware")
    current = current.astimezone(timezone.utc)
    if event_time > current:
        raise ContractError("future_timestamp")
    if (current - event_time).total_seconds() > 1200:
        raise ContractError("event_stale")

    return {
        "rule_id": "100111",
        "event_id_sha256": event_hash,
        "alert_body_sha256": body_hash,
    }


def _safe_reason(error: Exception) -> str:
    reason = str(error)
    if re.fullmatch(r"[a-z0-9_]{1,64}", reason) is None:
        return "dispatch_contract"
    return reason


def dispatch_rule_100110(
    github_token: Any,
    input_data: Any,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        token = _text(github_token, TOKEN_PATTERN, "github_token")
        parsed = _parse(input_data)
        rule = parsed.get("rule")
        rule_id = rule.get("id") if type(rule) is dict else parsed.get("rule_id")
        if rule_id == "100110":
            inputs = validate_rule_100110_payload(parsed, now=now)
            dispatch_url = DISPATCH_URL
        elif rule_id == "100111":
            inputs = validate_rule_100111_payload(parsed, now=now)
            dispatch_url = HARDEN_DISPATCH_URL
        else:
            raise ContractError("rule_id")
        body = {
            "ref": "main",
            "return_run_details": True,
            "inputs": inputs,
        }
        request = urllib.request.Request(
            dispatch_url,
            data=json.dumps(
                body, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "aws-topology-soc-auto-response/1.0",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        with opener(request, timeout=30) as response:
            status = int(response.getcode())
            if status != 200:
                raise ContractError(f"github_http_{status}")
            data = response.read(65537)
            if len(data) > 65536:
                raise ContractError("github_response_too_large")
        try:
            result = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ContractError("github_response_invalid_json") from error
        if not isinstance(result, dict):
            raise ContractError("github_response_not_object")
        run_id = result.get("workflow_run_id")
        if type(run_id) is not int or run_id <= 0:
            raise ContractError("github_workflow_run_id")
        if result.get("run_url") != f"{RUN_API_PREFIX}{run_id}":
            raise ContractError("github_run_url")
        if result.get("html_url") != f"{RUN_HTML_PREFIX}{run_id}":
            raise ContractError("github_html_url")
        response = {
            "success": True,
            "status": "DISPATCHED",
            "workflow_run_id": run_id,
            "rule_id": rule_id,
            "event_id_sha256": inputs["event_id_sha256"],
            "alert_body_sha256": inputs["alert_body_sha256"],
        }
        if rule_id == "100110":
            response.update(
                {
                    "take_id": inputs["take_id"],
                    "pod_name": inputs["pod_name"],
                    "pod_uid": inputs["pod_uid"],
                }
            )
        return response
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
    except ContractError as error:
        return {
            "success": False,
            "status": "RESPONSE_FAILED",
            "reason_code": _safe_reason(error),
        }
    except Exception:
        return {
            "success": False,
            "status": "RESPONSE_FAILED",
            "reason_code": "dispatcher_internal_error",
        }
