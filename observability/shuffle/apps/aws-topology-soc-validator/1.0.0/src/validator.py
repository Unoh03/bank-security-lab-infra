"""Strict, side-effect-free validator for the SOC sanitized alert contract."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime
from typing import Any


TOP_LEVEL_KEYS = {
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
}
RULE_KEYS = {"id", "level"}
INCIDENT_KEYS = {
    "take_id",
    "event_id",
    "wazuh_alert_id",
    "event_time_utc",
    "result",
    "route",
}
INTEGRITY_KEYS = {"raw_message_sha256", "body_sha256"}

UTC_MILLISECONDS_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
ACCOUNT_ALIAS_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
AWS_ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]$")
SCENARIO_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
RULE_ID_PATTERN = re.compile(r"^[0-9]{6}$")
TAKE_ID_PATTERN = re.compile(
    r"^capital-one-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$"
)
EVENT_ID_PATTERN = re.compile(r"^cwl:[0-9]{12}:[!-~]{1,480}$")
WAZUH_ALERT_ID_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class ValidationError(ValueError):
    """A payload violated the fixed, non-secret alert schema."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate_json_key")
        result[key] = value
    return result


def _parse_input(input_data: Any) -> dict[str, Any]:
    if isinstance(input_data, str):
        encoded = input_data.encode("utf-8")
        if len(encoded) > 65536:
            raise ValidationError("payload_too_large")
        try:
            input_data = json.loads(
                input_data,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    ValidationError("non_finite_number")
                ),
            )
        except ValidationError:
            raise
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValidationError("invalid_json") from error
    if not isinstance(input_data, dict):
        raise ValidationError("payload_not_object")
    return input_data


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label}_not_object")
    if set(value) != expected:
        raise ValidationError(f"{label}_keys")
    return value


def _require_string(
    value: Any,
    pattern: re.Pattern[str],
    label: str,
    *,
    minimum: int = 1,
    maximum: int = 512,
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or pattern.fullmatch(value) is None
    ):
        raise ValidationError(label)
    return value


def _require_utc_milliseconds(value: Any, label: str) -> str:
    text = _require_string(value, UTC_MILLISECONDS_PATTERN, label, maximum=24)
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise ValidationError(label) from error
    return text


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def validate_sanitized_alert(input_data: Any) -> dict[str, Any]:
    """Return only fields needed for fixed Shuffle branches; never echo input."""

    try:
        payload = _require_exact_keys(_parse_input(input_data), TOP_LEVEL_KEYS, "root")
        rule = _require_exact_keys(payload["rule"], RULE_KEYS, "rule")
        incident = _require_exact_keys(
            payload["incident"], INCIDENT_KEYS, "incident"
        )
        integrity = _require_exact_keys(
            payload["integrity"], INTEGRITY_KEYS, "integrity"
        )

        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise ValidationError("schema_version")
        if payload["source_system"] != "wazuh":
            raise ValidationError("source_system")

        sent_at = _require_utc_milliseconds(payload["sent_at_utc"], "sent_at_utc")
        account_alias = _require_string(
            payload["account_alias"], ACCOUNT_ALIAS_PATTERN, "account_alias", maximum=32
        )
        aws_account_id = _require_string(
            payload["aws_account_id"], AWS_ACCOUNT_ID_PATTERN, "aws_account_id", maximum=12
        )
        aws_region = _require_string(
            payload["aws_region"], AWS_REGION_PATTERN, "aws_region", maximum=32
        )
        scenario_id = _require_string(
            payload["scenario_id"], SCENARIO_ID_PATTERN, "scenario_id", maximum=64
        )
        rule_id = _require_string(rule["id"], RULE_ID_PATTERN, "rule_id", maximum=6)
        if type(rule["level"]) is not int or not 0 <= rule["level"] <= 15:
            raise ValidationError("rule_level")

        take_id = _require_string(
            incident["take_id"], TAKE_ID_PATTERN, "take_id", maximum=64
        )
        event_id = _require_string(
            incident["event_id"], EVENT_ID_PATTERN, "event_id", minimum=24, maximum=512
        )
        if not event_id.startswith(f"cwl:{aws_account_id}:"):
            raise ValidationError("event_id_account_mismatch")
        wazuh_alert_id = _require_string(
            incident["wazuh_alert_id"],
            WAZUH_ALERT_ID_PATTERN,
            "wazuh_alert_id",
            maximum=128,
        )
        event_time = _require_utc_milliseconds(
            incident["event_time_utc"], "event_time_utc"
        )
        if incident["result"] != "succeeded":
            raise ValidationError("incident_result")
        if incident["route"] != "/vulnerabilities/exec/":
            raise ValidationError("incident_route")

        raw_hash = _require_string(
            integrity["raw_message_sha256"], SHA256_PATTERN, "raw_message_sha256", maximum=64
        )
        supplied_body_hash = _require_string(
            integrity["body_sha256"], SHA256_PATTERN, "body_sha256", maximum=64
        )
        canonical_payload = json.loads(json.dumps(payload, ensure_ascii=False))
        del canonical_payload["integrity"]["body_sha256"]
        expected_body_hash = hashlib.sha256(_canonical_json(canonical_payload)).hexdigest()
        if not hmac.compare_digest(supplied_body_hash, expected_body_hash):
            raise ValidationError("body_sha256_mismatch")

        return {
            "valid": True,
            "rejection": "",
            "schema_version": 1,
            "source_system": "wazuh",
            "sent_at_utc": sent_at,
            "account_alias": account_alias,
            "aws_account_id": aws_account_id,
            "aws_region": aws_region,
            "scenario_id": scenario_id,
            "rule_id": rule_id,
            "rule_level": rule["level"],
            "take_id": take_id,
            "event_id": event_id,
            "wazuh_alert_id": wazuh_alert_id,
            "event_time_utc": event_time,
            "raw_message_sha256": raw_hash,
            "body_sha256": supplied_body_hash,
        }
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        reason = str(error)
        if not re.fullmatch(r"[a-z0-9_]{1,64}", reason):
            reason = "invalid_payload"
        return {
            "valid": False,
            "rejection": "REJECTED_SCHEMA",
            "reason_code": reason,
        }
