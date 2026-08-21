import hashlib
import json
import re
from datetime import datetime


ROOT_KEYS = (
    "schema_version", "source_system", "sent_at_utc", "account_alias",
    "aws_account_id", "aws_region", "scenario_id", "rule", "incident",
    "integrity",
)
RULE_KEYS = ("id", "level", "role")
INCIDENT_KEYS = (
    "cloudtrail_event_id", "wazuh_alert_id", "event_time_utc",
    "event_source", "event_name", "principal_role_name",
    "principal_session_id_sha256", "bucket_alias", "object_key", "result",
)
INTEGRITY_KEYS = ("raw_message_sha256", "body_sha256")

UTC = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
EVENT_ID = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SHA256 = r"[a-f0-9]{64}"
DEDUPE_KEY = r"CAPITAL-ONE:[0-9]{12}:" + EVENT_ID


def _duplicate_safe_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non_finite_number")


def _parse(value):
    if isinstance(value, str):
        try:
            if len(value.encode("utf-8")) > 65536:
                raise ValueError("payload_too_large")
        except UnicodeError:
            raise ValueError("invalid_json")
        try:
            value = json.loads(value, object_pairs_hook=_duplicate_safe_object, parse_constant=_reject_constant)
        except RecursionError:
            raise ValueError("invalid_json")
        except ValueError as error:
            reason = str(error)
            if reason == "duplicate_json_key" or reason == "non_finite_number":
                raise
            raise ValueError("invalid_json")
    if type(value) is not dict:
        raise ValueError("payload_not_object")
    return value


def _exact(value, keys, label):
    if type(value) is not dict:
        raise ValueError(label + "_not_object")
    if set(value) != set(keys):
        raise ValueError(label + "_keys")
    return value


def _text(value, pattern, label, minimum=1, maximum=512):
    if type(value) is not str:
        raise ValueError(label)
    if len(value) < minimum or len(value) > maximum:
        raise ValueError(label)
    if re.fullmatch(pattern, value) is None:
        raise ValueError(label)
    return value


def _timestamp(value, label):
    value = _text(value, UTC, label, 24, 24)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise ValueError(label)
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _schema_rejection(error):
    reason = str(error)
    if re.fullmatch(r"[a-z0-9_]{1,64}", reason) is None:
        reason = "invalid_payload"
    return {"valid": False, "rejection": "REJECTED_SCHEMA", "reason_code": reason}


def _allowlist_rejection(reason):
    return {"valid": False, "rejection": "REJECTED_ALLOWLIST", "reason_code": reason}


def validate_sanitized_alert(input_data):
    try:
        payload = _exact(_parse(input_data), ROOT_KEYS, "root")
        rule = _exact(payload["rule"], RULE_KEYS, "rule")
        incident = _exact(payload["incident"], INCIDENT_KEYS, "incident")
        integrity = _exact(payload["integrity"], INTEGRITY_KEYS, "integrity")

        if type(payload["schema_version"]) is not int or payload["schema_version"] != 2:
            raise ValueError("schema_version")
        if payload["source_system"] != "wazuh":
            raise ValueError("source_system")

        sent_at = _timestamp(payload["sent_at_utc"], "sent_at_utc")
        account_alias = _text(payload["account_alias"], r"[a-z][a-z0-9-]{2,31}", "account_alias", 3, 32)
        account_id = _text(payload["aws_account_id"], r"[0-9]{12}", "aws_account_id", 12, 12)
        region = _text(payload["aws_region"], r"[a-z]{2}-[a-z]+-[0-9]", "aws_region", 3, 32)
        scenario = _text(payload["scenario_id"], r"[A-Z][A-Z0-9-]{2,63}", "scenario_id", 3, 64)
        rule_id = _text(rule["id"], r"[0-9]{6}", "rule_id", 6, 6)
        if type(rule["level"]) is not int or rule["level"] < 0 or rule["level"] > 15:
            raise ValueError("rule_level")
        rule_role = _text(rule["role"], r"[a-z][a-z0-9_]{2,63}", "rule_role", 3, 64)

        event_id = _text(incident["cloudtrail_event_id"], EVENT_ID, "cloudtrail_event_id", 36, 36)
        alert_id = _text(incident["wazuh_alert_id"], r"[0-9]+\.[0-9]+", "wazuh_alert_id", 3, 128)
        event_time = _timestamp(incident["event_time_utc"], "event_time_utc")
        event_source = _text(incident["event_source"], r"[a-z0-9.-]{3,128}", "event_source", 3, 128)
        event_name = _text(incident["event_name"], r"[A-Za-z0-9]{1,64}", "event_name", 1, 64)
        principal_role = _text(incident["principal_role_name"], r"[A-Za-z0-9+=,.@_-]{1,128}", "principal_role_name", 1, 128)
        session_hash = _text(incident["principal_session_id_sha256"], SHA256, "principal_session_id_sha256", 64, 64)
        bucket = _text(incident["bucket_alias"], r"[a-z][a-z0-9-]{2,63}", "bucket_alias", 3, 64)
        object_key = _text(incident["object_key"], r"validation/[A-Za-z0-9._/-]{1,512}", "object_key", 12, 512)
        result = _text(incident["result"], r"[a-z]+", "incident_result", 1, 32)
        raw_hash = _text(integrity["raw_message_sha256"], SHA256, "raw_message_sha256", 64, 64)
        body_hash = _text(integrity["body_sha256"], SHA256, "body_sha256", 64, 64)

        covered = dict(payload)
        covered["integrity"] = dict(integrity)
        del covered["integrity"]["body_sha256"]
        expected_hash = hashlib.sha256(_canonical(covered)).hexdigest()
        if body_hash != expected_hash:
            raise ValueError("body_sha256_mismatch")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return _schema_rejection(error)

    fixed = (
        (account_alias, "primary-lab", "account_alias"),
        (account_id, "433048100798", "aws_account_id"),
        (region, "ap-northeast-2", "aws_region"),
        (scenario, "CAPITAL-ONE", "scenario_id"),
        (rule_id, "100104", "rule_id"),
        (rule["level"], 12, "rule_level"),
        (rule_role, "high_confidence_s3_access", "rule_role"),
        (event_source, "s3.amazonaws.com", "event_source"),
        (event_name, "GetObject", "event_name"),
        (principal_role, "aws-topology-primary-karpenter-node", "principal_role_name"),
        (bucket, "primary-application-data", "bucket_alias"),
        (object_key, "validation/capital-one-demo.csv", "object_key"),
        (result, "success", "incident_result"),
    )
    for actual, expected, reason in fixed:
        if actual != expected:
            return _allowlist_rejection(reason)

    output = {"valid": True, "rejection": "", "active_take_in_payload": False}
    for name in (
        "schema_version", "source_system", "sent_at_utc", "account_alias",
        "aws_account_id", "aws_region", "scenario_id",
    ):
        output[name] = payload[name]
    output["rule_id"] = rule_id
    output["rule_level"] = rule["level"]
    output["rule_role"] = rule_role
    for name in INCIDENT_KEYS:
        output[name] = incident[name]
    output["raw_message_sha256"] = raw_hash
    output["body_sha256"] = body_hash
    output["dedupe_key"] = "CAPITAL-ONE:" + account_id + ":" + event_id
    return output


def _claim_failure():
    return {"valid": False, "existed": True, "reason_code": "dedupe_claim_invalid"}


def classify_dedupe_claim(claim_result, expected_key):
    try:
        key = _text(expected_key, DEDUPE_KEY, "expected_key", 61, 61)
        claim = _exact(_parse(claim_result), ("success", "keys_existed"), "claim_result")
        if type(claim["success"]) is not bool or claim["success"] is not True:
            raise ValueError("claim_success")
        entries = claim["keys_existed"]
        if type(entries) is not list or len(entries) != 1:
            raise ValueError("keys_existed")
        entry = _exact(entries[0], ("key", "existed"), "keys_existed_entry")
        if entry["key"] != key:
            raise ValueError("dedupe_key")
        if type(entry["existed"]) is not bool:
            raise ValueError("existed")
        return {"valid": True, "existed": entry["existed"], "reason_code": ""}
    except (KeyError, TypeError, ValueError, OverflowError):
        return _claim_failure()
