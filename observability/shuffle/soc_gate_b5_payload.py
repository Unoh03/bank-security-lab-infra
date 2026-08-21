#!/usr/bin/env python3
"""Build deterministic, non-secret Gate B5 v2 payloads.

The optional control identifier is test metadata only and is deliberately
never inserted into the CloudTrail sanitized Alert payload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from typing import Any


CASES = (
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
)

# Every negative case is a single, explicit mutation of the fixed input
# contract.  Keeping this table next to the generator lets the unit tests
# compare the generated value with the contract rather than merely checking
# that JSON was produced.
CASE_MUTATIONS = {
    "valid": None,
    "wrong-account": ("aws_account_id", "000000000000"),
    "wrong-scenario": ("scenario_id", "OTHER-SCENARIO"),
    "wrong-rule": ("rule.id", "100999"),
    "wrong-role": ("incident.principal_role_name", "other-role"),
    "wrong-bucket": ("incident.bucket_alias", "other-application-data"),
    "wrong-key": ("incident.object_key", "validation/other.csv"),
    "wrong-event-source": ("incident.event_source", "ec2.amazonaws.com"),
    "wrong-event-name": ("incident.event_name", "PutObject"),
    "wrong-result": ("incident.result", "failed"),
    "wrong-body-hash": ("integrity.body_sha256", "0" * 64),
}


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _uuid_from_digest(digest: str) -> str:
    raw = bytearray.fromhex(digest[:32])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _refresh_body_hash(payload: dict[str, Any]) -> None:
    integrity = payload["integrity"]
    integrity.pop("body_sha256", None)
    integrity["body_sha256"] = hashlib.sha256(canonical_json(payload)).hexdigest()


def _base_payload(nonce: str) -> dict[str, Any]:
    digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    return {
        "schema_version": 2,
        "source_system": "wazuh",
        "sent_at_utc": "2026-08-18T00:00:01.000Z",
        "account_alias": "primary-lab",
        "aws_account_id": "433048100798",
        "aws_region": "ap-northeast-2",
        "scenario_id": "CAPITAL-ONE",
        "rule": {
            "id": "100104",
            "level": 12,
            "role": "high_confidence_s3_access",
        },
        "incident": {
            "cloudtrail_event_id": _uuid_from_digest(digest),
            "wazuh_alert_id": f"{int(digest[:12], 16)}.{int(digest[12:18], 16)}",
            "event_time_utc": "2026-08-18T00:00:00.000Z",
            "event_source": "s3.amazonaws.com",
            "event_name": "GetObject",
            "principal_role_name": "aws-topology-primary-karpenter-node",
            "principal_session_id_sha256": digest,
            "bucket_alias": "primary-application-data",
            "object_key": "validation/capital-one-demo.csv",
            "result": "success",
        },
        "integrity": {"raw_message_sha256": digest},
    }


def build_payload(
    control_id: str | None, nonce: str, case: str = "valid"
) -> dict[str, Any]:
    """Return a v2 payload; ``control_id`` is intentionally not serialized."""

    if case not in CASES:
        raise ValueError("unsupported Gate B5 payload case")
    # Keep control metadata outside the Alert derived from CloudTrail.
    _ = control_id
    payload = _base_payload(nonce)
    incident = payload["incident"]
    if case == "wrong-account":
        payload["aws_account_id"] = "000000000000"
    elif case == "wrong-scenario":
        payload["scenario_id"] = "OTHER-SCENARIO"
    elif case == "wrong-rule":
        payload["rule"]["id"] = "100999"
    elif case == "wrong-role":
        incident["principal_role_name"] = "other-role"
    elif case == "wrong-bucket":
        incident["bucket_alias"] = "other-application-data"
    elif case == "wrong-key":
        incident["object_key"] = "validation/other.csv"
    elif case == "wrong-event-source":
        incident["event_source"] = "ec2.amazonaws.com"
    elif case == "wrong-event-name":
        incident["event_name"] = "PutObject"
    elif case == "wrong-result":
        incident["result"] = "failed"

    if case == "wrong-body-hash":
        payload["integrity"]["body_sha256"] = "0" * 64
    else:
        _refresh_body_hash(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--control-id",
        required=True,
        help="Control-only identifier; never emitted in the payload.",
    )
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--case", choices=CASES, default="valid")
    args = parser.parse_args()
    payload = build_payload(args.control_id, args.nonce, args.case)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
