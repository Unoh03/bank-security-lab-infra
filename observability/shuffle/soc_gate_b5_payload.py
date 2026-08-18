#!/usr/bin/env python3
"""Build deterministic, non-secret Gate B5 webhook payloads from the real sanitizer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SANITIZER_PATH = (
    ROOT / "observability" / "wazuh" / "integrations" / "custom-shuffle-soc"
)
LOADER = importlib.machinery.SourceFileLoader("soc_sanitizer", str(SANITIZER_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
if SPEC is None:
    raise RuntimeError("the Wazuh sanitizer module could not be loaded")
SANITIZER = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(SANITIZER)

CASES = (
    "valid",
    "wrong-account",
    "wrong-scenario",
    "wrong-rule",
    "wrong-take",
    "wrong-body-hash",
)


def _source_alert(take_id: str, nonce: str) -> dict[str, Any]:
    digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    numeric = int(digest[:12], 16)
    return {
        "id": f"{numeric}.{int(digest[12:18], 16)}",
        "timestamp": "2026-08-18T00:00:00.000+0000",
        "rule": {"id": "100103", "level": 10},
        "data": {
            "schema_version": 1,
            "event_id": (
                "cwl:433048100798:/aws/eks/aws-topology-primary/"
                f"application:gate-b5:{digest[:24]}"
            ),
            "source": "dvwa",
            "aws_account_id": "433048100798",
            "aws_region": "ap-northeast-2",
            "event_time": "2026-08-18T00:00:00.000Z",
            "transport": "push",
            "raw_message_sha256": digest,
            "payload": {
                "normalized": True,
                "take_id": take_id,
                "event_type": "command.execution",
                "result": "succeeded",
                "route": "/vulnerabilities/exec/",
                "context": {
                    "action": "shell_command",
                    "resource": "ec2_imds",
                    "security_level": "low",
                    "status": "output_returned",
                },
            },
        },
    }


def _refresh_body_hash(payload: dict[str, Any]) -> None:
    integrity = payload["integrity"]
    integrity.pop("body_sha256", None)
    integrity["body_sha256"] = hashlib.sha256(
        SANITIZER.canonical_json(payload)
    ).hexdigest()


def build_payload(take_id: str, nonce: str, case: str = "valid") -> dict[str, Any]:
    if case not in CASES:
        raise ValueError("unsupported Gate B5 payload case")
    payload = SANITIZER.build_sanitized_alert(
        _source_alert(take_id, nonce),
        now=datetime(2026, 8, 18, 0, 0, 1, tzinfo=timezone.utc),
    )
    if case == "wrong-account":
        payload["account_alias"] = "other-lab"
        payload["aws_account_id"] = "000000000000"
        payload["incident"]["event_id"] = payload["incident"]["event_id"].replace(
            "cwl:433048100798:", "cwl:000000000000:"
        )
    elif case == "wrong-scenario":
        payload["scenario_id"] = "OTHER-SCENARIO"
    elif case == "wrong-rule":
        payload["rule"]["id"] = "999999"
    elif case == "wrong-take":
        suffix = take_id[-8:]
        replacement = ("0" if suffix[0] != "0" else "1") + suffix[1:]
        payload["incident"]["take_id"] = take_id[:-8] + replacement
    if case == "wrong-body-hash":
        payload["integrity"]["body_sha256"] = "0" * 64
    elif case != "valid":
        _refresh_body_hash(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--take-id", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--case", choices=CASES, default="valid")
    args = parser.parse_args()
    payload = build_payload(args.take_id, args.nonce, args.case)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
