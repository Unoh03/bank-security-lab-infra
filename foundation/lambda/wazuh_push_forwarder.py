"""Forward approved CloudWatch Logs events to the local Wazuh shadow queue."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3


MAX_BATCH_ENTRIES = 10
MAX_MESSAGE_BYTES = 240 * 1024
SAFE_PAYLOAD_FIELDS = (
    "timestamp",
    "event_type",
    "result",
    "user_id",
    "source_ip",
    "route",
    "request_id",
    "request_method",
    "request_path",
    "take_id",
    "training_marker",
)
SAFE_CONTEXT_FIELDS = (
    "action",
    "from",
    "http_method",
    "reason",
    "required",
    "resource",
    "security_level",
    "status",
    "to",
    "validation",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _event_time(timestamp_ms: int) -> str:
    return datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _decode_cloudwatch_payload(encoded_data: str) -> dict[str, Any]:
    compressed = base64.b64decode(encoded_data, validate=True)
    decoded = gzip.decompress(compressed).decode("utf-8")
    payload = json.loads(decoded)
    if not isinstance(payload, dict):
        raise ValueError("CloudWatch Logs subscription payload must be an object")
    return payload


def _parse_message(message: str) -> dict[str, Any]:
    try:
        parsed = json.loads(message)
    except (json.JSONDecodeError, TypeError):
        return {"normalized": False}

    if not isinstance(parsed, dict):
        return {"normalized": False}

    candidate = parsed.get("app_event", parsed)
    if not isinstance(candidate, dict):
        return {"normalized": False}

    normalized = {
        key: candidate[key]
        for key in SAFE_PAYLOAD_FIELDS
        if key in candidate
        and (
            candidate[key] is None
            or isinstance(candidate[key], (str, int, float, bool))
        )
    }
    context = candidate.get("context")
    if isinstance(context, dict):
        safe_context = {
            key: context[key]
            for key in SAFE_CONTEXT_FIELDS
            if key in context
            and (
                context[key] is None
                or isinstance(context[key], (str, int, float, bool))
            )
        }
        if safe_context:
            normalized["context"] = safe_context

    if not normalized:
        return {"normalized": False}
    normalized["normalized"] = True
    return normalized


def _build_envelope(
    *,
    payload: dict[str, Any],
    log_event: dict[str, Any],
    source_name: str,
    schema_version: int,
    aws_region: str,
) -> dict[str, Any]:
    owner = str(payload["owner"])
    log_group = str(payload["logGroup"])
    log_stream = str(payload["logStream"])
    log_event_id = str(log_event["id"])
    raw_message = str(log_event["message"])

    return {
        "schema_version": schema_version,
        "event_id": f"cwl:{owner}:{log_group}:{log_stream}:{log_event_id}",
        "source": source_name,
        "aws_account_id": owner,
        "aws_region": aws_region,
        "event_time": _event_time(int(log_event["timestamp"])),
        "aws_ingested_at": None,
        "aws_forwarded_at": _utc_now(),
        "bridge_received_at": None,
        "transport": "push",
        "source_metadata": {
            "log_group": log_group,
            "log_stream": log_stream,
            "log_event_id": log_event_id,
            "subscription_filters": payload.get("subscriptionFilters", []),
        },
        "raw_message_sha256": hashlib.sha256(
            raw_message.encode("utf-8")
        ).hexdigest(),
        "payload": _parse_message(raw_message),
    }


def _serialize_envelope(envelope: dict[str, Any]) -> str:
    body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    encoded_size = len(body.encode("utf-8"))
    if encoded_size <= MAX_MESSAGE_BYTES:
        return body

    reduced = dict(envelope)
    reduced["payload"] = {
        "oversized": True,
        "original_bytes": encoded_size,
        "raw_message_sha256": envelope["raw_message_sha256"],
    }
    return json.dumps(reduced, ensure_ascii=False, separators=(",", ":"))


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, int]:
    queue_url = os.environ["QUEUE_URL"]
    source_name = os.environ.get("SOURCE_NAME", "dvwa")
    schema_version = int(os.environ.get("SCHEMA_VERSION", "1"))
    expected_account_id = os.environ["EXPECTED_ACCOUNT_ID"]
    expected_log_group = os.environ["EXPECTED_LOG_GROUP"]
    aws_region = os.environ.get("AWS_REGION", "ap-northeast-2")

    encoded_data = event.get("awslogs", {}).get("data")
    if not encoded_data:
        raise ValueError("Missing awslogs.data subscription payload")

    payload = _decode_cloudwatch_payload(encoded_data)
    if payload.get("messageType") == "CONTROL_MESSAGE":
        return {"received": 0, "forwarded": 0}
    if payload.get("messageType") != "DATA_MESSAGE":
        raise ValueError("Unsupported CloudWatch Logs messageType")
    if str(payload.get("owner")) != expected_account_id:
        raise ValueError("CloudWatch Logs owner does not match EXPECTED_ACCOUNT_ID")
    if str(payload.get("logGroup")) != expected_log_group:
        raise ValueError("CloudWatch Logs group does not match EXPECTED_LOG_GROUP")

    log_events = payload.get("logEvents", [])
    if not isinstance(log_events, list):
        raise ValueError("CloudWatch Logs logEvents must be an array")

    bodies = [
        _serialize_envelope(
            _build_envelope(
                payload=payload,
                log_event=log_event,
                source_name=source_name,
                schema_version=schema_version,
                aws_region=aws_region,
            )
        )
        for log_event in log_events
    ]

    sqs = boto3.client("sqs", region_name=aws_region)
    forwarded = 0
    for batch_number, batch in enumerate(_chunks(bodies, MAX_BATCH_ENTRIES)):
        response = sqs.send_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {"Id": f"event-{batch_number:04d}-{index:02d}", "MessageBody": body}
                for index, body in enumerate(batch)
            ],
        )
        failures = response.get("Failed", [])
        if failures:
            failed_ids = ",".join(str(item.get("Id", "unknown")) for item in failures)
            raise RuntimeError(f"SQS rejected subscription entries: {failed_ids}")
        forwarded += len(response.get("Successful", []))

    return {"received": len(log_events), "forwarded": forwarded}
