"""Harmless local-module canary functions."""


def validate_sanitized_alert(input_data):
    return {"valid": False, "rejection": "CANARY"}


def classify_dedupe_claim(claim_result, expected_key):
    return {"valid": False, "existed": True, "reason_code": "CANARY"}
