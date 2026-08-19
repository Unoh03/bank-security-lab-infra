#!/usr/bin/env python3
"""Secret-safe OBSERVE_ONLY Shuffle snapshot, minimal update, rollback, and Gate 2.

This runner deliberately supports only the one-trigger/one-action workflow used to
prove Wazuh -> Shuffle delivery.  It never prints or persists runtime secrets or a
full workflow export.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
DPAPI_TIMEOUT_SECONDS = 30
SERVER_METADATA_DRIFT_PATHS = frozenset(
    {
        "edited",
        "suborg_distribution",
        "validation.changed_at",
        "validation.execution_id",
        "validation.last_valid",
    }
)
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SAFE_SECRET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FORBIDDEN_ACTION = re.compile(
    r"(?i)(validator|datastore|dispatcher|github|argo|containment|execute_python|execute_bash)"
)
FORBIDDEN_EVIDENCE_KEYS = {
    "authorization", "cipher_base64", "api_key", "webhook_url", "webhook_uri",
    "header_value", "cookie", "token", "full_log", "command", "execution_argument",
    "repeat_result", "request_payload", "workflow_export",
}
GATE2_FAILURE_CATEGORIES = frozenset(
    {
        "stage_failure",
        "singleton_set_changed",
        "singleton_final_missing",
        "singleton_request_failed",
        "negative_execution_observed",
        "negative_request_failed",
        "case_deadline",
        "argument_decode_failed",
        "repeat_contract_failed",
        "repeat_contract_timeout",
        "repeat_decode_failed",
        "request_argument_mismatch",
        "argument_repeat_mismatch",
    }
)
SEMANTIC_DIFF_LIMIT = 64
MAX_RESULT_READY_OBSERVATIONS = 4096
REPEAT_NONTERMINAL_STATUSES = frozenset(
    {"", "PENDING", "WAITING", "RUNNING", "EXECUTING"}
)
SEMANTIC_DIFF_KINDS = frozenset(
    {"missing_left", "missing_right", "type_mismatch", "value_mismatch"}
)
SEMANTIC_JSON_TYPES = frozenset(
    {"object", "array", "string", "number", "boolean", "null", "missing"}
)
APPROVED_SEMANTIC_POINTERS = frozenset(
    {
        "/schema_version",
        "/source_system",
        "/sent_at_utc",
        "/account_alias",
        "/aws_account_id",
        "/aws_region",
        "/scenario_id",
        "/rule",
        "/rule/id",
        "/rule/level",
        "/incident",
        "/incident/take_id",
        "/incident/event_id",
        "/incident/wazuh_alert_id",
        "/incident/event_time_utc",
        "/incident/result",
        "/incident/route",
        "/integrity",
        "/integrity/raw_message_sha256",
        "/integrity/body_sha256",
    }
)
PS_DIAGNOSTIC_SENTINEL = "SOC_DPAPI_DIAGNOSTIC_V1"
ALLOWED_PS_EXCEPTION_TYPES = {
    "System.ArgumentException",
    "System.IO.FileNotFoundException",
    "System.Management.Automation.ItemNotFoundException",
    "System.Management.Automation.RuntimeException",
    "System.Security.Cryptography.CryptographicException",
    "System.UnauthorizedAccessException",
}
ALLOWED_PS_FQIDS = {
    "InvalidOperation",
    "MethodInvocationException",
    "Modules_ModuleNotFound,Microsoft.PowerShell.Commands.ImportModuleCommand",
    "PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand",
    "RuntimeException",
    "UnauthorizedAccess",
}
HEADER_NAME = "X-SOC-Webhook-Key"
HEADER_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9.*+?-]{24,128}$")
API_KEY_NAME = "shuffle_api_key"
WEBHOOK_URI_NAME = "shuffle_webhook_url"
WEBHOOK_HEADER_NAME = "shuffle_webhook_header_key"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SECURITY_MODULE = REPOSITORY_ROOT / "automation" / "SocLab.Security.psm1"
SCHEMA_PATH = REPOSITORY_ROOT / "observability" / "shuffle" / "sanitized-alert.schema.json"
SANITIZER_PATH = (
    REPOSITORY_ROOT / "observability" / "wazuh" / "integrations" / "custom-shuffle-soc"
)


class Refusal(RuntimeError):
    """A fail-closed contract refusal safe to show to an operator."""


class RepeatResultNotReady(Refusal):
    """A narrow retry signal for an otherwise valid incomplete Action result."""


class RecoveryFailure(Refusal):
    """A mutation failed and the exact protected original was not proven restored."""


class ReadbackProofFailure(RecoveryFailure):
    """A read-back failed the closed restoration proof without retaining raw data."""

    def __init__(self, *, restored_semantically: bool, full_exact: bool) -> None:
        super().__init__("Workflow read-back proof failed")
        self.restored_semantically = restored_semantically
        self.full_exact = full_exact


class RestoreFailure(RecoveryFailure):
    """A fixed recovery stage failed; only safe booleans and enums are retained."""

    def __init__(
        self,
        stage: str,
        *,
        mutation_attempted: bool,
        restored_semantically: bool = False,
        full_exact: bool = False,
    ) -> None:
        if stage not in {"put", "get", "proof"}:
            stage = "proof"
        super().__init__(f"Workflow restoration failed at stage={stage}")
        self.stage = stage
        self.mutation_attempted = mutation_attempted
        self.restored_semantically = restored_semantically
        self.full_exact = full_exact


class Gate2StageFailure(Refusal):
    """A Gate 2 failure reduced to an allowlisted phase name."""

    def __init__(
        self,
        stage: str,
        category: str = "stage_failure",
        semantic_diagnostic: dict[str, Any] | None = None,
        result_readiness: dict[str, Any] | None = None,
    ) -> None:
        if stage not in {
            "preflight",
            "valid_baseline",
            "valid_post",
            "valid_execution",
            "valid_result_ready",
            "valid_singleton",
            "valid_semantic",
            "wrong_baseline",
            "wrong_post",
            "wrong_observation",
            "missing_baseline",
            "missing_post",
            "missing_observation",
            "evidence_write",
            "unexpected",
        }:
            stage = "unexpected"
        if category not in GATE2_FAILURE_CATEGORIES:
            category = "stage_failure"
        super().__init__(f"Gate 2 failed at stage={stage} category={category}")
        self.stage = stage
        self.category = category
        self.semantic_diagnostic = copy.deepcopy(semantic_diagnostic)
        self.result_readiness = copy.deepcopy(result_readiness)


class Gate2CategoryFailure(Refusal):
    """A fixed, secret-independent Gate 2 failure category."""

    def __init__(
        self,
        category: str,
        semantic_diagnostic: dict[str, Any] | None = None,
        result_readiness: dict[str, Any] | None = None,
    ) -> None:
        if category not in GATE2_FAILURE_CATEGORIES - {"stage_failure"}:
            category = "stage_failure"
        super().__init__(f"Gate 2 category={category}")
        self.category = category
        self.semantic_diagnostic = copy.deepcopy(semantic_diagnostic)
        self.result_readiness = copy.deepcopy(result_readiness)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


_SEMANTIC_MISSING = object()


def _semantic_json_type(value: Any) -> str:
    if value is _SEMANTIC_MISSING:
        return "missing"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    raise Refusal("semantic comparison encountered a non-JSON value")


def _json_pointer_child(parent: str, child: str) -> str:
    escaped = child.replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}"


def semantic_diff_summary(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded value-free diff; unknown JSON pointers are hashed."""
    stack: list[tuple[str, Any, Any]] = [("", left, right)]
    entries: list[dict[str, Any]] = []
    total = 0
    while stack:
        pointer, left_value, right_value = stack.pop()
        left_type = _semantic_json_type(left_value)
        right_type = _semantic_json_type(right_value)
        if left_type == right_type == "object":
            left_keys = set(left_value)
            right_keys = set(right_value)
            if not all(isinstance(key, str) for key in left_keys | right_keys):
                raise Refusal("semantic comparison encountered a non-JSON object key")
            for key in reversed(sorted(left_keys | right_keys)):
                stack.append(
                    (
                        _json_pointer_child(pointer, key),
                        left_value.get(key, _SEMANTIC_MISSING),
                        right_value.get(key, _SEMANTIC_MISSING),
                    )
                )
            continue
        if left_type == right_type == "array":
            for index in reversed(range(max(len(left_value), len(right_value)))):
                stack.append(
                    (
                        _json_pointer_child(pointer, str(index)),
                        left_value[index] if index < len(left_value) else _SEMANTIC_MISSING,
                        right_value[index] if index < len(right_value) else _SEMANTIC_MISSING,
                    )
                )
            continue
        if left_value == right_value:
            continue
        total += 1
        if len(entries) >= SEMANTIC_DIFF_LIMIT:
            continue
        if left_type == "missing":
            kind = "missing_left"
        elif right_type == "missing":
            kind = "missing_right"
        elif left_type != right_type:
            kind = "type_mismatch"
        else:
            kind = "value_mismatch"
        entry = {
            "kind": kind,
            "left_type": left_type,
            "right_type": right_type,
        }
        if pointer in APPROVED_SEMANTIC_POINTERS:
            entry["path"] = pointer
        else:
            entry["path_sha256"] = sha256_bytes(pointer.encode("utf-8"))
        entries.append(entry)
    return {
        "total": total,
        "truncated": total > len(entries),
        "entries": entries,
    }


def _validated_semantic_diagnostic(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "request_canonical_sha256",
        "argument_canonical_sha256",
        "repeat_canonical_sha256",
        "request_equals_argument",
        "argument_equals_repeat",
        "request_argument_diff",
        "argument_repeat_diff",
    }
    if not isinstance(value, dict) or not set(value).issubset(allowed):
        raise Refusal("semantic diagnostic fields are unsafe")
    if "request_canonical_sha256" not in value:
        raise Refusal("semantic diagnostic lacks the request hash")
    for name in (
        "request_canonical_sha256",
        "argument_canonical_sha256",
        "repeat_canonical_sha256",
    ):
        if name in value and not (
            isinstance(value[name], str)
            and re.fullmatch(r"[0-9a-f]{64}", value[name]) is not None
        ):
            raise Refusal("semantic diagnostic hash is unsafe")
    for name in ("request_equals_argument", "argument_equals_repeat"):
        if name in value and not isinstance(value[name], bool):
            raise Refusal("semantic diagnostic equality is unsafe")
    for name in ("request_argument_diff", "argument_repeat_diff"):
        if name not in value:
            continue
        summary = value[name]
        if not isinstance(summary, dict) or set(summary) != {
            "total", "truncated", "entries"
        }:
            raise Refusal("semantic diagnostic diff shape is unsafe")
        total = summary["total"]
        entries = summary["entries"]
        truncated = summary["truncated"]
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or not isinstance(truncated, bool)
            or not isinstance(entries, list)
            or len(entries) > SEMANTIC_DIFF_LIMIT
            or total < len(entries)
            or truncated != (total > len(entries))
        ):
            raise Refusal("semantic diagnostic diff bounds are unsafe")
        for entry in entries:
            if not isinstance(entry, dict):
                raise Refusal("semantic diagnostic entry is unsafe")
            path_keys = {key for key in ("path", "path_sha256") if key in entry}
            if len(path_keys) != 1 or set(entry) != {
                "kind", "left_type", "right_type", *path_keys
            }:
                raise Refusal("semantic diagnostic path fields are unsafe")
            if entry["kind"] not in SEMANTIC_DIFF_KINDS or not {
                entry["left_type"], entry["right_type"]
            }.issubset(SEMANTIC_JSON_TYPES):
                raise Refusal("semantic diagnostic enums are unsafe")
            if "path" in entry and entry["path"] not in APPROVED_SEMANTIC_POINTERS:
                raise Refusal("semantic diagnostic exposed an unapproved path")
            if "path_sha256" in entry and not (
                isinstance(entry["path_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", entry["path_sha256"]) is not None
            ):
                raise Refusal("semantic diagnostic path hash is unsafe")
    return copy.deepcopy(value)


def _validated_result_readiness(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "observation_count",
        "execution_finished_seen",
        "repeat_ready",
    }:
        raise Refusal("result-readiness diagnostic fields are unsafe")
    count = value["observation_count"]
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not 1 <= count <= MAX_RESULT_READY_OBSERVATIONS
        or not isinstance(value["execution_finished_seen"], bool)
        or not isinstance(value["repeat_ready"], bool)
    ):
        raise Refusal("result-readiness diagnostic values are unsafe")
    return copy.deepcopy(value)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise Refusal("a timestamp source was not timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def require_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        raise Refusal(f"{label} is not a canonical UUID")
    return value


def require_secret_name(value: str) -> str:
    if not SAFE_SECRET_NAME.fullmatch(value):
        raise Refusal("the DPAPI record name is unsafe")
    return value


def validate_origin(url: str, *, base: bool = False) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise Refusal("the Shuffle URL is invalid") from error
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or not (host == "shuffler.io" or host.endswith(".shuffler.io"))
    ):
        raise Refusal("the Shuffle URL violates the fixed HTTPS origin allowlist")
    if base and parsed.path not in ("", "/"):
        raise Refusal("the Shuffle API base must be an origin without a path")
    return f"https://{host}"


def validate_webhook_uri(url: str, webhook_id: str) -> str:
    origin = validate_origin(url)
    parsed = urlsplit(url)
    allowed = {
        f"/api/v1/hooks/{webhook_id}",
        f"/api/v1/hooks/webhook_{webhook_id}",
        f"/api/v1/webhooks/webhook_{webhook_id}",
    }
    if parsed.path not in allowed:
        raise Refusal("the protected Webhook URI does not contain the configured ID")
    return origin + parsed.path


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise Refusal("an HTTP redirect was refused")


@dataclass(frozen=True)
class HttpResponse:
    status: int
    value: Any


class SafeHttp:
    """Bounded urllib transport with a fixed Shuffle origin and no redirects."""

    def __init__(
        self,
        api_base: str,
        *,
        timeout: int = 20,
        opener: Any | None = None,
    ) -> None:
        if not 5 <= timeout <= 60:
            raise Refusal("HTTP timeout must be between 5 and 60 seconds")
        self.origin = validate_origin(api_base, base=True)
        self.timeout = timeout
        self.opener = opener or build_opener(NoRedirect)

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any | None,
        *,
        allow_non_success: bool,
        deadline: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> HttpResponse:
        parsed = urlsplit(url)
        validate_origin(f"{parsed.scheme}://{parsed.netloc}/", base=True)
        if parsed.fragment:
            raise Refusal("the Shuffle request URL contains a fragment")
        data = None if body is None else canonical_bytes(body)
        request = Request(url, data=data, method=method, headers=headers)
        request_timeout = float(self.timeout)
        if deadline is not None:
            remaining = deadline - clock()
            if remaining <= 0:
                raise Refusal("the bounded Shuffle HTTP deadline expired before request")
            request_timeout = min(request_timeout, remaining)
        try:
            response = self.opener.open(request, timeout=request_timeout)
        except HTTPError as error:
            if 300 <= error.code < 400:
                raise Refusal("an HTTP redirect was refused") from error
            if not allow_non_success:
                raise Refusal(f"Shuffle HTTP request failed with status {error.code}") from error
            raw = error.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise Refusal("Shuffle HTTP response exceeded the fixed size limit")
            if deadline is not None and clock() > deadline:
                raise Refusal("the bounded Shuffle HTTP deadline expired")
            return HttpResponse(error.code, None)
        except (URLError, OSError, TimeoutError) as error:
            raise Refusal("the bounded Shuffle HTTP request failed") from error
        with response:
            status = int(response.status)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if deadline is not None and clock() > deadline:
            raise Refusal("the bounded Shuffle HTTP deadline expired")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise Refusal("Shuffle HTTP response exceeded the fixed size limit")
        if 300 <= status < 400:
            raise Refusal("an HTTP redirect was refused")
        if not 200 <= status < 300 and not allow_non_success:
            raise Refusal(f"Shuffle HTTP request failed with status {status}")
        value: Any = None
        if raw:
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                if 200 <= status < 300:
                    raise Refusal("Shuffle returned a non-JSON success response")
        return HttpResponse(status, value)

    def api(
        self,
        method: str,
        path: str,
        api_key: str,
        org_id: str,
        body: Any | None = None,
        *,
        deadline: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> Any:
        if method not in {"GET", "POST", "PUT"}:
            raise Refusal("an unsupported Shuffle API method was requested")
        if not path.startswith("/api/v1/") or ".." in path or any(
            character in path for character in "\r\n#"
        ):
            raise Refusal("the Shuffle API path is unsafe")
        if not api_key or "\r" in api_key or "\n" in api_key:
            raise Refusal("the protected Shuffle API key is empty or unsafe")
        require_uuid(org_id, "Shuffle organization ID")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Org-Id": org_id,
        }
        return self._send(
            method,
            self.origin + path,
            headers,
            body,
            allow_non_success=False,
            deadline=deadline,
            clock=clock,
        ).value

    def webhook(
        self,
        url: str,
        payload: dict[str, Any],
        header_value: str | None,
        *,
        deadline: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> HttpResponse:
        validate_origin(url)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if header_value is not None:
            if not header_value or "\r" in header_value or "\n" in header_value:
                raise Refusal("the Webhook Header value is empty or unsafe")
            headers[HEADER_NAME] = header_value
        return self._send(
            "POST",
            url,
            headers,
            payload,
            allow_non_success=True,
            deadline=deadline,
            clock=clock,
        )


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ps_diagnostic_wrapper(operation: str) -> str:
    return (
        "$ErrorActionPreference='Stop'; try { "
        + operation
        + " } catch { $diag=[ordered]@{sentinel='"
        + PS_DIAGNOSTIC_SENTINEL
        + "';exception_type=$_.Exception.GetType().FullName;fqid=[string]$_.FullyQualifiedErrorId}; "
        + "[Console]::Error.Write(($diag | ConvertTo-Json -Compress)); exit 31 }"
    )


def _safe_ps_diagnostic(stderr: str) -> tuple[str | None, str | None]:
    if not isinstance(stderr, str) or not 1 <= len(stderr) <= 1024:
        return None, None
    try:
        value = json.loads(stderr)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(value, dict) or set(value) != {
        "sentinel", "exception_type", "fqid"
    } or value.get("sentinel") != PS_DIAGNOSTIC_SENTINEL:
        return None, None
    exception_type = value.get("exception_type")
    fqid = value.get("fqid")
    safe_type = (
        exception_type if exception_type in ALLOWED_PS_EXCEPTION_TYPES else None
    )
    safe_fqid = fqid if fqid in ALLOWED_PS_FQIDS else None
    return safe_type, safe_fqid


class DpapiSecrets:
    """Use the repository's PowerShell DPAPI implementation via captured pipes."""

    def __init__(
        self,
        secret_root: Path,
        *,
        module_path: Path = SECURITY_MODULE,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.secret_root = secret_root.resolve()
        self.module_path = module_path.resolve()
        self.run = run

    def record_path(self, name: str) -> Path:
        return self.secret_root / f"{require_secret_name(name)}.dpapi.json"

    def _invoke(self, stage: str, operation: str, plaintext: str = "") -> str:
        if stage not in {"unprotect", "protect_new"}:
            raise Refusal("DPAPI stage is not allowlisted")
        script = _ps_diagnostic_wrapper(operation)
        try:
            completed = self.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                input=plaintext,
                text=True,
                capture_output=True,
                shell=False,
                check=False,
                timeout=DPAPI_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise Refusal(
                f"DPAPI stage={stage} returncode_category=timeout"
            ) from error
        except OSError as error:
            raise Refusal(
                f"DPAPI stage={stage} returncode_category=launch_failure"
            ) from error
        if completed.returncode != 0:
            category = (
                "powershell_exception" if completed.returncode == 31
                else "terminated" if completed.returncode < 0
                else "process_failure"
            )
            parts = [f"DPAPI stage={stage}", f"returncode_category={category}"]
            if category == "powershell_exception":
                exception_type, fqid = _safe_ps_diagnostic(completed.stderr)
                if exception_type is not None:
                    parts.append(f"exception_type={exception_type}")
                if fqid is not None:
                    parts.append(f"fqid={fqid}")
            raise Refusal(" ".join(parts))
        return completed.stdout.rstrip("\r\n")

    def unprotect(self, name: str) -> str:
        name = require_secret_name(name)
        operation = (
            "Import-Module -Force "
            + _ps_quote(str(self.module_path))
            + "; [Console]::Out.Write((Unprotect-SocSecret -Name "
            + _ps_quote(name)
            + " -SecretRoot "
            + _ps_quote(str(self.secret_root))
            + "))"
        )
        value = self._invoke("unprotect", operation)
        if not value:
            raise Refusal("a required protected secret is empty")
        return value

    def protect_new(self, name: str, plaintext: str) -> Path:
        name = require_secret_name(name)
        if not plaintext:
            raise Refusal("an empty rollback export cannot be protected")
        path = self.record_path(name)
        if path.exists():
            raise Refusal("the rollback DPAPI record already exists")
        operation = (
            "Import-Module -Force "
            + _ps_quote(str(self.module_path))
            + "; $plain=[Console]::In.ReadToEnd(); "
            + "$path=Protect-SocSecret -Name "
            + _ps_quote(name)
            + " -PlainText $plain -SecretRoot "
            + _ps_quote(str(self.secret_root))
            + "; [Console]::Out.Write($path)"
        )
        returned = Path(self._invoke("protect_new", operation, plaintext)).resolve()
        if returned != path.resolve() or not path.is_file():
            raise Refusal("the rollback DPAPI record path was not proven")
        return path


@dataclass(frozen=True)
class Configuration:
    api_base: str
    org_id: str
    workflow_id: str
    webhook_id: str


def default_config_path() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise Refusal("LOCALAPPDATA is unavailable")
    return Path(local) / "aws-topology" / "soc-config" / "soc-lab.json"


def default_secret_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise Refusal("LOCALAPPDATA is unavailable")
    return Path(local) / "aws-topology" / "soc-secrets"


def load_json_file(path: Path, limit: int = MAX_EVIDENCE_BYTES) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise Refusal(f"required JSON is unavailable: {path.name}") from error
    if len(raw) > limit:
        raise Refusal(f"JSON exceeded its fixed size limit: {path.name}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"required JSON is invalid: {path.name}") from error


def load_configuration(path: Path) -> Configuration:
    value = load_json_file(path)
    if not isinstance(value, dict):
        raise Refusal("SOC configuration is not an object")
    required = (
        "shuffle_api_base",
        "shuffle_org_id",
        "shuffle_workflow_id",
        "shuffle_webhook_id",
    )
    if any(not isinstance(value.get(key), str) or not value[key] for key in required):
        raise Refusal("SOC configuration is missing a required Shuffle key")
    validate_origin(value["shuffle_api_base"], base=True)
    return Configuration(
        api_base=value["shuffle_api_base"],
        org_id=require_uuid(value["shuffle_org_id"], "Shuffle organization ID"),
        workflow_id=require_uuid(value["shuffle_workflow_id"], "Shuffle workflow ID"),
        webhook_id=require_uuid(value["shuffle_webhook_id"], "Shuffle Webhook ID"),
    )


def _field(value: dict[str, Any], names: Iterable[str], default: Any = None) -> Any:
    for name in names:
        if name in value:
            return value[name]
    return default


def _active_status(trigger: dict[str, Any]) -> str:
    status = _field(trigger, ("status", "state"), "")
    if isinstance(status, str) and status.upper() in {"RUNNING", "ACTIVE"}:
        return status
    if status == "" and trigger.get("active") is True:
        return "ACTIVE"
    raise Refusal("the configured Shuffle Webhook is not running")


def _header_lines(trigger: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for name in ("auth", "authentication"):
        value = trigger.get(name)
        if isinstance(value, str) and value.strip():
            values.append(value)
    parameters = trigger.get("parameters", [])
    if parameters is None:
        parameters = []
    if not isinstance(parameters, list):
        raise Refusal("the Shuffle Webhook parameters are invalid")
    for parameter in parameters:
        if not isinstance(parameter, dict):
            raise Refusal("the Shuffle Webhook parameter is invalid")
        if str(parameter.get("name", "")).lower() in {
            "auth",
            "auth_headers",
            "authentication",
        }:
            value = parameter.get("value")
            if isinstance(value, str) and value.strip():
                values.append(value)
    return values


def _assert_header(trigger: dict[str, Any], expected: str) -> None:
    parsed: list[tuple[str, str]] = []
    for block in _header_lines(trigger):
        for line in block.splitlines():
            if not line.strip():
                continue
            delimiter_count = line.count(":") + line.count("=")
            if delimiter_count != 1 or (":" in line and "=" in line):
                raise Refusal("the Shuffle Webhook Header configuration is malformed")
            delimiter = ":" if ":" in line else "="
            name, value = line.split(delimiter, 1)
            parsed.append((name.strip(), value.strip()))
    matches = [(name, value) for name, value in parsed if name == HEADER_NAME]
    if len(matches) != 1 or matches[0][1] != expected:
        raise Refusal("the Shuffle Webhook Header does not exactly match DPAPI")
    if len(parsed) != 1:
        raise Refusal("the Shuffle Webhook contains an unexpected authentication Header")


def _is_unconditional(branch: dict[str, Any]) -> bool:
    values = [branch[name] for name in ("condition", "conditions") if name in branch]
    if not values:
        return True
    return all(value in (None, "", [], {}) for value in values)


def inspect_workflow(
    workflow: Any,
    config: Configuration,
    expected_header: str,
    *,
    expected_call: str | None = None,
) -> dict[str, Any]:
    if not isinstance(workflow, dict):
        raise Refusal("Shuffle Workflow is not an object")
    workflow_id = _field(workflow, ("id", "workflow_id"))
    if workflow_id != config.workflow_id:
        raise Refusal("Shuffle Workflow ID does not match configuration")
    private = workflow.get("sharing") == "private" or workflow.get("is_private") is True
    if not private or workflow.get("is_valid") is not True:
        raise Refusal("Shuffle Workflow is not private and valid")
    workflow_name = workflow.get("name")
    if not isinstance(workflow_name, str) or not 1 <= len(workflow_name) <= 256:
        raise Refusal("Shuffle Workflow name is missing or unbounded")

    triggers = workflow.get("triggers")
    if not isinstance(triggers, list) or len(triggers) != 1:
        raise Refusal("the OBSERVE_ONLY Workflow must contain exactly one trigger")
    trigger = triggers[0]
    if not isinstance(trigger, dict) or _field(trigger, ("id", "trigger_id")) != config.webhook_id:
        raise Refusal("the configured Shuffle Webhook trigger is absent")
    trigger_type = str(_field(trigger, ("trigger_type", "type"), "")).lower()
    if trigger_type != "webhook":
        raise Refusal("the configured Shuffle trigger is not a WEBHOOK")
    trigger_status = _active_status(trigger)
    _assert_header(trigger, expected_header)

    actions = workflow.get("actions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
        raise Refusal("the OBSERVE_ONLY Workflow must contain exactly one Action")
    action = actions[0]
    action_text = " ".join(
        str(_field(action, names, ""))
        for names in (("app_name", "app"), ("name", "action_name", "action"), ("label",))
    )
    if FORBIDDEN_ACTION.search(action_text):
        raise Refusal("the Workflow contains a forbidden side-effect Action")
    app_name = str(_field(action, ("app_name", "app"), "")).lower()
    operation = str(_field(action, ("name", "action_name", "action"), "")).lower()
    if app_name != "shuffle tools" or operation != "repeat_back_to_me":
        raise Refusal("the sole Action is not Shuffle Tools/repeat_back_to_me")
    app_version = action.get("app_version")
    action_label = action.get("label")
    if (
        not isinstance(app_version, str) or not 1 <= len(app_version) <= 64
        or not isinstance(action_label, str) or not 1 <= len(action_label) <= 128
    ):
        raise Refusal("the repeat Action version or label is missing or unbounded")
    action_id = require_uuid(
        _field(action, ("id", "action_id")), "repeat Action ID"
    )
    parameters = action.get("parameters")
    if not isinstance(parameters, list) or len(parameters) != 1 or not isinstance(parameters[0], dict):
        raise Refusal("repeat_back_to_me must contain only one call parameter")
    parameter = parameters[0]
    if parameter.get("name") != "call" or "value" not in parameter:
        raise Refusal("repeat_back_to_me lacks the unique call parameter")
    call_value = parameter["value"]
    if not isinstance(call_value, str):
        raise Refusal("repeat_back_to_me call.value is not a string")
    if expected_call is not None and call_value != expected_call:
        raise Refusal("repeat_back_to_me call.value does not match the required literal")

    branches = _field(workflow, ("branches", "workflow_edges", "edges"), None)
    if not isinstance(branches, list) or len(branches) != 1 or not isinstance(branches[0], dict):
        raise Refusal("the OBSERVE_ONLY Workflow must contain exactly one Branch")
    branch = branches[0]
    branch_id = require_uuid(_field(branch, ("id", "branch_id")), "Branch ID")
    source = _field(branch, ("source_id", "source"))
    destination = _field(branch, ("destination_id", "destination"))
    if source != config.webhook_id or destination != action_id or not _is_unconditional(branch):
        raise Refusal("the Webhook-to-repeat Branch is not exactly unconditional")

    return {
        "workflow_id": workflow_id,
        "workflow_name": workflow_name,
        "sharing": "private",
        "private": True,
        "valid": True,
        "trigger_count": 1,
        "trigger_id": config.webhook_id,
        "webhook_id": config.webhook_id,
        "trigger_type": "WEBHOOK",
        "trigger_status": trigger_status,
        "action_count": 1,
        "unexpected_action_count": 0,
        "repeat_action_id": action_id,
        "action_id": action_id,
        "repeat_app": "Shuffle Tools",
        "app_version": app_version,
        "repeat_operation": "repeat_back_to_me",
        "action_label": action_label,
        "call_is_exec": call_value == "$exec",
        "call_classification": "literal-exec" if call_value == "$exec" else "non-exec",
        "call_sha256": sha256_bytes(call_value.encode("utf-8")),
        "branch_count": 1,
        "branch_id": branch_id,
        "branch_source_id": source,
        "branch_destination_id": destination,
        "effective_unconditional_branch_count": 1,
        "header_name": HEADER_NAME,
        "header_exact_match": True,
        "canonical_workflow_sha256": canonical_sha256(workflow),
    }


def semantic_projection(projection: dict[str, Any]) -> dict[str, Any]:
    comparable = copy.deepcopy(projection)
    comparable.pop("canonical_workflow_sha256", None)
    return comparable


@dataclass(frozen=True)
class RestoreProof:
    full_exact: bool
    server_metadata_drift_only: bool
    restored_semantically: bool
    readback_projection: dict[str, Any]


def structural_diff_paths(left: Any, right: Any, path: str = "") -> list[str]:
    """Return granular paths only; never retain or expose differing values."""
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        differences: list[str] = []
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}" if path else str(key)
            if key not in left:
                differences.extend(_leaf_paths(right[key], child))
            elif key not in right:
                differences.extend(_leaf_paths(left[key], child))
            else:
                differences.extend(structural_diff_paths(left[key], right[key], child))
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return [path]
        differences = []
        for index, (a, b) in enumerate(zip(left, right)):
            differences.extend(structural_diff_paths(a, b, f"{path}[{index}]"))
        return differences
    return [] if left == right else [path]


def _leaf_paths(value: Any, path: str) -> list[str]:
    if isinstance(value, dict) and value:
        paths: list[str] = []
        for key in sorted(value):
            paths.extend(_leaf_paths(value[key], f"{path}.{key}"))
        return paths
    return [path]


def _is_allowed_server_metadata_path(path: str) -> bool:
    return any(
        path == allowed or path.startswith(allowed + ".") or path.startswith(allowed + "[")
        for allowed in SERVER_METADATA_DRIFT_PATHS
    )


def prove_workflow_readback(
    expected: dict[str, Any],
    readback: dict[str, Any],
    config: Configuration,
    expected_header: str,
    *,
    expected_call: str | None = None,
) -> RestoreProof:
    """Prove exact semantics and permit drift only under five observed metadata paths."""
    full_exact = canonical_sha256(readback) == canonical_sha256(expected)
    try:
        expected_projection = inspect_workflow(
            expected, config, expected_header, expected_call=expected_call
        )
        readback_projection = inspect_workflow(
            readback, config, expected_header, expected_call=expected_call
        )
    except Refusal as error:
        raise ReadbackProofFailure(
            restored_semantically=False, full_exact=full_exact
        ) from error
    restored_semantically = (
        semantic_projection(expected_projection)
        == semantic_projection(readback_projection)
    )
    if not restored_semantically:
        raise ReadbackProofFailure(
            restored_semantically=False, full_exact=full_exact
        )
    drift_paths = structural_diff_paths(expected, readback)
    if any(not _is_allowed_server_metadata_path(path) for path in drift_paths):
        raise ReadbackProofFailure(
            restored_semantically=True, full_exact=full_exact
        )
    return RestoreProof(
        full_exact=full_exact,
        server_metadata_drift_only=bool(drift_paths) and not full_exact,
        restored_semantically=True,
        readback_projection=readback_projection,
    )


def mutate_call_only(workflow: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(workflow)
    parameters = changed["actions"][0]["parameters"]
    old = parameters[0]["value"]
    if old == "$exec":
        raise Refusal("repeat_back_to_me already uses $exec; no scalar mutation exists")
    parameters[0]["value"] = "$exec"
    differences = structural_diff(workflow, changed)
    if differences != [("actions[0].parameters[0].value", old, "$exec")]:
        raise Refusal("the proposed Workflow mutation is not exactly one scalar")
    return changed


def structural_diff(left: Any, right: Any, path: str = "") -> list[tuple[str, Any, Any]]:
    if type(left) is not type(right):
        return [(path, left, right)]
    if isinstance(left, dict):
        differences: list[tuple[str, Any, Any]] = []
        if left.keys() != right.keys():
            return [(path, left, right)]
        for key in left:
            child = f"{path}.{key}" if path else key
            differences.extend(structural_diff(left[key], right[key], child))
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return [(path, left, right)]
        differences = []
        for index, (a, b) in enumerate(zip(left, right)):
            differences.extend(structural_diff(a, b, f"{path}[{index}]"))
        return differences
    return [] if left == right else [(path, left, right)]


def execution_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("success") is False:
            raise Refusal("Shuffle returned an unsuccessful execution list")
        value = value.get("executions")
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise Refusal("Shuffle returned an unsupported execution-list shape")
    return value


def execution_id(item: dict[str, Any]) -> str:
    return require_uuid(item.get("execution_id", item.get("id")), "Shuffle execution ID")


def safe_execution_projection(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projected = []
    for item in items:
        status = str(item.get("status", "")).upper()
        if status not in {
            "", "EXECUTING", "RUNNING", "WAITING", "FINISHED", "SUCCESS",
            "COMPLETED", "ABORTED", "FAILED", "FAILURE",
        }:
            status = "UNKNOWN"
        def bounded_timestamp(name: str) -> str | None:
            value = item.get(name)
            return value if isinstance(value, str) and len(value) <= 64 else None
        projected.append(
            {
                "execution_id": execution_id(item),
                "status": status,
                "started_at": bounded_timestamp("started_at"),
                "completed_at": bounded_timestamp("completed_at"),
            }
        )
    return projected


def write_evidence(path: Path, value: dict[str, Any], forbidden: Iterable[str] = ()) -> None:
    def inspect_keys(current: Any) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                if str(key).lower() in FORBIDDEN_EVIDENCE_KEYS:
                    raise Refusal("Evidence contains a forbidden raw field")
                inspect_keys(child)
        elif isinstance(current, list):
            for child in current:
                inspect_keys(child)

    inspect_keys(value)
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    for secret in forbidden:
        if secret and secret in raw:
            raise Refusal("a runtime secret would have been persisted in Evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(raw, encoding="utf-8")
    os.replace(temporary, path)


def _write_recovery_evidence(
    path: Path,
    *,
    gate: str,
    initial_failure_stage: str,
    initial_failure_category: str,
    recovery_failure_stage: str | None,
    workflow_id: str,
    mutation_attempted: bool,
    restored_semantically: bool,
    full_exact: bool,
    server_metadata_drift_only: bool,
    recovery_proof_succeeded: bool,
    now: Callable[[], datetime],
    forbidden: Iterable[str],
    semantic_diagnostic: dict[str, Any] | None = None,
    result_readiness: dict[str, Any] | None = None,
) -> None:
    allowed_initial = {
        "g1_apply",
        "explicit_rollback",
        "preflight",
        "valid_baseline",
        "valid_post",
        "valid_execution",
        "valid_result_ready",
        "valid_singleton",
        "valid_semantic",
        "wrong_baseline",
        "wrong_post",
        "wrong_observation",
        "missing_baseline",
        "missing_post",
        "missing_observation",
        "evidence_write",
        "unexpected",
    }
    if initial_failure_stage not in allowed_initial:
        initial_failure_stage = "unexpected"
    if initial_failure_category not in GATE2_FAILURE_CATEGORIES | {
        "apply_failure",
        "rollback_requested",
    }:
        initial_failure_category = "stage_failure"
    if recovery_failure_stage not in {None, "put", "get", "proof"}:
        recovery_failure_stage = "proof"
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "artifact_kind": "shuffle-observe-only-recovery",
        "created_at_utc": utc_text(now()),
        "failure_gate": gate,
        "initial_failure_stage": initial_failure_stage,
        "initial_failure_category": initial_failure_category,
        "recovery_failure_stage": recovery_failure_stage,
        "workflow_id": workflow_id,
        "mutation_attempted": mutation_attempted,
        "restored_semantically": restored_semantically,
        "full_exact": full_exact,
        "server_metadata_drift_only": server_metadata_drift_only,
        "recovery_proof_succeeded": recovery_proof_succeeded,
        "secret_persisted_in_evidence": False,
    }
    if semantic_diagnostic is not None:
        evidence["semantic_diagnostic"] = _validated_semantic_diagnostic(
            semantic_diagnostic
        )
    if result_readiness is not None:
        evidence["result_readiness"] = _validated_result_readiness(result_readiness)
    write_evidence(path, evidence, forbidden)


def _ensure_deadline(
    deadline: float | None, clock: Callable[[], float]
) -> None:
    if deadline is not None and clock() >= deadline:
        raise Refusal("the bounded operation deadline expired")


def _api_workflow(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    _ensure_deadline(deadline, clock)
    value = http.api(
        "GET",
        f"/api/v1/workflows/{config.workflow_id}",
        api_key,
        config.org_id,
        deadline=deadline,
        clock=clock,
    )
    _ensure_deadline(deadline, clock)
    if not isinstance(value, dict):
        raise Refusal("Shuffle returned an invalid Workflow object")
    return value


def _api_executions(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> list[dict[str, Any]]:
    _ensure_deadline(deadline, clock)
    items = execution_list(
        http.api(
            "GET",
            f"/api/v1/workflows/{config.workflow_id}/executions?top=100",
            api_key,
            config.org_id,
            deadline=deadline,
            clock=clock,
        )
    )
    _ensure_deadline(deadline, clock)
    if len(items) >= 100:
        raise Refusal("the top=100 execution window may be truncated")
    return items


def _put_workflow(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    workflow: dict[str, Any],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    _ensure_deadline(deadline, clock)
    http.api(
        "PUT",
        f"/api/v1/workflows/{config.workflow_id}",
        api_key,
        config.org_id,
        workflow,
        deadline=deadline,
        clock=clock,
    )
    _ensure_deadline(deadline, clock)


def _http_timeout_seconds(http: Any) -> float:
    value = getattr(http, "timeout", 20)
    if not isinstance(value, (int, float)) or not 0 < float(value) <= 60:
        return 20.0
    return float(value)


def restore_and_prove(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    header: str,
    original: dict[str, Any],
    *,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any], RestoreProof]:
    mutation_attempted = False
    try:
        mutation_attempted = True
        _put_workflow(
            http, config, api_key, original, deadline=deadline, clock=clock
        )
    except Exception as error:
        raise RestoreFailure(
            "put", mutation_attempted=mutation_attempted
        ) from error
    try:
        readback = _api_workflow(
            http, config, api_key, deadline=deadline, clock=clock
        )
    except Exception as error:
        raise RestoreFailure(
            "get", mutation_attempted=mutation_attempted
        ) from error
    try:
        proof = prove_workflow_readback(original, readback, config, header)
    except ReadbackProofFailure as error:
        raise RestoreFailure(
            "proof",
            mutation_attempted=mutation_attempted,
            restored_semantically=error.restored_semantically,
            full_exact=error.full_exact,
        ) from error
    return readback, proof


def _secret_material(
    secrets_backend: DpapiSecrets, config: Configuration
) -> tuple[str, str, str]:
    api_key = secrets_backend.unprotect(API_KEY_NAME)
    webhook_uri = validate_webhook_uri(
        secrets_backend.unprotect(WEBHOOK_URI_NAME), config.webhook_id
    )
    header = secrets_backend.unprotect(WEBHOOK_HEADER_NAME)
    if not HEADER_VALUE_PATTERN.fullmatch(header):
        raise Refusal("the protected Webhook Header is empty or unsafe")
    return api_key, webhook_uri, header


def _default_rollback_name(config: Configuration, now: datetime) -> str:
    return "shuffle_observe_rollback_" + now.astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )


def snapshot(
    config: Configuration,
    evidence_path: Path,
    secrets_backend: DpapiSecrets,
    http: SafeHttp,
    *,
    rollback_name: str | None = None,
    now: Callable[[], datetime] = utc_now,
) -> dict[str, Any]:
    api_key, webhook_uri, header = _secret_material(secrets_backend, config)
    workflow = _api_workflow(http, config, api_key)
    projection = inspect_workflow(workflow, config, header)
    executions = _api_executions(http, config, api_key)
    moment = now()
    name = require_secret_name(rollback_name or _default_rollback_name(config, moment))
    rollback_path = secrets_backend.protect_new(
        name, canonical_bytes(workflow).decode("utf-8")
    )
    try:
        protected_roundtrip = json.loads(secrets_backend.unprotect(name))
    except json.JSONDecodeError as error:
        raise Refusal("the new rollback DPAPI record failed JSON round-trip") from error
    if canonical_sha256(protected_roundtrip) != canonical_sha256(workflow):
        raise Refusal("the new rollback DPAPI record failed canonical round-trip")
    record_hash = sha256_bytes(rollback_path.read_bytes())
    path_hash = sha256_bytes(str(rollback_path.resolve()).encode("utf-8"))
    evidence = {
        "schema_version": 1,
        "artifact_kind": "shuffle-observe-only-g0-snapshot",
        "created_at_utc": utc_text(moment),
        "api_origin": validate_origin(config.api_base, base=True),
        "organization_id": config.org_id,
        "workflow_id": config.workflow_id,
        "webhook_id": config.webhook_id,
        "workflow": projection,
        "webhook": {
            "secret_reference": WEBHOOK_URI_NAME,
            "uri_sha256": sha256_bytes(webhook_uri.encode("utf-8")),
        },
        "required_header": {
            "name": HEADER_NAME,
            "secret_reference": WEBHOOK_HEADER_NAME,
            "exact_match": True,
        },
        "rollback": {
            "secret_reference": name,
            "record_path_sha256": path_hash,
            "record_sha256": record_hash,
            "canonical_workflow_sha256": canonical_sha256(workflow),
            "dpapi_roundtrip_proven": True,
        },
        "execution_baseline": safe_execution_projection(executions),
        "secret_persisted_in_evidence": False,
    }
    write_evidence(evidence_path, evidence, (api_key, webhook_uri, header))
    return evidence


def _load_snapshot(
    path: Path, config: Configuration, secrets_backend: DpapiSecrets
) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = load_json_file(path)
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
        raise Refusal("the Gate 0 snapshot is invalid")
    if evidence.get("artifact_kind") != "shuffle-observe-only-g0-snapshot":
        raise Refusal("the Evidence is not a Gate 0 snapshot")
    if (
        evidence.get("api_origin") != validate_origin(config.api_base, base=True)
        or evidence.get("organization_id") != config.org_id
        or evidence.get("workflow_id") != config.workflow_id
        or evidence.get("webhook_id") != config.webhook_id
    ):
        raise Refusal("the Gate 0 snapshot does not match current configuration")
    rollback = evidence.get("rollback")
    if not isinstance(rollback, dict):
        raise Refusal("the Gate 0 rollback reference is absent")
    name = require_secret_name(str(rollback.get("secret_reference", "")))
    path_record = secrets_backend.record_path(name)
    if not path_record.is_file():
        raise Refusal("the protected rollback record is unavailable")
    if sha256_bytes(str(path_record.resolve()).encode("utf-8")) != rollback.get(
        "record_path_sha256"
    ) or sha256_bytes(path_record.read_bytes()) != rollback.get("record_sha256"):
        raise Refusal("the protected rollback record identity or content changed")
    plaintext = secrets_backend.unprotect(name)
    try:
        workflow = json.loads(plaintext)
    except json.JSONDecodeError as error:
        raise Refusal("the protected rollback Workflow is invalid JSON") from error
    expected_hash = rollback.get("canonical_workflow_sha256")
    if canonical_sha256(workflow) != expected_hash:
        raise Refusal("the protected rollback Workflow hash does not match Gate 0")
    return evidence, workflow


def apply_minimal(
    config: Configuration,
    snapshot_path: Path,
    evidence_path: Path,
    secrets_backend: DpapiSecrets,
    http: SafeHttp,
    *,
    now: Callable[[], datetime] = utc_now,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    _, original = _load_snapshot(snapshot_path, config, secrets_backend)
    api_key, webhook_uri, header = _secret_material(secrets_backend, config)
    fresh = _api_workflow(http, config, api_key)
    try:
        precondition_proof = prove_workflow_readback(
            original, fresh, config, header
        )
    except ReadbackProofFailure as error:
        raise Refusal(
            "fresh Workflow GET failed the Gate 0 semantic precondition"
        ) from error
    updated = mutate_call_only(fresh)
    submitted_projection = inspect_workflow(updated, config, header, expected_call="$exec")
    attempted = False
    try:
        attempted = True
        _put_workflow(http, config, api_key, updated)
        readback = _api_workflow(http, config, api_key)
        readback_proof = prove_workflow_readback(
            updated, readback, config, header, expected_call="$exec"
        )
        readback_projection = readback_proof.readback_projection
    except Exception as update_error:
        if attempted:
            recovery_path = evidence_path.with_name("g1-recovery.json")
            try:
                _, recovery_proof = restore_and_prove(
                    http,
                    config,
                    api_key,
                    header,
                    original,
                    deadline=clock() + (2 * _http_timeout_seconds(http)) + 1,
                    clock=clock,
                )
            except RestoreFailure as rollback_error:
                _write_recovery_evidence(
                    recovery_path,
                    gate="G1",
                    initial_failure_stage="g1_apply",
                    initial_failure_category="apply_failure",
                    recovery_failure_stage=rollback_error.stage,
                    workflow_id=config.workflow_id,
                    mutation_attempted=rollback_error.mutation_attempted,
                    restored_semantically=rollback_error.restored_semantically,
                    full_exact=rollback_error.full_exact,
                    server_metadata_drift_only=False,
                    recovery_proof_succeeded=False,
                    now=now,
                    forbidden=(api_key, webhook_uri, header),
                )
                raise RecoveryFailure(
                    "the minimal update failed and Workflow recovery was not proven"
                ) from rollback_error
            _write_recovery_evidence(
                recovery_path,
                gate="G1",
                initial_failure_stage="g1_apply",
                initial_failure_category="apply_failure",
                recovery_failure_stage=None,
                workflow_id=config.workflow_id,
                mutation_attempted=True,
                restored_semantically=recovery_proof.restored_semantically,
                full_exact=recovery_proof.full_exact,
                server_metadata_drift_only=recovery_proof.server_metadata_drift_only,
                recovery_proof_succeeded=True,
                now=now,
                forbidden=(api_key, webhook_uri, header),
            )
        raise Refusal("the minimal update failed; Workflow recovery was proven") from update_error
    evidence = {
        "schema_version": 1,
        "artifact_kind": "shuffle-observe-only-g1-apply",
        "created_at_utc": utc_text(now()),
        "workflow_id": config.workflow_id,
        "webhook_id": config.webhook_id,
        "before_canonical_sha256": canonical_sha256(original),
        "precondition_full_exact": precondition_proof.full_exact,
        "precondition_server_metadata_drift_only": (
            precondition_proof.server_metadata_drift_only
        ),
        "submitted_canonical_sha256": canonical_sha256(updated),
        "readback_canonical_sha256": canonical_sha256(readback),
        "full_exact": readback_proof.full_exact,
        "server_metadata_drift_only": readback_proof.server_metadata_drift_only,
        "structural_change_count": 1,
        "changed_field": "actions[0].parameters[0].value",
        "call_is_exec": True,
        "trigger_status_preserved": True,
        "workflow_shape": readback_projection,
        "unexpected_action_count": 0,
        "secret_persisted_in_evidence": False,
    }
    write_evidence(evidence_path, evidence, (api_key, webhook_uri, header))
    return evidence


def rollback(
    config: Configuration,
    snapshot_path: Path,
    evidence_path: Path,
    secrets_backend: DpapiSecrets,
    http: SafeHttp,
    *,
    now: Callable[[], datetime] = utc_now,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    _, original = _load_snapshot(snapshot_path, config, secrets_backend)
    api_key, webhook_uri, header = _secret_material(secrets_backend, config)
    inspect_workflow(original, config, header)
    try:
        readback, proof = restore_and_prove(
            http,
            config,
            api_key,
            header,
            original,
            deadline=clock() + (2 * _http_timeout_seconds(http)) + 1,
            clock=clock,
        )
    except RestoreFailure as error:
        _write_recovery_evidence(
            evidence_path,
            gate="ROLLBACK",
            initial_failure_stage="explicit_rollback",
            initial_failure_category="rollback_requested",
            recovery_failure_stage=error.stage,
            workflow_id=config.workflow_id,
            mutation_attempted=error.mutation_attempted,
            restored_semantically=error.restored_semantically,
            full_exact=error.full_exact,
            server_metadata_drift_only=False,
            recovery_proof_succeeded=False,
            now=now,
            forbidden=(api_key, webhook_uri, header),
        )
        raise RecoveryFailure("explicit Workflow rollback was not proven") from error
    evidence = {
        "schema_version": 1,
        "artifact_kind": "shuffle-observe-only-rollback",
        "created_at_utc": utc_text(now()),
        "workflow_id": config.workflow_id,
        "target_canonical_sha256": canonical_sha256(original),
        "readback_canonical_sha256": canonical_sha256(readback),
        "restored_semantically": proof.restored_semantically,
        "full_exact": proof.full_exact,
        "server_metadata_drift_only": proof.server_metadata_drift_only,
        "secret_persisted_in_evidence": False,
    }
    write_evidence(evidence_path, evidence, (api_key, webhook_uri, header))
    return evidence


def _required_keys(schema: dict[str, Any], section: str | None = None) -> set[str]:
    node = schema if section is None else schema["properties"][section]
    return set(node.get("required", []))


def assert_approved_sources(schema_path: Path, sanitizer_path: Path) -> dict[str, Any]:
    schema = load_json_file(schema_path)
    if not isinstance(schema, dict):
        raise Refusal("the approved sanitized Alert schema is invalid")
    expected_top = {
        "schema_version", "source_system", "sent_at_utc", "account_alias",
        "aws_account_id", "aws_region", "scenario_id", "rule", "incident", "integrity",
    }
    if (
        schema.get("additionalProperties") is not False
        or _required_keys(schema) != expected_top
        or _required_keys(schema, "rule") != {"id", "level"}
        or _required_keys(schema, "incident") != {
            "take_id", "event_id", "wazuh_alert_id", "event_time_utc", "result", "route"
        }
        or _required_keys(schema, "integrity") != {"raw_message_sha256", "body_sha256"}
    ):
        raise Refusal("the approved sanitized Alert schema shape changed")
    try:
        sanitizer = sanitizer_path.read_text(encoding="utf-8")
    except OSError as error:
        raise Refusal("the approved Wazuh sanitizer source is unavailable") from error
    required_tokens = (
        'EXPECTED_RULE_ID = "100103"',
        'EXPECTED_RULE_LEVEL = 10',
        'EXPECTED_ACCOUNT_ID = "433048100798"',
        'EXPECTED_REGION = "ap-northeast-2"',
        'body_sha256 = hashlib.sha256(canonical_json(sanitized)).hexdigest()',
    )
    if any(token not in sanitizer for token in required_tokens):
        raise Refusal("the approved Wazuh sanitizer contract changed")
    return schema


def build_synthetic_payload(
    *,
    now: datetime | None = None,
    nonce: str | None = None,
    schema_path: Path = SCHEMA_PATH,
    sanitizer_path: Path = SANITIZER_PATH,
) -> dict[str, Any]:
    schema = assert_approved_sources(schema_path, sanitizer_path)
    moment = now or utc_now()
    token = nonce or secrets.token_hex(16)
    digest = sha256_bytes(token.encode("utf-8"))
    payload: dict[str, Any] = {
        "schema_version": 1,
        "source_system": "wazuh",
        "sent_at_utc": utc_text(moment),
        "account_alias": "primary-lab",
        "aws_account_id": "433048100798",
        "aws_region": "ap-northeast-2",
        "scenario_id": "CAPITAL-ONE",
        "rule": {"id": "100103", "level": 10},
        "incident": {
            "take_id": "capital-one-"
            + moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
            + digest[:8],
            "event_id": "cwl:433048100798:/aws/eks/aws-topology-primary/application:observe-only:"
            + digest[:24],
            "wazuh_alert_id": f"{int(moment.timestamp())}.{int(digest[:8], 16)}",
            "event_time_utc": utc_text(moment),
            "result": "succeeded",
            "route": "/vulnerabilities/exec/",
        },
        "integrity": {"raw_message_sha256": digest},
    }
    payload["integrity"]["body_sha256"] = canonical_sha256(payload)
    validate_synthetic_payload(payload, schema)
    return payload


def validate_synthetic_payload(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    if set(payload) != _required_keys(schema):
        raise Refusal("synthetic payload top-level fields do not match the approved schema")
    if set(payload["rule"]) != _required_keys(schema, "rule"):
        raise Refusal("synthetic payload rule fields do not match the approved schema")
    if set(payload["incident"]) != _required_keys(schema, "incident"):
        raise Refusal("synthetic payload incident fields do not match the approved schema")
    if set(payload["integrity"]) != _required_keys(schema, "integrity"):
        raise Refusal("synthetic payload integrity fields do not match the approved schema")
    expected = copy.deepcopy(payload)
    supplied_hash = expected["integrity"].pop("body_sha256")
    if supplied_hash != canonical_sha256(expected):
        raise Refusal("synthetic payload body_sha256 does not use the sanitizer rule")
    serialized = canonical_bytes(payload).decode("utf-8").lower()
    for forbidden in ("full_log", "command", "cookie", "token", "credential", "authorization"):
        if f'"{forbidden}"' in serialized:
            raise Refusal("synthetic payload contains a forbidden field")
    _validate_schema_value(payload, schema, "payload")


def _validate_schema_value(value: Any, schema: dict[str, Any], path: str) -> None:
    """Validate the bounded JSON-Schema subset used by sanitized-alert.schema.json."""
    if "const" in schema and value != schema["const"]:
        raise Refusal(f"{path} violates an approved schema constant")
    expected_type = schema.get("type")
    matches_type = {
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
    }.get(expected_type, True)
    if not matches_type:
        raise Refusal(f"{path} violates an approved schema type")
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise Refusal(f"{path} violates an approved minimum length")
        if len(value) > int(schema.get("maxLength", len(value))):
            raise Refusal(f"{path} violates an approved maximum length")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            raise Refusal(f"{path} violates an approved schema pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise Refusal(f"{path} violates an approved minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise Refusal(f"{path} violates an approved maximum")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        if not required.issubset(value):
            raise Refusal(f"{path} lacks an approved required field")
        if schema.get("additionalProperties") is False and not set(value).issubset(properties):
            raise Refusal(f"{path} contains a field outside the approved schema")
        for key, child in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _validate_schema_value(child, child_schema, f"{path}.{key}")


def decode_json_once(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, str):
        if len(value) > MAX_EVIDENCE_BYTES:
            raise Refusal(f"{label} exceeded the fixed size limit")
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise Refusal(f"{label} is not JSON") from error
        if isinstance(value, str):
            raise Refusal(f"{label} is double-encoded JSON")
    if not isinstance(value, dict):
        raise Refusal(f"{label} is not a JSON object")
    return value


def _reference_from(value: Any) -> tuple[str | None, str | None]:
    queue = [value]
    visited = 0
    while queue and visited < 128:
        visited += 1
        current = queue.pop(0)
        if isinstance(current, dict):
            candidate = current.get("execution_id")
            if isinstance(candidate, str) and UUID_PATTERN.fullmatch(candidate):
                authorization = current.get("authorization")
                if not isinstance(authorization, str) or not UUID_PATTERN.fullmatch(authorization):
                    authorization = None
                return candidate, authorization
            queue.extend(current.values())
        elif isinstance(current, list):
            queue.extend(current)
    return None, None


def _new_executions(
    items: list[dict[str, Any]], baseline: set[str]
) -> list[dict[str, Any]]:
    return [item for item in items if execution_id(item) not in baseline]


def _wait_for_one_execution(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    baseline: set[str],
    deadline: float,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    interval: float,
) -> dict[str, Any]:
    while True:
        if clock() >= deadline:
            raise Refusal("one Webhook POST did not create exactly one new Execution in time")
        new = _new_executions(
            _api_executions(
                http, config, api_key, deadline=deadline, clock=clock
            ),
            baseline,
        )
        if clock() > deadline:
            raise Refusal("one Webhook POST did not create exactly one new Execution in time")
        if len(new) > 1:
            raise Refusal("one Webhook POST created more than one new Execution")
        if len(new) == 1:
            return new[0]
        sleep(min(interval, max(0.0, deadline - clock())))


def _wait_for_finished_result(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    reference: dict[str, Any],
    response_value: Any,
    deadline: float,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    interval: float,
) -> tuple[dict[str, Any], str]:
    response_id, response_auth = _reference_from(response_value)
    expected_id = execution_id(reference)
    if response_id is not None and response_id != expected_id:
        raise Refusal("Webhook response referenced a different Execution")
    authorization = response_auth or reference.get("authorization")
    if not isinstance(authorization, str) or not UUID_PATTERN.fullmatch(authorization):
        raise Refusal("the new Execution lacks bounded results authorization")
    while True:
        if clock() >= deadline:
            raise Refusal("the OBSERVE_ONLY Execution did not reach FINISHED in time")
        value = http.api(
            "POST",
            "/api/v1/streams/results",
            api_key,
            config.org_id,
            {"execution_id": expected_id, "authorization": authorization},
            deadline=deadline,
            clock=clock,
        )
        if clock() > deadline:
            raise Refusal("the OBSERVE_ONLY Execution did not reach FINISHED in time")
        if not isinstance(value, dict) or execution_id(value) != expected_id:
            raise Refusal("Shuffle returned results for a different Execution")
        status = str(value.get("status", ""))
        if status in {"ABORTED", "FAILED", "FAILURE"}:
            raise Refusal("the OBSERVE_ONLY Execution failed")
        if status == "FINISHED":
            return value, authorization
        sleep(min(interval, max(0.0, deadline - clock())))


def _observation_new_ids(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    baseline: set[str],
    total_deadline: float,
    *,
    clock: Callable[[], float],
    request_failure_category: str,
) -> set[str]:
    if clock() >= total_deadline:
        raise Gate2CategoryFailure("case_deadline")
    try:
        items = _api_executions(
            http,
            config,
            api_key,
            deadline=total_deadline,
            clock=clock,
        )
    except Exception as error:
        category = (
            "case_deadline" if clock() >= total_deadline
            else request_failure_category
        )
        raise Gate2CategoryFailure(category) from error
    return {
        execution_id(item) for item in _new_executions(items, baseline)
    }


def _observe_singleton_execution(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    baseline: set[str],
    expected_id: str,
    observation_end: float,
    total_deadline: float,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    interval: float,
) -> int:
    observations = 0
    observed_ids: set[str] = set()
    while clock() < observation_end:
        new_ids = _observation_new_ids(
            http,
            config,
            api_key,
            baseline,
            total_deadline,
            clock=clock,
            request_failure_category="singleton_request_failed",
        )
        observations += 1
        if new_ids - {expected_id}:
            raise Gate2CategoryFailure("singleton_set_changed")
        observed_ids.update(new_ids)
        if clock() >= observation_end:
            break
        sleep(min(interval, max(0.0, observation_end - clock())))

    final_ids = _observation_new_ids(
        http,
        config,
        api_key,
        baseline,
        total_deadline,
        clock=clock,
        request_failure_category="singleton_request_failed",
    )
    observations += 1
    if final_ids - {expected_id}:
        raise Gate2CategoryFailure("singleton_set_changed")
    observed_ids.update(final_ids)
    if final_ids != {expected_id} or observed_ids != {expected_id}:
        raise Gate2CategoryFailure("singleton_final_missing")
    return observations


def _repeat_result(
    execution: dict[str, Any],
    repeat_action_id: str,
    repeat_action_label: str,
    webhook_id: str,
) -> Any:
    if "results" not in execution or execution.get("results") is None:
        raise RepeatResultNotReady("Action results are not ready")
    results = execution["results"]
    if not isinstance(results, list):
        raise Refusal("the finished Execution contains malformed Action results")
    if not results:
        raise RepeatResultNotReady("Action results are not ready")
    repeats: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise Refusal("the finished Execution contains an invalid Action result")
        action = result.get("action")
        action_id = result.get("action_id")
        label = result.get("label")
        if isinstance(action, str):
            action_id = action
        elif isinstance(action, dict):
            action_id = action.get("id", action_id)
            label = action.get("label", label)
        is_repeat = action_id == repeat_action_id
        if is_repeat:
            if label not in (None, "") and label != repeat_action_label:
                raise Refusal("the repeat Action result label is inconsistent")
            repeats.append(result)
        elif action_id == webhook_id:
            continue
        else:
            raise Refusal("the Execution contains an unexpected Action result")
    if not repeats:
        raise RepeatResultNotReady("repeat_back_to_me is not ready")
    if len(repeats) != 1:
        raise Refusal("repeat_back_to_me returned duplicate Action results")
    status = str(repeats[0].get("status", ""))
    if status in REPEAT_NONTERMINAL_STATUSES:
        raise RepeatResultNotReady("repeat_back_to_me is not ready")
    if status != "SUCCESS":
        raise Refusal("repeat_back_to_me reached a terminal failure")
    if "result" not in repeats[0]:
        raise RepeatResultNotReady("repeat_back_to_me result is not ready")
    return repeats[0]["result"]


def _result_readiness(observations: int, ready: bool) -> dict[str, Any]:
    return {
        "observation_count": observations,
        "execution_finished_seen": True,
        "repeat_ready": ready,
    }


def _request_finished_execution_result(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    execution: str,
    authorization: str,
    total_deadline: float,
    *,
    clock: Callable[[], float],
) -> dict[str, Any]:
    if clock() >= total_deadline:
        raise Refusal("the result-readiness deadline expired before request")
    value = http.api(
        "POST",
        "/api/v1/streams/results",
        api_key,
        config.org_id,
        {"execution_id": execution, "authorization": authorization},
        deadline=total_deadline,
        clock=clock,
    )
    if clock() > total_deadline:
        raise Refusal("the result-readiness deadline expired")
    if not isinstance(value, dict) or execution_id(value) != execution:
        raise Refusal("Shuffle returned results for a different Execution")
    if str(value.get("status", "")) != "FINISHED":
        raise Refusal("the finished Execution result contract regressed")
    return value


def _wait_for_repeat_result_ready(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    initial: dict[str, Any],
    authorization: str,
    repeat_action_id: str,
    repeat_action_label: str,
    webhook_id: str,
    observation_end: float,
    total_deadline: float,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    interval: float,
) -> tuple[dict[str, Any], Any, int]:
    expected_id = execution_id(initial)
    observations = 1

    def inspect(value: dict[str, Any]) -> tuple[bool, Any]:
        try:
            return True, _repeat_result(
                value, repeat_action_id, repeat_action_label, webhook_id
            )
        except RepeatResultNotReady:
            return False, None
        except Exception as error:
            raise Gate2CategoryFailure(
                "repeat_contract_failed",
                result_readiness=_result_readiness(observations, False),
            ) from error

    ready, repeat = inspect(initial)
    if ready:
        return initial, repeat, observations

    def request() -> dict[str, Any]:
        try:
            return _request_finished_execution_result(
                http,
                config,
                api_key,
                expected_id,
                authorization,
                total_deadline,
                clock=clock,
            )
        except Exception as error:
            category = (
                "repeat_contract_timeout"
                if clock() >= total_deadline
                else "repeat_contract_failed"
            )
            raise Gate2CategoryFailure(
                category,
                result_readiness=_result_readiness(observations, False),
            ) from error

    while clock() < observation_end and clock() < total_deadline:
        sleep(
            min(
                interval,
                max(0.0, observation_end - clock()),
                max(0.0, total_deadline - clock()),
            )
        )
        if clock() >= observation_end or clock() >= total_deadline:
            break
        value = request()
        observations += 1
        ready, repeat = inspect(value)
        if ready:
            return value, repeat, observations

    value = request()
    observations += 1
    ready, repeat = inspect(value)
    if not ready:
        raise Gate2CategoryFailure(
            "repeat_contract_timeout",
            result_readiness=_result_readiness(observations, False),
        )
    return value, repeat, observations


def _observe_zero_new(
    http: SafeHttp,
    config: Configuration,
    api_key: str,
    baseline: set[str],
    observation_end: float,
    total_deadline: float,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    interval: float,
) -> int:
    observations = 0
    while clock() < observation_end:
        new_ids = _observation_new_ids(
            http,
            config,
            api_key,
            baseline,
            total_deadline,
            clock=clock,
            request_failure_category="negative_request_failed",
        )
        observations += 1
        if new_ids:
            raise Gate2CategoryFailure("negative_execution_observed")
        if clock() >= observation_end:
            break
        sleep(min(interval, max(0.0, observation_end - clock())))

    final_ids = _observation_new_ids(
        http,
        config,
        api_key,
        baseline,
        total_deadline,
        clock=clock,
        request_failure_category="negative_request_failed",
    )
    observations += 1
    if final_ids:
        raise Gate2CategoryFailure("negative_execution_observed")
    return observations


def _gate2(
    config: Configuration,
    snapshot_path: Path,
    evidence_path: Path,
    secrets_backend: DpapiSecrets,
    http: SafeHttp,
    *,
    poll_timeout: int = 60,
    poll_interval: float = 2.0,
    now: Callable[[], datetime] = utc_now,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    schema_path: Path = SCHEMA_PATH,
    sanitizer_path: Path = SANITIZER_PATH,
    snapshot_verified: bool = False,
    total_deadline: float | None = None,
    secret_material: tuple[str, str, str] | None = None,
) -> dict[str, Any]:
    if not 10 <= poll_timeout <= 300 or not 0.1 <= poll_interval <= 10:
        raise Refusal("Gate 2 polling bounds are unsafe")
    http_timeout = _http_timeout_seconds(http)
    cap_seconds = gate2_total_wall_cap_seconds(poll_timeout, http_timeout)
    if total_deadline is None:
        total_deadline = clock() + cap_seconds
    stage = "preflight"
    try:
        if not snapshot_verified:
            _load_snapshot(snapshot_path, config, secrets_backend)
        api_key, webhook_uri, header = secret_material or _secret_material(
            secrets_backend, config
        )
        workflow = _api_workflow(
            http, config, api_key, deadline=total_deadline, clock=clock
        )
        projection = inspect_workflow(workflow, config, header, expected_call="$exec")
        payload = build_synthetic_payload(
            now=now(), schema_path=schema_path, sanitizer_path=sanitizer_path
        )
        payload_hash = canonical_sha256(payload)

        stage = "valid_baseline"
        baseline_items = _api_executions(
            http, config, api_key, deadline=total_deadline, clock=clock
        )
        baseline = {execution_id(item) for item in baseline_items}
        started_wall = now()
        started = clock()
        stage = "valid_post"
        _ensure_deadline(total_deadline, clock)
        valid_response = http.webhook(
            webhook_uri,
            payload,
            header,
            deadline=total_deadline,
            clock=clock,
        )
        _ensure_deadline(total_deadline, clock)
        if not 200 <= valid_response.status < 300:
            raise Refusal("the valid authenticated Webhook request was rejected")
        execution_deadline = min(total_deadline, clock() + poll_timeout)
        stage = "valid_execution"
        reference = _wait_for_one_execution(
            http, config, api_key, baseline, execution_deadline,
            clock=clock, sleep=sleep, interval=poll_interval,
        )
        finished, results_authorization = _wait_for_finished_result(
            http, config, api_key, reference, valid_response.value, execution_deadline,
            clock=clock, sleep=sleep, interval=poll_interval,
        )
        valid_latency_ms = max(0, int((clock() - started) * 1000))
        initial_execution_argument = finished.get("execution_argument")
        stage = "valid_result_ready"
        finished, repeat_raw, result_ready_observations = _wait_for_repeat_result_ready(
            http,
            config,
            api_key,
            finished,
            results_authorization,
            projection["repeat_action_id"],
            projection["action_label"],
            config.webhook_id,
            clock() + poll_timeout,
            total_deadline,
            clock=clock,
            sleep=sleep,
            interval=poll_interval,
        )
        result_readiness = _result_readiness(result_ready_observations, True)
        stage = "valid_singleton"
        singleton_deadline = min(total_deadline, clock() + poll_timeout)
        execution_observations = _observe_singleton_execution(
            http,
            config,
            api_key,
            baseline,
            execution_id(reference),
            singleton_deadline,
            total_deadline,
            clock=clock,
            sleep=sleep,
            interval=poll_interval,
        )
        stage = "valid_semantic"
        semantic_diagnostic: dict[str, Any] = {
            "request_canonical_sha256": payload_hash,
        }
        try:
            argument = decode_json_once(
                finished.get("execution_argument", initial_execution_argument),
                "Execution Argument",
            )
            semantic_diagnostic["argument_canonical_sha256"] = canonical_sha256(
                argument
            )
            semantic_diagnostic["request_equals_argument"] = payload == argument
            semantic_diagnostic["request_argument_diff"] = semantic_diff_summary(
                payload, argument
            )
        except Exception as error:
            raise Gate2CategoryFailure(
                "argument_decode_failed",
                semantic_diagnostic,
                result_readiness=result_readiness,
            ) from error
        try:
            repeat = decode_json_once(repeat_raw, "repeat_back_to_me result")
            semantic_diagnostic["repeat_canonical_sha256"] = canonical_sha256(repeat)
        except Exception as error:
            raise Gate2CategoryFailure(
                "repeat_decode_failed",
                semantic_diagnostic,
                result_readiness=result_readiness,
            ) from error
        if payload != argument:
            raise Gate2CategoryFailure(
                "request_argument_mismatch",
                semantic_diagnostic,
                result_readiness=result_readiness,
            )
        semantic_diagnostic["argument_equals_repeat"] = argument == repeat
        semantic_diagnostic["argument_repeat_diff"] = semantic_diff_summary(
            argument, repeat
        )
        if argument != repeat:
            raise Gate2CategoryFailure(
                "argument_repeat_mismatch",
                semantic_diagnostic,
                result_readiness=result_readiness,
            )

        negative: list[dict[str, Any]] = []
        wrong_header = "wrong-" + secrets.token_hex(16)
        while wrong_header == header:
            wrong_header = "wrong-" + secrets.token_hex(16)
        for case, value, prefix in (
            ("wrong-header", wrong_header, "wrong"),
            ("missing-header", None, "missing"),
        ):
            stage = f"{prefix}_baseline"
            fresh_items = _api_executions(
                http, config, api_key, deadline=total_deadline, clock=clock
            )
            fresh_baseline = {execution_id(item) for item in fresh_items}
            stage = f"{prefix}_post"
            _ensure_deadline(total_deadline, clock)
            response = http.webhook(
                webhook_uri,
                payload,
                value,
                deadline=total_deadline,
                clock=clock,
            )
            _ensure_deadline(total_deadline, clock)
            if 200 <= response.status < 300:
                raise Refusal(f"the {case} Webhook request was not rejected")
            stage = f"{prefix}_observation"
            observations = _observe_zero_new(
                http,
                config,
                api_key,
                fresh_baseline,
                min(total_deadline, clock() + poll_timeout),
                total_deadline,
                clock=clock,
                sleep=sleep,
                interval=poll_interval,
            )
            negative.append(
                {
                    "case": case,
                    "http_success": False,
                    "new_execution_count": 0,
                    "observation_count": observations,
                }
            )

        completed_wall = now()
        execution = execution_id(finished)
        evidence = {
            "schema_version": 1,
            "artifact_kind": "shuffle-observe-only-gate2",
            "created_at_utc": utc_text(completed_wall),
            "workflow_id": config.workflow_id,
            "webhook_id": config.webhook_id,
            "payload_canonical_sha256": payload_hash,
            "poll_timeout_seconds_per_window": poll_timeout,
            "total_wall_cap_seconds": cap_seconds,
            "valid_header": {
                "http_success": True,
                "new_execution_count": 1,
                "execution_observation_count": execution_observations,
                "result_readiness_observation_count": result_ready_observations,
                "result_ready": True,
                "execution_id": execution,
                "execution_status": "FINISHED",
                "repeat_status": "SUCCESS",
                "started_at": finished.get("started_at"),
                "completed_at": finished.get("completed_at"),
                "observed_at_utc": utc_text(started_wall),
                "latency_ms": valid_latency_ms,
                "request_equals_argument": True,
                "argument_equals_repeat_result": True,
            },
            "authentication_negative_cases": negative,
            "unexpected_action_count": 0,
            "unexpected_side_effect_count": 0,
            "secret_persisted_in_evidence": False,
        }
        stage = "evidence_write"
        write_evidence(evidence_path, evidence, (api_key, webhook_uri, header))
        return evidence
    except Gate2StageFailure:
        raise
    except Gate2CategoryFailure as error:
        raise Gate2StageFailure(
            stage,
            error.category,
            error.semantic_diagnostic,
            error.result_readiness,
        ) from error
    except Exception as error:
        raise Gate2StageFailure(stage) from error


def gate2_total_wall_cap_seconds(poll_timeout: int, http_timeout: float) -> float:
    """Five windows plus DPAPI, setup, poll overrun, and final GET budgets."""
    return float(
        (4 * DPAPI_TIMEOUT_SECONDS)
        + (5 * poll_timeout)
        + (15 * http_timeout)
    )


def gate2(
    config: Configuration,
    snapshot_path: Path,
    evidence_path: Path,
    secrets_backend: DpapiSecrets,
    http: SafeHttp,
    *,
    poll_timeout: int = 60,
    poll_interval: float = 2.0,
    now: Callable[[], datetime] = utc_now,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    schema_path: Path = SCHEMA_PATH,
    sanitizer_path: Path = SANITIZER_PATH,
) -> dict[str, Any]:
    if not 10 <= poll_timeout <= 300 or not 0.1 <= poll_interval <= 10:
        raise Refusal("Gate 2 polling bounds are unsafe")
    http_timeout = _http_timeout_seconds(http)
    total_deadline = clock() + gate2_total_wall_cap_seconds(
        poll_timeout, http_timeout
    )
    _, original = _load_snapshot(snapshot_path, config, secrets_backend)
    material = _secret_material(secrets_backend, config)
    try:
        return _gate2(
            config,
            snapshot_path,
            evidence_path,
            secrets_backend,
            http,
            poll_timeout=poll_timeout,
            poll_interval=poll_interval,
            now=now,
            clock=clock,
            sleep=sleep,
            schema_path=schema_path,
            sanitizer_path=sanitizer_path,
            snapshot_verified=True,
            total_deadline=total_deadline,
            secret_material=material,
        )
    except Exception as gate_error:
        initial_stage = (
            gate_error.stage
            if isinstance(gate_error, Gate2StageFailure)
            else "unexpected"
        )
        initial_category = (
            gate_error.category
            if isinstance(gate_error, Gate2StageFailure)
            else "stage_failure"
        )
        semantic_diagnostic = (
            gate_error.semantic_diagnostic
            if isinstance(gate_error, Gate2StageFailure)
            else None
        )
        result_readiness = (
            gate_error.result_readiness
            if isinstance(gate_error, Gate2StageFailure)
            else None
        )
        recovery_path = evidence_path.with_name("gate2-recovery.json")
        api_key, webhook_uri, header = material
        try:
            _, recovery_proof = restore_and_prove(
                http,
                config,
                api_key,
                header,
                original,
                deadline=clock() + (2 * http_timeout) + 1,
                clock=clock,
            )
        except RestoreFailure as recovery_error:
            _write_recovery_evidence(
                recovery_path,
                gate="G2",
                initial_failure_stage=initial_stage,
                initial_failure_category=initial_category,
                recovery_failure_stage=recovery_error.stage,
                workflow_id=config.workflow_id,
                mutation_attempted=recovery_error.mutation_attempted,
                restored_semantically=recovery_error.restored_semantically,
                full_exact=recovery_error.full_exact,
                server_metadata_drift_only=False,
                recovery_proof_succeeded=False,
                now=now,
                forbidden=(api_key, webhook_uri, header),
                semantic_diagnostic=semantic_diagnostic,
                result_readiness=result_readiness,
            )
            raise RecoveryFailure(
                "Gate 2 failed and Workflow recovery was not proven"
            ) from recovery_error
        _write_recovery_evidence(
            recovery_path,
            gate="G2",
            initial_failure_stage=initial_stage,
            initial_failure_category=initial_category,
            recovery_failure_stage=None,
            workflow_id=config.workflow_id,
            mutation_attempted=True,
            restored_semantically=recovery_proof.restored_semantically,
            full_exact=recovery_proof.full_exact,
            server_metadata_drift_only=recovery_proof.server_metadata_drift_only,
            recovery_proof_succeeded=True,
            now=now,
            forbidden=(api_key, webhook_uri, header),
            semantic_diagnostic=semantic_diagnostic,
            result_readiness=result_readiness,
        )
        raise Refusal("Gate 2 failed; Workflow recovery was proven") from gate_error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("snapshot", "apply-minimal", "rollback", "gate2"))
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--rollback-name")
    parser.add_argument("--http-timeout", type=int, default=20)
    parser.add_argument("--poll-timeout", type=int, default=60)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_configuration(default_config_path().resolve())
    secrets_backend = DpapiSecrets(default_secret_root().resolve())
    http = SafeHttp(config.api_base, timeout=args.http_timeout)
    evidence_dir = args.evidence_dir.resolve()
    snapshot_path = evidence_dir / "g0-snapshot.json"
    if args.command == "snapshot":
        snapshot(
            config,
            snapshot_path,
            secrets_backend,
            http,
            rollback_name=args.rollback_name,
        )
    elif args.command == "apply-minimal":
        apply_minimal(
            config,
            snapshot_path,
            evidence_dir / "g1-apply.json",
            secrets_backend,
            http,
        )
    elif args.command == "rollback":
        rollback(
            config,
            snapshot_path,
            evidence_dir / "rollback.json",
            secrets_backend,
            http,
        )
    else:
        gate2(
            config,
            snapshot_path,
            evidence_dir / "gate2.json",
            secrets_backend,
            http,
            poll_timeout=args.poll_timeout,
            poll_interval=args.poll_interval,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"refused: {error}", file=sys.stderr)
        raise SystemExit(2)
