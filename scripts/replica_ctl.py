#!/usr/bin/env python3
"""Atomic, dependency-free state controller for Goal App Replica projects.

The controller deliberately stores only orchestration metadata.  Browser
profiles, cookies, tokens, passwords, captured customer records, and other
authentication material belong outside this workspace.
"""

from __future__ import annotations

import argparse
import copy
import datetime as _datetime
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit


SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 15 * 60
DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
DEFAULT_STALE_LOCK_SECONDS = 30.0
SUPPORTED_PLATFORMS = ("web", "windows", "macos", "android", "ios")
TASK_STATES = {"ready", "claimed", "review", "done", "blocked"}
TASK_KINDS = {
    "generic",
    "core_contract_builder",
    "web_foundation",
    "web_builder",
    "web_structure_builder",
    "web_qa",
}
WEB_FIDELITY_LEVELS = {"functional", "visual", "pixel"}
ASSET_RIGHTS_LEVELS = {"user_owned", "licensed", "explicit_authorized", "reference_only", "unknown"}
GAP_STATES = {"open", "closed"}
RUN_STATES = {"active", "paused", "blocked", "stopped", "complete"}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ReplicaCtlError(Exception):
    """An expected, safe-to-display controller error."""

    def __init__(self, message: str, code: str = "operation_failed") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class StateValidationError(ReplicaCtlError):
    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__(
            "State validation failed; run validate for details.",
            code="invalid_state",
        )


class LockTimeoutError(ReplicaCtlError):
    def __init__(self, path: Path) -> None:
        super().__init__(
            "Timed out waiting for the short-lived state lock at %s" % path,
            code="lock_timeout",
        )


def utc_now() -> _datetime.datetime:
    return _datetime.datetime.now(_datetime.timezone.utc)


def _coerce_utc(value: Optional[_datetime.datetime]) -> _datetime.datetime:
    value = value or utc_now()
    if value.tzinfo is None:
        value = value.replace(tzinfo=_datetime.timezone.utc)
    return value.astimezone(_datetime.timezone.utc)


def format_time(value: Optional[_datetime.datetime] = None) -> str:
    value = _coerce_utc(value)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> _datetime.datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp is not a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = _datetime.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(_datetime.timezone.utc)


def _new_id(prefix: str) -> str:
    stamp = utc_now().strftime("%Y%m%dT%H%M%S")
    return "%s-%s-%s" % (prefix, stamp, uuid.uuid4().hex[:10])


def _clean_list(values: Optional[Iterable[str]], field: str) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values or []:
        if not isinstance(value, str) or not value.strip():
            raise ReplicaCtlError("%s entries must be non-empty strings" % field, "invalid_input")
        value = value.strip()
        assert_safe_text(field, value)
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


_FORBIDDEN_KEYS = {
    "password",
    "passwd",
    "pwd",
    "cookie",
    "cookies",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "client_secret",
    "secret",
    "authorization",
    "session_storage",
    "local_storage",
    "credential",
    "credentials",
    "private_key",
}
_SAFE_REDACTIONS = {"<redacted>", "[redacted]", "redacted", "none", "not-stored", "not_stored"}
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)(?:\b(?:password|passwd|pwd|secret|access[ _-]?token|refresh[ _-]?token|"
    r"id[ _-]?token|api[ _-]?key|authorization|cookie|set-cookie)\b\s*[:=]\s*)"
    r"([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+([^\s,;]+)")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----")


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _unsafe_text_reason(value: str) -> Optional[str]:
    if "\x00" in value:
        return "contains a NUL byte"
    if _PRIVATE_KEY_RE.search(value):
        return "looks like private-key material"
    for regex in (_ASSIGNMENT_SECRET_RE, _BEARER_RE):
        match = regex.search(value)
        if match and match.group(1).strip().lower() not in _SAFE_REDACTIONS:
            return "looks like credential material"

    # URL user-info and sensitive query keys are easy to leak accidentally.
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme and parsed.netloc:
        try:
            if parsed.username is not None or parsed.password is not None:
                return "contains URL user-info"
        except ValueError:
            return "contains invalid URL user-info"
        for key, query_value in parse_qsl(parsed.query, keep_blank_values=True):
            if _normalized_key(key) in _FORBIDDEN_KEYS and query_value.lower() not in _SAFE_REDACTIONS:
                return "contains a sensitive URL query parameter"
    return None


def assert_safe_text(field: str, value: Optional[str], maximum: int = 20000) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ReplicaCtlError("%s must be a string" % field, "invalid_input")
    if len(value) > maximum:
        raise ReplicaCtlError("%s is too long" % field, "invalid_input")
    reason = _unsafe_text_reason(value)
    if reason:
        # Never include the unsafe value itself in an error or event.
        raise ReplicaCtlError(
            "%s %s; credentials and session material must stay outside state" % (field, reason),
            "sensitive_input_rejected",
        )


def _sensitive_state_errors(value: Any, path: str = "$") -> List[str]:
    errors: List[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = "%s.%s" % (path, key_text)
            if _normalized_key(key_text) in _FORBIDDEN_KEYS:
                errors.append("%s uses a forbidden credential field" % child_path)
                continue
            errors.extend(_sensitive_state_errors(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_sensitive_state_errors(child, "%s[%d]" % (path, index)))
    elif isinstance(value, str):
        reason = _unsafe_text_reason(value)
        if reason:
            errors.append("%s %s" % (path, reason))
    return errors


def _safe_component(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReplicaCtlError("%s must be a non-empty string" % field, "invalid_input")
    if value != value.strip():
        raise ReplicaCtlError("%s cannot begin or end with whitespace" % field, "invalid_input")
    assert_safe_text(field, value, maximum=128)
    windows_forbidden = set('<>:"/\\|?*')
    if (
        value in {".", ".."}
        or value.endswith((".", " "))
        or any(char in windows_forbidden or unicodedata.category(char) == "Cc" for char in value)
    ):
        raise ReplicaCtlError("%s must be a single safe path component" % field, "invalid_input")
    windows_device_name = value.split(".", 1)[0].upper()
    if windows_device_name in {"CON", "PRN", "AUX", "NUL", "CLOCK$"} or re.fullmatch(
        r"(?:COM|LPT)[1-9]", windows_device_name
    ):
        raise ReplicaCtlError("%s is a reserved Windows device name" % field, "invalid_input")
    return value


def _canonical_path(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReplicaCtlError("%s must be a non-empty path" % field, "invalid_input")
    assert_safe_text(field, value)
    return str(Path(value).expanduser().resolve(strict=False))


def _is_project_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        return False
    windows_path = PureWindowsPath(value)
    posix_path = PurePosixPath(value.replace("\\", "/"))
    if windows_path.is_absolute() or windows_path.drive or posix_path.is_absolute():
        return False
    return all(part not in {".", ".."} for part in posix_path.parts)


def _is_core_contract_editable_path(value: Any) -> bool:
    if not _is_project_relative_path(value):
        return False
    path = PurePosixPath(value.replace("\\", "/"))
    allowed_roots = (PurePosixPath("src/core"), PurePosixPath("test/core"))
    return any(path == root or root in path.parents for root in allowed_roots)


def _verify_core_contract_editable_paths(editable_paths: Any) -> None:
    if not isinstance(editable_paths, list) or not editable_paths:
        raise ReplicaCtlError(
            "core_contract_builder requires at least one editable path under src/core or test/core",
            "gate_blocked",
        )
    invalid = [path for path in editable_paths if not _is_core_contract_editable_path(path)]
    if invalid:
        raise ReplicaCtlError(
            "core_contract_builder editable paths are limited to src/core and test/core",
            "gate_blocked",
        )


def _verify_core_contract_forbidden_paths(forbidden_paths: Any) -> None:
    if not isinstance(forbidden_paths, list) or any(
        not _is_project_relative_path(path) for path in forbidden_paths
    ):
        raise ReplicaCtlError(
            "core_contract_builder forbidden paths must be project-root-relative paths",
            "gate_blocked",
        )


def _verify_core_contract_changed_files(
    editable_paths: Any,
    forbidden_paths: Any,
    changed_files: Any,
    *,
    require_non_empty: bool = False,
) -> None:
    _verify_core_contract_editable_paths(editable_paths)
    if not isinstance(changed_files, list):
        raise ReplicaCtlError(
            "core_contract_builder changed files must be an array",
            "gate_blocked",
        )
    if require_non_empty and not changed_files:
        raise ReplicaCtlError(
            "completed core_contract_builder handoffs require at least one changed file",
            "gate_blocked",
        )
    _verify_core_contract_forbidden_paths(forbidden_paths)
    invalid = [path for path in changed_files if not _is_core_contract_editable_path(path)]
    if invalid:
        raise ReplicaCtlError(
            "core_contract_builder changed files are limited to src/core and test/core",
            "gate_blocked",
        )
    editable_scopes = [PurePosixPath(path.replace("\\", "/")) for path in editable_paths]
    undeclared = []
    for value in changed_files:
        path = PurePosixPath(value.replace("\\", "/"))
        if not any(path == scope or scope in path.parents for scope in editable_scopes):
            undeclared.append(value)
    if undeclared:
        raise ReplicaCtlError(
            "core_contract_builder changed files must stay within declared editable paths",
            "gate_blocked",
        )
    forbidden_scopes = []
    for value in forbidden_paths:
        normalized = value.replace("\\", "/")
        if normalized.endswith("/**"):
            normalized = normalized[:-3]
        forbidden_scopes.append(PurePosixPath(normalized.casefold()))
    forbidden = []
    for value in changed_files:
        path = PurePosixPath(value.replace("\\", "/").casefold())
        if any(path == scope or scope in path.parents for scope in forbidden_scopes):
            forbidden.append(value)
    if forbidden:
        raise ReplicaCtlError(
            "core_contract_builder changed files cannot enter forbidden paths",
            "gate_blocked",
        )


def _strict_web_execution(state: Mapping[str, Any]) -> bool:
    project = state.get("project")
    if not isinstance(project, Mapping):
        return False
    policy = project.get("web")
    return bool(
        isinstance(policy, Mapping)
        and policy.get("workflow_version", 1) >= 2
        and policy.get("fidelity") in {"visual", "pixel"}
        and isinstance(project.get("reference"), Mapping)
        and project["reference"].get("platform") == "web"
        and isinstance(project.get("replica"), Mapping)
        and project["replica"].get("platform") == "web"
    )


def _reference_identity_fingerprint(identity: str) -> str:
    parsed = urlsplit(identity)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        public_identity = "%s://%s%s" % (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
        )
    else:
        public_identity = identity.strip()
    return hashlib.sha256(public_identity.encode("utf-8")).hexdigest()


def _verify_web_preflight(
    code_root: str,
    report_path: str,
    expected_sha256: str,
    expected_scope_id: str,
    expected_scope_kind: Optional[str] = None,
    expected_project_id: Optional[str] = None,
    expected_reference_fingerprint: Optional[str] = None,
    allowed_equivalence_scopes: Sequence[str] = ("declared_scope",),
) -> None:
    """Verify the exact passing Web fidelity Gate artifact bound to a task."""

    if not _is_project_relative_path(report_path):
        raise ReplicaCtlError(
            "Web Builder preflight report must be a project-root-relative path",
            "gate_blocked",
        )
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ReplicaCtlError("Web Builder preflight SHA-256 must be 64 hexadecimal characters", "gate_blocked")

    try:
        root = Path(code_root).expanduser().resolve(strict=True)
        target = (root / report_path).resolve(strict=True)
        target.relative_to(root)
        if not target.is_file():
            raise OSError("preflight path is not a file")
        content = target.read_bytes()
    except (OSError, ValueError):
        raise ReplicaCtlError("Web Builder preflight report is unavailable inside the project root", "gate_blocked")

    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256.lower() != expected_sha256.lower():
        raise ReplicaCtlError("Web Builder preflight report SHA-256 does not match", "gate_blocked")

    try:
        report = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReplicaCtlError("Web Builder preflight report is not valid UTF-8 JSON", "gate_blocked")
    if not isinstance(report, dict):
        raise ReplicaCtlError("Web Builder preflight report root must be an object", "gate_blocked")
    if (
        report.get("gate") != "web_fidelity_gate"
        or report.get("ok") is not True
        or report.get("status") != "pass"
        or report.get("stage") != "builder"
        or report.get("strong_mode") is not True
        or report.get("enforcement_mode") != "capture_bundle_v2"
        or report.get("equivalence_scope") not in set(allowed_equivalence_scopes)
        or not isinstance(report.get("manifest_sha256"), str)
        or not SHA256_RE.fullmatch(report.get("manifest_sha256", ""))
        or not _is_project_relative_path(report.get("manifest_relative_path"))
        or report.get("scope_id") != expected_scope_id
        or (expected_scope_kind is not None and report.get("scope_kind") != expected_scope_kind)
        or (expected_project_id is not None and report.get("project_id") != expected_project_id)
        or (expected_reference_fingerprint is not None and report.get("reference_fingerprint") != expected_reference_fingerprint)
    ):
        raise ReplicaCtlError(
            "Web Builder preflight Gate has not passed capture_bundle_v2 strong enforcement",
            "gate_blocked",
        )

    try:
        manifest_path = (root / report["manifest_relative_path"]).resolve(strict=True)
        manifest_path.relative_to(root)
        if not manifest_path.is_file():
            raise OSError("manifest path is not a file")
        current_manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except (OSError, ValueError):
        raise ReplicaCtlError("Web Builder preflight Manifest is unavailable inside the project root", "gate_blocked")
    if current_manifest_sha256.lower() != report["manifest_sha256"].lower():
        raise ReplicaCtlError("Web Builder preflight Manifest has changed since Gate evaluation", "gate_blocked")

    gate_script = Path(__file__).with_name("web_fidelity_gate.py")
    try:
        specification = importlib.util.spec_from_file_location("goal_app_replica_web_fidelity_gate", gate_script)
        if specification is None or specification.loader is None:
            raise OSError("gate module unavailable")
        gate_module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(gate_module)
        current_report, current_exit = gate_module.run_gate(manifest_path, root, "builder")
    except Exception as exc:
        raise ReplicaCtlError("Web Builder preflight could not be re-evaluated", "gate_blocked") from exc
    if (
        current_exit != 0
        or current_report.get("ok") is not True
        or current_report.get("status") != "pass"
        or current_report.get("strong_mode") is not True
        or current_report.get("enforcement_mode") != "capture_bundle_v2"
        or current_report.get("equivalence_scope") not in set(allowed_equivalence_scopes)
        or current_report.get("equivalence_scope") != report.get("equivalence_scope")
        or current_report.get("scope_id") != expected_scope_id
        or (expected_scope_kind is not None and current_report.get("scope_kind") != expected_scope_kind)
        or (expected_project_id is not None and current_report.get("project_id") != expected_project_id)
        or (expected_reference_fingerprint is not None and current_report.get("reference_fingerprint") != expected_reference_fingerprint)
        or current_report.get("manifest_sha256") != report.get("manifest_sha256")
    ):
        raise ReplicaCtlError(
            "Web Builder preflight artifacts no longer pass capture_bundle_v2 strong enforcement",
            "gate_blocked",
        )


def _verify_web_qa_report(
    code_root: str,
    report_path: str,
    expected_sha256: str,
    require_declared_scope: bool,
) -> Dict[str, str]:
    """Verify and re-run the exact QA Gate report used to close a Web Gap."""

    if not _is_project_relative_path(report_path):
        raise ReplicaCtlError("Web QA report must be a project-root-relative path", "qa_evidence_required")
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ReplicaCtlError("Web QA report SHA-256 must be 64 hexadecimal characters", "qa_evidence_required")
    try:
        root = Path(code_root).expanduser().resolve(strict=True)
        target = (root / report_path).resolve(strict=True)
        target.relative_to(root)
        content = target.read_bytes()
        if hashlib.sha256(content).hexdigest().lower() != expected_sha256.lower():
            raise OSError("qa report hash mismatch")
        report = json.loads(content.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ReplicaCtlError("Web QA report is unavailable, changed, or invalid", "qa_evidence_required")
    if (
        not isinstance(report, dict)
        or report.get("gate") != "web_fidelity_gate"
        or report.get("stage") != "qa"
        or report.get("ok") is not True
        or report.get("status") != "pass"
        or not _is_project_relative_path(report.get("manifest_relative_path"))
    ):
        raise ReplicaCtlError("Web QA Gate has not passed", "qa_evidence_required")
    if require_declared_scope and (
        report.get("strong_mode") is not True
        or report.get("equivalence_scope") != "declared_scope"
    ):
        raise ReplicaCtlError("Strict Web QA requires strong declared-scope evidence", "qa_evidence_required")
    manifest_path = (root / report["manifest_relative_path"]).resolve(strict=True)
    try:
        manifest_path.relative_to(root)
    except ValueError as exc:
        raise ReplicaCtlError("Web QA Manifest escapes the project root", "qa_evidence_required") from exc
    gate_script = Path(__file__).with_name("web_fidelity_gate.py")
    try:
        specification = importlib.util.spec_from_file_location("goal_app_replica_web_fidelity_gate_qa", gate_script)
        if specification is None or specification.loader is None:
            raise OSError("gate module unavailable")
        gate_module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(gate_module)
        current_report, current_exit = gate_module.run_gate(manifest_path, root, "qa")
    except Exception as exc:
        raise ReplicaCtlError("Web QA Gate could not be re-evaluated", "qa_evidence_required") from exc
    if (
        current_exit != 0
        or current_report.get("ok") is not True
        or current_report.get("status") != "pass"
        or current_report.get("manifest_sha256") != report.get("manifest_sha256")
        or (require_declared_scope and (
            current_report.get("strong_mode") is not True
            or current_report.get("equivalence_scope") != "declared_scope"
        ))
    ):
        raise ReplicaCtlError("Web QA artifacts no longer pass the current Gate", "qa_evidence_required")
    return {"path": report_path, "sha256": expected_sha256.lower()}


def _fingerprint(project: Mapping[str, Any]) -> str:
    material = {
        "project_id": project.get("project_id"),
        "code_root": project.get("code_root"),
        "reference": project.get("reference"),
        "replica": project.get("replica"),
        "scope_id": project.get("scope_id"),
        "reference_write_policy": project.get("reference_write_policy"),
    }
    if "web" in project:
        material["web"] = project.get("web")
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:%s" % hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _workflow_v2_legacy_task_ids(state: Mapping[str, Any]) -> set:
    project = state.get("project")
    events = state.get("events")
    if not isinstance(project, Mapping) or not isinstance(events, list):
        return set()
    fingerprint = project.get("fingerprint")
    for event in reversed(events):
        if (
            isinstance(event, Mapping)
            and event.get("type") == "project_web_migrated"
            and event.get("new_fingerprint") == fingerprint
            and event.get("workflow_version") == 2
            and isinstance(event.get("legacy_task_ids"), list)
        ):
            return {
                task_id
                for task_id in event["legacy_task_ids"]
                if isinstance(task_id, str) and task_id
            }
    return set()


class ExclusiveFileLock:
    """Portable, short-lived lock based on O_CREAT | O_EXCL.

    The JSON state is never held open while external work runs.  The lock is
    acquired only for a read/check/replace transaction.  A token check keeps a
    stale holder from deleting a newer holder's lock.
    """

    def __init__(
        self,
        path: Path,
        timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
        stale_seconds: float = DEFAULT_STALE_LOCK_SECONDS,
    ) -> None:
        self.path = path
        self.timeout_seconds = max(0.0, float(timeout_seconds))
        self.stale_seconds = max(5.0, float(stale_seconds))
        self.token = uuid.uuid4().hex
        self.acquired = False

    def __enter__(self) -> "ExclusiveFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout_seconds
        payload = json.dumps(
            {"pid": os.getpid(), "created_at": format_time(), "lock_token": self.token},
            separators=(",", ":"),
        ).encode("utf-8")
        while True:
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                self._discard_stale_lock_if_safe()
                if time.monotonic() >= deadline:
                    raise LockTimeoutError(self.path)
                time.sleep(0.025)
                continue
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            self.acquired = True
            return self

    def _discard_stale_lock_if_safe(self) -> None:
        try:
            age = time.time() - self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if age <= self.stale_seconds:
            return
        quarantine = self.path.with_name("%s.stale-%s" % (self.path.name, uuid.uuid4().hex))
        try:
            os.replace(str(self.path), str(quarantine))
        except FileNotFoundError:
            return
        try:
            quarantine.unlink()
        except FileNotFoundError:
            pass

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if not self.acquired:
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            lock_data = json.loads(raw)
            owns_current_lock = lock_data.get("lock_token") == self.token
        except (OSError, ValueError, TypeError):
            owns_current_lock = False
        if owns_current_lock:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
        self.acquired = False


class StateStore:
    def __init__(
        self,
        state_path: Path,
        lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.state_path = state_path.resolve(strict=False)
        self.lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        self.lock_timeout_seconds = lock_timeout_seconds

    def lock(self) -> ExclusiveFileLock:
        return ExclusiveFileLock(self.lock_path, timeout_seconds=self.lock_timeout_seconds)

    def read_unvalidated(self) -> Dict[str, Any]:
        try:
            with self.state_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            raise ReplicaCtlError(
                "No replica state exists at %s; start the project first" % self.state_path,
                "state_not_found",
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ReplicaCtlError("Cannot read replica state: %s" % exc, "state_unreadable")
        if not isinstance(data, dict):
            raise ReplicaCtlError("Replica state root must be an object", "invalid_state")
        return data

    def read(self) -> Dict[str, Any]:
        state = self.read_unvalidated()
        errors = validate_state(state)
        if errors:
            raise StateValidationError(errors)
        return state

    def atomic_write(self, state: Mapping[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=".%s." % self.state_path.name,
            suffix=".tmp",
            dir=str(self.state_path.parent),
        )
        temporary_path = Path(temporary_name)
        try:
            try:
                os.chmod(str(temporary_path), 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(temporary_path), str(self.state_path))
            self._sync_parent_directory()
        except Exception:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise

    def _sync_parent_directory(self) -> None:
        if not hasattr(os, "O_DIRECTORY"):
            return
        try:
            fd = os.open(str(self.state_path.parent), os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def mutate(
        self,
        operation: Callable[[Dict[str, Any]], Tuple[Any, bool]],
        now: Optional[_datetime.datetime] = None,
    ) -> Any:
        mutation_time = _coerce_utc(now)
        with self.lock():
            state = self.read()
            result, changed = operation(state)
            if not changed:
                return result
            state["revision"] = int(state.get("revision", 0)) + 1
            state["updated_at"] = format_time(mutation_time)
            errors = validate_state(state)
            if errors:
                raise StateValidationError(errors)
            self.atomic_write(state)
            return result


def _is_dict(value: Any, errors: List[str], path: str) -> bool:
    if not isinstance(value, dict):
        errors.append("%s must be an object" % path)
        return False
    return True


def _is_list(value: Any, errors: List[str], path: str) -> bool:
    if not isinstance(value, list):
        errors.append("%s must be an array" % path)
        return False
    return True


def _valid_timestamp(value: Any, errors: List[str], path: str) -> None:
    try:
        parse_time(value)
    except (TypeError, ValueError):
        errors.append("%s must be an ISO-8601 timestamp with timezone" % path)


def validate_state(state: Any) -> List[str]:
    """Return invariant and secret-safety errors without exposing values."""

    errors: List[str] = []
    if not isinstance(state, dict):
        return ["$ must be an object"]
    errors.extend(_sensitive_state_errors(state))

    if state.get("schema_version") != SCHEMA_VERSION:
        errors.append("$.schema_version must equal %d" % SCHEMA_VERSION)
    if not isinstance(state.get("revision"), int) or isinstance(state.get("revision"), bool) or state.get("revision", 0) < 1:
        errors.append("$.revision must be a positive integer")
    _valid_timestamp(state.get("created_at"), errors, "$.created_at")
    _valid_timestamp(state.get("updated_at"), errors, "$.updated_at")

    project = state.get("project")
    if _is_dict(project, errors, "$.project"):
        for key in ("project_id", "code_root", "scope_id", "reference_write_policy", "fingerprint"):
            if not isinstance(project.get(key), str) or not project.get(key):
                errors.append("$.project.%s must be a non-empty string" % key)
        if project.get("reference_write_policy") not in {
            "read_only",
            "reversible_test_writes",
            "writable_test",
        }:
            errors.append("$.project.reference_write_policy is invalid")
        web = project.get("web")
        if web is not None:
            if _is_dict(web, errors, "$.project.web"):
                if web.get("fidelity") not in WEB_FIDELITY_LEVELS:
                    errors.append("$.project.web.fidelity is invalid")
                if web.get("asset_rights") not in ASSET_RIGHTS_LEVELS:
                    errors.append("$.project.web.asset_rights is invalid")
                if "workflow_version" in web and web.get("workflow_version") not in {1, 2}:
                    errors.append("$.project.web.workflow_version is invalid")
        for side in ("reference", "replica"):
            endpoint = project.get(side)
            if _is_dict(endpoint, errors, "$.project.%s" % side):
                if not isinstance(endpoint.get("identity"), str) or not endpoint.get("identity"):
                    errors.append("$.project.%s.identity must be a non-empty string" % side)
                if endpoint.get("platform") not in SUPPORTED_PLATFORMS:
                    errors.append("$.project.%s.platform is unsupported" % side)
        if all(
            key in project
            for key in (
                "project_id",
                "code_root",
                "reference",
                "replica",
                "scope_id",
                "reference_write_policy",
                "fingerprint",
            )
        ):
            if project.get("fingerprint") != _fingerprint(project):
                errors.append("$.project.fingerprint does not match immutable identity fields")

    run = state.get("run")
    if _is_dict(run, errors, "$.run"):
        if run.get("state") not in RUN_STATES:
            errors.append("$.run.state is invalid")
        if not isinstance(run.get("phase"), str) or not run.get("phase"):
            errors.append("$.run.phase must be a non-empty string")

    gaps = state.get("gaps")
    if not _is_dict(gaps, errors, "$.gaps"):
        gaps = {}
    tasks = state.get("tasks")
    if not _is_dict(tasks, errors, "$.tasks"):
        tasks = {}
    legacy_workflow_v2_task_ids = _workflow_v2_legacy_task_ids(state)
    unknown_legacy_task_ids = legacy_workflow_v2_task_ids.difference(tasks)
    if unknown_legacy_task_ids:
        errors.append("$.events project_web_migrated refers to missing legacy tasks")
    if isinstance(project, dict):
        web_policy = project.get("web")
        if isinstance(web_policy, dict) and web_policy.get("fidelity") in {"visual", "pixel"}:
            for task_id, task in tasks.items():
                if (
                    task_id not in legacy_workflow_v2_task_ids
                    and isinstance(task, dict)
                    and task.get("task_kind", "generic") == "generic"
                ):
                    errors.append("$.tasks.%s.task_kind cannot be generic for a visual/pixel Web project" % task_id)
    resource_leases = state.get("resource_leases")
    if not _is_dict(resource_leases, errors, "$.resource_leases"):
        resource_leases = {}
    handoffs = state.get("handoffs")
    if not _is_dict(handoffs, errors, "$.handoffs"):
        handoffs = {}

    for required_list in ("checkpoints", "events", "abandoned_leases"):
        _is_list(state.get(required_list), errors, "$.%s" % required_list)
    checkpoints = state.get("checkpoints") if isinstance(state.get("checkpoints"), list) else []

    for gap_id, gap in gaps.items():
        path = "$.gaps.%s" % gap_id
        if not _is_dict(gap, errors, path):
            continue
        if gap.get("gap_id") != gap_id:
            errors.append("%s.gap_id must match its map key" % path)
        if gap.get("status") not in GAP_STATES:
            errors.append("%s.status is invalid" % path)
        if gap.get("priority") not in PRIORITY_ORDER:
            errors.append("%s.priority is invalid" % path)
        if gap.get("status") == "closed":
            closure = gap.get("closure")
            if not isinstance(closure, dict) or not closure.get("qa_evidence"):
                errors.append("%s closed without QA evidence" % path)

    dependency_graph: Dict[str, List[str]] = {}
    for task_id, task in tasks.items():
        path = "$.tasks.%s" % task_id
        if not _is_dict(task, errors, path):
            continue
        if task.get("task_id") != task_id:
            errors.append("%s.task_id must match its map key" % path)
        if task.get("status") not in TASK_STATES:
            errors.append("%s.status is invalid" % path)
        if task.get("priority") not in PRIORITY_ORDER:
            errors.append("%s.priority is invalid" % path)
        task_kind = task.get("task_kind", "generic")
        if not isinstance(task_kind, str) or task_kind not in TASK_KINDS:
            errors.append("%s.task_kind is invalid" % path)
        preflight_report = task.get("preflight_report", "")
        preflight_sha256 = task.get("preflight_sha256", "")
        preflight_scope_id = task.get("preflight_scope_id", "")
        if not isinstance(preflight_report, str):
            errors.append("%s.preflight_report must be a string" % path)
        if not isinstance(preflight_sha256, str):
            errors.append("%s.preflight_sha256 must be a string" % path)
        if not isinstance(preflight_scope_id, str):
            errors.append("%s.preflight_scope_id must be a string" % path)
        strict_web = _strict_web_execution(state)
        is_legacy_workflow_v2_task = task_id in legacy_workflow_v2_task_ids
        requires_preflight = not is_legacy_workflow_v2_task and (
            task_kind in {"web_builder", "web_structure_builder"}
            or (strict_web and task_kind == "web_foundation")
        )
        if requires_preflight:
            if not _is_project_relative_path(preflight_report):
                errors.append("%s.preflight_report must be a project-root-relative path" % path)
            if not isinstance(preflight_sha256, str) or not SHA256_RE.fullmatch(preflight_sha256):
                errors.append("%s.preflight_sha256 must be 64 hexadecimal characters" % path)
            if not isinstance(preflight_scope_id, str) or not preflight_scope_id.strip():
                errors.append("%s.preflight_scope_id must be a non-empty string" % path)
        if task_kind == "core_contract_builder":
            try:
                _verify_core_contract_editable_paths(task.get("editable_paths"))
                _verify_core_contract_forbidden_paths(task.get("forbidden_paths"))
            except ReplicaCtlError as exc:
                errors.append("%s %s" % (path, exc.message))
        if strict_web and not is_legacy_workflow_v2_task and task_kind == "web_qa" and task.get("editable_paths"):
            errors.append("%s web_qa tasks cannot edit product paths" % path)
        if (
            strict_web
            and task_kind == "web_structure_builder"
            and state.get("project", {}).get("web", {}).get("asset_rights") not in {"reference_only", "unknown"}
        ):
            errors.append("%s web_structure_builder requires reference_only or unknown asset rights" % path)
        if not isinstance(task.get("lease_epoch"), int) or isinstance(task.get("lease_epoch"), bool) or task.get("lease_epoch", -1) < 0:
            errors.append("%s.lease_epoch must be a non-negative integer" % path)
        gap_ids = task.get("gap_ids")
        if not isinstance(gap_ids, list):
            errors.append("%s.gap_ids must be an array" % path)
        else:
            for gap_id in gap_ids:
                if not isinstance(gap_id, str) or not gap_id:
                    errors.append("%s.gap_ids must contain non-empty strings" % path)
                elif gap_id not in gaps:
                    errors.append("%s refers to missing gap %s" % (path, gap_id))
        dependencies = task.get("dependencies")
        if not isinstance(dependencies, list):
            errors.append("%s.dependencies must be an array" % path)
            dependencies = []
        valid_dependencies = []
        for dependency in dependencies:
            if not isinstance(dependency, str) or not dependency:
                errors.append("%s.dependencies must contain non-empty strings" % path)
            elif dependency == task_id:
                errors.append("%s cannot depend on itself" % path)
            elif dependency not in tasks:
                errors.append("%s refers to missing dependency %s" % (path, dependency))
            else:
                valid_dependencies.append(dependency)
        dependency_graph[task_id] = valid_dependencies
        if (
            _strict_web_execution(state)
            and not is_legacy_workflow_v2_task
            and task_kind in {"web_builder", "web_structure_builder"}
            and not any(
            isinstance(tasks.get(dependency), dict)
            and tasks[dependency].get("task_kind") == "web_foundation"
            for dependency in valid_dependencies
            )
        ):
            errors.append("%s requires a web_foundation dependency" % path)

        resources = task.get("resource_keys")
        if not isinstance(resources, list) or any(not isinstance(item, str) or not item for item in resources):
            errors.append("%s.resource_keys must be an array of non-empty strings" % path)
            resources = []
        elif len(resources) != len(set(resources)):
            errors.append("%s.resource_keys contains duplicates" % path)

        lease = task.get("lease")
        if lease is None:
            if task.get("status") == "claimed":
                errors.append("%s is claimed without a lease" % path)
        elif isinstance(lease, dict):
            if task.get("status") != "claimed":
                errors.append("%s has a lease but is not claimed" % path)
            for key in ("lease_id", "owner", "acquired_at", "heartbeat_at", "expires_at"):
                if not isinstance(lease.get(key), str) or not lease.get(key):
                    errors.append("%s.lease.%s must be a non-empty string" % (path, key))
            for key in ("acquired_at", "heartbeat_at", "expires_at"):
                _valid_timestamp(lease.get(key), errors, "%s.lease.%s" % (path, key))
            if lease.get("epoch") != task.get("lease_epoch"):
                errors.append("%s.lease epoch does not match task lease_epoch" % path)
            if lease.get("resource_keys") != resources:
                errors.append("%s.lease resource set differs from the task" % path)
            for resource in resources:
                resource_lease = resource_leases.get(resource)
                if not isinstance(resource_lease, dict):
                    errors.append("%s is missing resource lease %s" % (path, resource))
                elif resource_lease.get("task_id") != task_id or resource_lease.get("lease_id") != lease.get("lease_id"):
                    errors.append("%s resource lease %s belongs to another lease" % (path, resource))
        else:
            errors.append("%s.lease must be null or an object" % path)

        handoff_ids = task.get("handoff_ids")
        if not isinstance(handoff_ids, list):
            errors.append("%s.handoff_ids must be an array" % path)
        else:
            for handoff_id in handoff_ids:
                if not isinstance(handoff_id, str) or not handoff_id:
                    errors.append("%s.handoff_ids must contain non-empty strings" % path)
                elif handoff_id not in handoffs:
                    errors.append("%s refers to missing handoff %s" % (path, handoff_id))

    pending_handoffs_by_task: Dict[str, List[str]] = {}
    for handoff_id, handoff in handoffs.items():
        path = "$.handoffs.%s" % handoff_id
        if not _is_dict(handoff, errors, path):
            continue
        if handoff.get("handoff_id") != handoff_id:
            errors.append("%s.handoff_id must match its map key" % path)
        task_id = handoff.get("task_id")
        if not isinstance(task_id, str) or task_id not in tasks:
            errors.append("%s refers to a missing task" % path)
        elif tasks[task_id].get("task_kind") == "core_contract_builder":
            try:
                _verify_core_contract_changed_files(
                    tasks[task_id].get("editable_paths"),
                    tasks[task_id].get("forbidden_paths"),
                    handoff.get("changed_files"),
                    require_non_empty=handoff.get("result") == "completed",
                )
            except ReplicaCtlError as exc:
                errors.append("%s %s" % (path, exc.message))
        decision = handoff.get("decision")
        if decision is not None:
            if not isinstance(decision, dict):
                errors.append("%s.decision must be null or an object" % path)
            elif decision.get("result") not in {"merged", "rejected"}:
                errors.append("%s.decision.result is invalid" % path)
        elif handoff.get("result") == "completed" and isinstance(task_id, str):
            pending_handoffs_by_task.setdefault(task_id, []).append(handoff_id)

    for task_id, task in tasks.items():
        if not isinstance(task, dict):
            continue
        pending = pending_handoffs_by_task.get(task_id, [])
        if task.get("status") == "review" and len(pending) != 1:
            errors.append("$.tasks.%s review state requires exactly one pending completed handoff" % task_id)
        if pending and task.get("status") != "review":
            errors.append("$.tasks.%s has a pending completed handoff but is not in review" % task_id)
        merged = [
            item
            for item in handoffs.values()
            if isinstance(item, dict)
            and item.get("task_id") == task_id
            and isinstance(item.get("decision"), dict)
            and item["decision"].get("result") == "merged"
        ]
        if task.get("status") == "done" and not merged:
            errors.append("$.tasks.%s is done without a merged handoff decision" % task_id)

    if isinstance(run, dict) and run.get("state") == "complete":
        if not gaps:
            errors.append("$.run.state cannot be complete without at least one tracked Gap")
        if not tasks:
            errors.append("$.run.state cannot be complete without at least one completed task")
        if not any(
            isinstance(checkpoint, dict)
            and isinstance(checkpoint.get("evidence_ids"), list)
            and checkpoint.get("evidence_ids")
            for checkpoint in checkpoints
        ):
            errors.append("$.run.state cannot be complete without checkpoint evidence")
        if any(isinstance(gap, dict) and gap.get("status") != "closed" for gap in gaps.values()):
            errors.append("$.run.state cannot be complete while a Gap is open")
        if any(isinstance(task, dict) and task.get("status") != "done" for task in tasks.values()):
            errors.append("$.run.state cannot be complete while a task is unfinished")
        if resource_leases:
            errors.append("$.run.state cannot be complete while a resource lease is active")
        if pending_handoffs_by_task:
            errors.append("$.run.state cannot be complete while a handoff awaits review")

    for resource, resource_lease in resource_leases.items():
        path = "$.resource_leases.%s" % resource
        if not isinstance(resource_lease, dict):
            errors.append("%s must be an object" % path)
            continue
        task_id = resource_lease.get("task_id")
        task = tasks.get(task_id) if isinstance(task_id, str) else None
        if not isinstance(task, dict) or not isinstance(task.get("lease"), dict):
            errors.append("%s refers to a task without an active lease" % path)
        elif task["lease"].get("lease_id") != resource_lease.get("lease_id"):
            errors.append("%s lease_id differs from its task" % path)

    # Dependency cycles would make tasks permanently unrunnable.
    visiting: set = set()
    visited: set = set()

    def visit(task_id: str) -> None:
        if task_id in visited or task_id not in dependency_graph:
            return
        if task_id in visiting:
            errors.append("$.tasks dependency graph contains a cycle at %s" % task_id)
            return
        visiting.add(task_id)
        for dependency in dependency_graph.get(task_id, []):
            visit(dependency)
        visiting.discard(task_id)
        visited.add(task_id)

    for task_id in dependency_graph:
        visit(task_id)
    return sorted(set(errors))


def _event(event_type: str, at: _datetime.datetime, actor: str, **references: Any) -> Dict[str, Any]:
    event = {
        "event_id": _new_id("EVT"),
        "type": event_type,
        "at": format_time(at),
        "actor": actor,
    }
    event.update(references)
    return event


def _task_snapshot(task: Mapping[str, Any]) -> Dict[str, Any]:
    keys = (
        "task_id",
        "goal",
        "gap_ids",
        "inputs",
        "dependencies",
        "resource_keys",
        "editable_paths",
        "forbidden_paths",
        "base_revision",
        "acceptance",
        "expected_outputs",
        "priority",
    )
    snapshot = {key: copy.deepcopy(task.get(key)) for key in keys}
    snapshot["task_kind"] = task.get("task_kind", "generic")
    snapshot["preflight_report"] = task.get("preflight_report", "")
    snapshot["preflight_sha256"] = task.get("preflight_sha256", "")
    snapshot["preflight_scope_id"] = task.get("preflight_scope_id", "")
    return snapshot


def _gap_snapshot(gap: Mapping[str, Any]) -> Dict[str, Any]:
    keys = (
        "gap_id",
        "title",
        "description",
        "priority",
        "scenario_ids",
        "reference_evidence",
        "replica_evidence",
        "acceptance",
        "status",
    )
    return {key: copy.deepcopy(gap.get(key)) for key in keys}


class ReplicaController:
    def __init__(self, workspace: Path, lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS) -> None:
        workspace = Path(workspace).expanduser().resolve(strict=False)
        if workspace.suffix.lower() == ".json":
            self.workspace = workspace.parent
            state_path = workspace
        else:
            self.workspace = workspace
            state_path = workspace / "state.json"
        self.store = StateStore(state_path, lock_timeout_seconds=lock_timeout_seconds)

    @classmethod
    def start_project(
        cls,
        project_id: str,
        workspace_root: Path,
        code_root: str,
        reference_id: str,
        reference_platform: str,
        replica_id: str,
        replica_platform: str,
        scope_id: str = "unspecified",
        reference_write_policy: str = "read_only",
        web_fidelity: str = "functional",
        asset_rights: str = "unknown",
        lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
        now: Optional[_datetime.datetime] = None,
    ) -> Tuple["ReplicaController", Dict[str, Any]]:
        project_id = _safe_component(project_id, "project_id")
        for field, value in (("reference_id", reference_id), ("replica_id", replica_id)):
            if not isinstance(value, str) or not value.strip():
                raise ReplicaCtlError("%s must be a non-empty string" % field, "invalid_input")
            assert_safe_text(field, value)
        if reference_platform not in SUPPORTED_PLATFORMS or replica_platform not in SUPPORTED_PLATFORMS:
            raise ReplicaCtlError("Unsupported reference or replica platform", "invalid_input")
        if not isinstance(scope_id, str) or not scope_id.strip():
            raise ReplicaCtlError("scope_id must be a non-empty string", "invalid_input")
        scope_id = scope_id.strip()
        assert_safe_text("scope_id", scope_id)
        if reference_write_policy not in {
            "read_only",
            "reversible_test_writes",
            "writable_test",
        }:
            raise ReplicaCtlError("reference_write_policy is invalid", "invalid_input")
        if web_fidelity not in WEB_FIDELITY_LEVELS:
            raise ReplicaCtlError("web_fidelity is invalid", "invalid_input")
        if asset_rights not in ASSET_RIGHTS_LEVELS:
            raise ReplicaCtlError("asset_rights is invalid", "invalid_input")
        workspace_root = Path(workspace_root).expanduser().resolve(strict=False)
        controller = cls(workspace_root / project_id, lock_timeout_seconds=lock_timeout_seconds)
        timestamp = _coerce_utc(now)
        project = {
            "project_id": project_id,
            "code_root": _canonical_path(code_root, "code_root"),
            "reference": {"identity": reference_id.strip(), "platform": reference_platform},
            "replica": {"identity": replica_id.strip(), "platform": replica_platform},
            "scope_id": scope_id,
            "reference_write_policy": reference_write_policy,
            "web": {"fidelity": web_fidelity, "asset_rights": asset_rights, "workflow_version": 2},
        }
        project["fingerprint"] = _fingerprint(project)
        state = {
            "schema_version": SCHEMA_VERSION,
            "revision": 1,
            "created_at": format_time(timestamp),
            "updated_at": format_time(timestamp),
            "project": project,
            "run": {"state": "active", "phase": "bootstrap", "latest_checkpoint_id": None},
            "gaps": {},
            "tasks": {},
            "resource_leases": {},
            "checkpoints": [],
            "handoffs": {},
            "abandoned_leases": [],
            "events": [_event("project_started", timestamp, "coordinator", project_id=project_id)],
        }
        validation_errors = validate_state(state)
        if validation_errors:
            raise StateValidationError(validation_errors)

        with controller.store.lock():
            if controller.store.state_path.exists():
                existing = controller.store.read_unvalidated()
                errors = validate_state(existing)
                existing_project = existing.get("project") if isinstance(existing.get("project"), dict) else {}
                mismatches = []
                for key in (
                    "project_id",
                    "code_root",
                    "scope_id",
                    "reference_write_policy",
                    "web",
                    "fingerprint",
                ):
                    if existing_project.get(key) != project.get(key):
                        mismatches.append(key)
                result = {
                    "ok": False,
                    "created": False,
                    "unchanged": True,
                    "action_required": "resume",
                    "workspace": str(controller.workspace),
                    "state_file": str(controller.store.state_path),
                    "project_id": existing_project.get("project_id"),
                    "revision": existing.get("revision"),
                    "valid": not errors,
                    "validation_errors": errors,
                    "identity_mismatches": mismatches,
                }
                return controller, result
            for directory_name in ("scenarios", "evidence", "handoffs", "reports"):
                (controller.workspace / directory_name).mkdir(parents=True, exist_ok=True)
            controller.store.atomic_write(state)
        return controller, {
            "ok": True,
            "created": True,
            "unchanged": False,
            "workspace": str(controller.workspace),
            "state_file": str(controller.store.state_path),
            "project_id": project_id,
            "fingerprint": project["fingerprint"],
            "revision": 1,
            "valid": True,
            "validation_errors": [],
            "identity_mismatches": [],
        }

    def status(self, full: bool = False, now: Optional[_datetime.datetime] = None) -> Dict[str, Any]:
        state = self.store.read()
        if full:
            return {"ok": True, "workspace": str(self.workspace), "state": state}
        current = _coerce_utc(now)
        active_leases = []
        for task in state["tasks"].values():
            lease = task.get("lease")
            if lease:
                active_leases.append(
                    {
                        "task_id": task["task_id"],
                        "owner": lease["owner"],
                        "lease_epoch": lease["epoch"],
                        "resource_keys": list(lease["resource_keys"]),
                        "heartbeat_at": lease["heartbeat_at"],
                        "expires_at": lease["expires_at"],
                        "expired": parse_time(lease["expires_at"]) <= current,
                    }
                )
        counts = {
            "gaps": {status: sum(1 for item in state["gaps"].values() if item["status"] == status) for status in sorted(GAP_STATES)},
            "tasks": {status: sum(1 for item in state["tasks"].values() if item["status"] == status) for status in sorted(TASK_STATES)},
            "active_leases": len(active_leases),
            "expired_leases": sum(1 for item in active_leases if item["expired"]),
            "handoffs": len(state["handoffs"]),
            "pending_handoffs": sum(
                1
                for item in state["handoffs"].values()
                if item.get("result") == "completed" and item.get("decision") is None
            ),
        }
        runnable = [task["task_id"] for task in self._runnable_tasks(state)]
        return {
            "ok": True,
            "workspace": str(self.workspace),
            "project_id": state["project"]["project_id"],
            "fingerprint": state["project"]["fingerprint"],
            "revision": state["revision"],
            "updated_at": state["updated_at"],
            "run": copy.deepcopy(state["run"]),
            "counts": counts,
            "runnable_tasks": runnable,
            "active_leases": active_leases,
            "latest_checkpoint": copy.deepcopy(state["checkpoints"][-1]) if state["checkpoints"] else None,
        }

    @staticmethod
    def _runnable_tasks(state: Mapping[str, Any]) -> List[Mapping[str, Any]]:
        tasks = state["tasks"]
        runnable = []
        for task in tasks.values():
            if task["status"] != "ready" or task.get("lease") is not None:
                continue
            if any(tasks[dependency]["status"] != "done" for dependency in task["dependencies"]):
                continue
            if any(resource in state["resource_leases"] for resource in task["resource_keys"]):
                continue
            runnable.append(task)
        runnable.sort(key=lambda item: (PRIORITY_ORDER[item["priority"]], item["created_at"], item["task_id"]))
        return runnable

    def checkpoint(
        self,
        summary: str,
        actor: str = "coordinator",
        phase: Optional[str] = None,
        run_state: Optional[str] = None,
        next_actions: Optional[Iterable[str]] = None,
        evidence_ids: Optional[Iterable[str]] = None,
        dirty_files: Optional[Iterable[str]] = None,
        blockers: Optional[Iterable[str]] = None,
        checkpoint_id: Optional[str] = None,
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        if not isinstance(summary, str) or not summary.strip():
            raise ReplicaCtlError("checkpoint summary is required", "invalid_input")
        summary = summary.strip()
        actor = actor.strip()
        assert_safe_text("summary", summary)
        assert_safe_text("actor", actor)
        if not actor:
            raise ReplicaCtlError("actor is required", "invalid_input")
        if phase is not None:
            phase = phase.strip()
            if not phase:
                raise ReplicaCtlError("phase cannot be blank", "invalid_input")
            assert_safe_text("phase", phase)
        if run_state is not None and run_state not in RUN_STATES:
            raise ReplicaCtlError("run_state is invalid", "invalid_input")
        checkpoint_id = _safe_component(checkpoint_id, "checkpoint_id") if checkpoint_id else _new_id("CP")
        checkpoint = {
            "checkpoint_id": checkpoint_id,
            "at": format_time(timestamp),
            "actor": actor,
            "summary": summary,
            "phase": phase,
            "run_state": run_state,
            "next_actions": _clean_list(next_actions, "next_action"),
            "evidence_ids": _clean_list(evidence_ids, "evidence_id"),
            "dirty_files": _clean_list(dirty_files, "dirty_file"),
            "blockers": _clean_list(blockers, "blocker"),
        }

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            if any(item["checkpoint_id"] == checkpoint_id for item in state["checkpoints"]):
                raise ReplicaCtlError("Checkpoint %s already exists" % checkpoint_id, "already_exists")
            state["checkpoints"].append(checkpoint)
            state["run"]["latest_checkpoint_id"] = checkpoint_id
            if phase is not None:
                state["run"]["phase"] = phase
            if run_state is not None:
                state["run"]["state"] = run_state
            state["events"].append(_event("checkpoint_written", timestamp, actor, checkpoint_id=checkpoint_id))
            return {"ok": True, "workspace": str(self.workspace), "checkpoint": checkpoint}, True

        return self.store.mutate(operation, now=timestamp)

    def migrate_web_policy(
        self,
        web_fidelity: str,
        asset_rights: str,
        expected_revision: int,
        expected_fingerprint: str,
        approval_ref: str,
        actor: str = "coordinator",
        dry_run: bool = False,
        resume_run: bool = False,
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        if web_fidelity not in WEB_FIDELITY_LEVELS:
            raise ReplicaCtlError("web_fidelity is invalid", "invalid_input")
        if asset_rights not in ASSET_RIGHTS_LEVELS:
            raise ReplicaCtlError("asset_rights is invalid", "invalid_input")
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 1:
            raise ReplicaCtlError("expected_revision must be a positive integer", "invalid_input")
        if not isinstance(expected_fingerprint, str) or not expected_fingerprint.startswith("sha256:"):
            raise ReplicaCtlError("expected_fingerprint must be a sha256 fingerprint", "invalid_input")
        actor = actor.strip()
        approval_ref = approval_ref.strip()
        if not actor or not approval_ref:
            raise ReplicaCtlError("actor and approval_ref are required", "invalid_input")
        assert_safe_text("actor", actor)
        assert_safe_text("approval_ref", approval_ref)

        target_policy = {
            "fidelity": web_fidelity,
            "asset_rights": asset_rights,
            "workflow_version": 2,
        }

        def build_plan(state: Dict[str, Any]) -> Dict[str, Any]:
            if state["revision"] != expected_revision:
                raise ReplicaCtlError("State revision does not match expected_revision", "revision_conflict")
            project = state["project"]
            if project.get("fingerprint") != expected_fingerprint:
                raise ReplicaCtlError("Project fingerprint does not match expected_fingerprint", "identity_conflict")
            if project.get("reference", {}).get("platform") != "web" or project.get("replica", {}).get("platform") != "web":
                raise ReplicaCtlError("Web policy migration requires Web reference and replica platforms", "identity_conflict")
            if state.get("resource_leases"):
                raise ReplicaCtlError("Web policy migration requires zero active resource leases", "lease_conflict")
            if any(isinstance(task, Mapping) and task.get("lease") is not None for task in state["tasks"].values()):
                raise ReplicaCtlError("Web policy migration requires zero active task leases", "lease_conflict")
            if any(
                isinstance(handoff, Mapping)
                and handoff.get("result") == "completed"
                and handoff.get("decision") is None
                for handoff in state["handoffs"].values()
            ):
                raise ReplicaCtlError("Web policy migration requires zero pending handoffs", "handoff_conflict")
            if project.get("web") == target_policy:
                return {
                    "already_migrated": True,
                    "old_fingerprint": project["fingerprint"],
                    "new_fingerprint": project["fingerprint"],
                    "legacy_task_ids": sorted(_workflow_v2_legacy_task_ids(state)),
                    "legacy_open_task_ids": [],
                }
            if project.get("web") is not None:
                raise ReplicaCtlError("Existing project.web differs from the requested migration target", "identity_conflict")
            legacy_task_ids = sorted(state["tasks"])
            legacy_open_task_ids = sorted(
                task_id
                for task_id, task in state["tasks"].items()
                if isinstance(task, Mapping) and task.get("status") != "done"
            )
            migrated_project = copy.deepcopy(project)
            migrated_project["web"] = copy.deepcopy(target_policy)
            migrated_project["fingerprint"] = _fingerprint(migrated_project)
            return {
                "already_migrated": False,
                "old_fingerprint": project["fingerprint"],
                "new_fingerprint": migrated_project["fingerprint"],
                "legacy_task_ids": legacy_task_ids,
                "legacy_open_task_ids": legacy_open_task_ids,
            }

        if dry_run:
            with self.store.lock():
                state = self.store.read()
                plan = build_plan(state)
            return {
                "ok": True,
                "dry_run": True,
                "workspace": str(self.workspace),
                "expected_revision": expected_revision,
                "target_web_policy": target_policy,
                **plan,
            }

        migration_id = _new_id("MIG-WEB-V2")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            plan = build_plan(state)
            if plan["already_migrated"]:
                return {
                    "ok": True,
                    "dry_run": False,
                    "changed": False,
                    "workspace": str(self.workspace),
                    "target_web_policy": target_policy,
                    **plan,
                }, False

            snapshot_relative = "reports/migrations/%s/state.before.json" % migration_id
            snapshot_path = self.workspace / Path(snapshot_relative)
            if snapshot_path.exists():
                raise ReplicaCtlError("Migration snapshot already exists", "already_exists")
            StateStore(snapshot_path).atomic_write(state)
            snapshot_sha256 = _file_sha256(snapshot_path)

            old_run_state = state["run"]["state"]
            state["project"]["web"] = copy.deepcopy(target_policy)
            state["project"]["fingerprint"] = plan["new_fingerprint"]
            for task_id in plan["legacy_open_task_ids"]:
                task = state["tasks"][task_id]
                task["status"] = "blocked"
                task["updated_at"] = format_time(timestamp)
                task["migration_blocker"] = "workflow_v2_requires_new_typed_task"
            if resume_run:
                state["run"]["state"] = "active"
            state["events"].append(
                _event(
                    "project_web_migrated",
                    timestamp,
                    actor,
                    migration_id=migration_id,
                    approval_ref=approval_ref,
                    from_revision=expected_revision,
                    to_revision=expected_revision + 1,
                    old_fingerprint=plan["old_fingerprint"],
                    new_fingerprint=plan["new_fingerprint"],
                    workflow_version=2,
                    target_web_policy=copy.deepcopy(target_policy),
                    snapshot_path=snapshot_relative,
                    snapshot_sha256=snapshot_sha256,
                    legacy_task_ids=plan["legacy_task_ids"],
                    blocked_legacy_task_ids=plan["legacy_open_task_ids"],
                    old_run_state=old_run_state,
                    new_run_state=state["run"]["state"],
                )
            )
            return {
                "ok": True,
                "dry_run": False,
                "changed": True,
                "workspace": str(self.workspace),
                "migration_id": migration_id,
                "target_web_policy": target_policy,
                "snapshot_path": snapshot_relative,
                "snapshot_sha256": snapshot_sha256,
                **plan,
            }, True

        return self.store.mutate(operation, now=timestamp)

    def add_gap(
        self,
        gap_id: str,
        title: str,
        priority: str = "P1",
        description: str = "",
        scenario_ids: Optional[Iterable[str]] = None,
        reference_evidence: Optional[Iterable[str]] = None,
        replica_evidence: Optional[Iterable[str]] = None,
        acceptance: Optional[Iterable[str]] = None,
        actor: str = "coordinator",
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        gap_id = _safe_component(gap_id, "gap_id")
        if not isinstance(title, str) or not title.strip():
            raise ReplicaCtlError("gap title is required", "invalid_input")
        title = title.strip()
        description = description.strip()
        actor = actor.strip()
        for field, value in (("title", title), ("description", description), ("actor", actor)):
            assert_safe_text(field, value)
        if priority not in PRIORITY_ORDER:
            raise ReplicaCtlError("priority must be P0, P1, or P2", "invalid_input")
        gap = {
            "gap_id": gap_id,
            "title": title,
            "description": description,
            "priority": priority,
            "scenario_ids": _clean_list(scenario_ids, "scenario_id"),
            "reference_evidence": _clean_list(reference_evidence, "reference_evidence"),
            "replica_evidence": _clean_list(replica_evidence, "replica_evidence"),
            "acceptance": _clean_list(acceptance, "acceptance"),
            "status": "open",
            "closure": None,
            "created_at": format_time(timestamp),
            "updated_at": format_time(timestamp),
        }

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            if gap_id in state["gaps"]:
                raise ReplicaCtlError("Gap %s already exists" % gap_id, "already_exists")
            state["gaps"][gap_id] = gap
            state["events"].append(_event("gap_added", timestamp, actor, gap_id=gap_id))
            return {"ok": True, "workspace": str(self.workspace), "gap": gap}, True

        return self.store.mutate(operation, now=timestamp)

    def add_task(
        self,
        task_id: str,
        goal: str,
        gap_ids: Optional[Iterable[str]] = None,
        priority: str = "P1",
        inputs: Optional[Iterable[str]] = None,
        dependencies: Optional[Iterable[str]] = None,
        resource_keys: Optional[Iterable[str]] = None,
        editable_paths: Optional[Iterable[str]] = None,
        forbidden_paths: Optional[Iterable[str]] = None,
        base_revision: str = "",
        acceptance: Optional[Iterable[str]] = None,
        expected_outputs: Optional[Iterable[str]] = None,
        task_kind: str = "generic",
        preflight_report: str = "",
        preflight_sha256: str = "",
        preflight_scope_id: str = "",
        actor: str = "coordinator",
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        task_id = _safe_component(task_id, "task_id")
        if not isinstance(goal, str) or not goal.strip():
            raise ReplicaCtlError("task goal is required", "invalid_input")
        goal = goal.strip()
        actor = actor.strip()
        base_revision = base_revision.strip()
        if not isinstance(task_kind, str):
            raise ReplicaCtlError("task_kind must be a string", "invalid_input")
        if (
            not isinstance(preflight_report, str)
            or not isinstance(preflight_sha256, str)
            or not isinstance(preflight_scope_id, str)
        ):
            raise ReplicaCtlError("preflight report, SHA-256, and scope ID must be strings", "invalid_input")
        task_kind = task_kind.strip()
        preflight_report = preflight_report.strip()
        preflight_sha256 = preflight_sha256.strip()
        preflight_scope_id = preflight_scope_id.strip()
        for field, value in (
            ("goal", goal),
            ("actor", actor),
            ("base_revision", base_revision),
            ("task_kind", task_kind),
            ("preflight_report", preflight_report),
            ("preflight_sha256", preflight_sha256),
            ("preflight_scope_id", preflight_scope_id),
        ):
            assert_safe_text(field, value)
        if priority not in PRIORITY_ORDER:
            raise ReplicaCtlError("priority must be P0, P1, or P2", "invalid_input")
        if task_kind not in TASK_KINDS:
            raise ReplicaCtlError("task_kind is invalid", "invalid_input")
        if task_kind in {"web_builder", "web_structure_builder"} and (
            not _is_project_relative_path(preflight_report)
            or not SHA256_RE.fullmatch(preflight_sha256)
            or not preflight_scope_id
        ):
            raise ReplicaCtlError(
                "Web Builder tasks require a project-relative preflight report, its SHA-256, and a scope ID",
                "gate_blocked",
            )
        task = {
            "task_id": task_id,
            "goal": goal,
            "task_kind": task_kind,
            "preflight_report": preflight_report,
            "preflight_sha256": preflight_sha256,
            "preflight_scope_id": preflight_scope_id,
            "gap_ids": _clean_list(gap_ids, "gap_id"),
            "priority": priority,
            "inputs": _clean_list(inputs, "input"),
            "dependencies": _clean_list(dependencies, "dependency"),
            "resource_keys": _clean_list(resource_keys, "resource_key"),
            "editable_paths": _clean_list(editable_paths, "editable_path"),
            "forbidden_paths": _clean_list(forbidden_paths, "forbidden_path"),
            "base_revision": base_revision,
            "acceptance": _clean_list(acceptance, "acceptance"),
            "expected_outputs": _clean_list(expected_outputs, "expected_output"),
            "status": "ready",
            "lease_epoch": 0,
            "lease": None,
            "handoff_ids": [],
            "created_at": format_time(timestamp),
            "updated_at": format_time(timestamp),
        }

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            if task_id in state["tasks"]:
                raise ReplicaCtlError("Task %s already exists" % task_id, "already_exists")
            missing_gaps = [item for item in task["gap_ids"] if item not in state["gaps"]]
            missing_dependencies = [item for item in task["dependencies"] if item not in state["tasks"]]
            if missing_gaps:
                raise ReplicaCtlError("Task refers to missing gaps: %s" % ", ".join(missing_gaps), "missing_dependency")
            if missing_dependencies:
                raise ReplicaCtlError(
                    "Task refers to missing dependencies: %s" % ", ".join(missing_dependencies),
                    "missing_dependency",
                )
            if task_id in task["dependencies"]:
                raise ReplicaCtlError("Task cannot depend on itself", "invalid_input")
            web_policy = state["project"].get("web")
            strict_web = _strict_web_execution(state)
            if (
                task["task_kind"] == "generic"
                and isinstance(web_policy, Mapping)
                and web_policy.get("fidelity") in {"visual", "pixel"}
                and state["project"].get("reference", {}).get("platform") == "web"
                and state["project"].get("replica", {}).get("platform") == "web"
            ):
                raise ReplicaCtlError(
                    "visual/pixel Web projects require typed core_contract_builder, web_foundation, web_builder, "
                    "web_structure_builder, or web_qa tasks",
                    "gate_blocked",
                )
            if task["task_kind"] == "core_contract_builder":
                _verify_core_contract_editable_paths(task["editable_paths"])
                _verify_core_contract_forbidden_paths(task["forbidden_paths"])
            if strict_web and task["task_kind"] in {"web_foundation", "web_qa"} and task["editable_paths"]:
                raise ReplicaCtlError(
                    "Web foundation and QA tasks are evidence-only and cannot edit product paths",
                    "gate_blocked",
                )
            if strict_web and task["task_kind"] in {"web_builder", "web_structure_builder"} and not any(
                isinstance(state["tasks"].get(dependency), Mapping)
                and state["tasks"][dependency].get("task_kind") == "web_foundation"
                for dependency in task["dependencies"]
            ):
                raise ReplicaCtlError(
                    "Web Builder tasks require an explicit web_foundation dependency",
                    "gate_blocked",
                )
            if task["task_kind"] in {"web_builder", "web_structure_builder"}:
                if (
                    task["task_kind"] == "web_structure_builder"
                    and state["project"].get("web", {}).get("asset_rights") not in {"reference_only", "unknown"}
                ):
                    raise ReplicaCtlError(
                        "web_structure_builder is only for reference_only/unknown asset-rights projects",
                        "gate_blocked",
                    )
                _verify_web_preflight(
                    state["project"]["code_root"],
                    task["preflight_report"],
                    task["preflight_sha256"],
                    task["preflight_scope_id"],
                    expected_project_id=state["project"]["project_id"],
                    expected_reference_fingerprint=_reference_identity_fingerprint(state["project"]["reference"]["identity"]),
                    allowed_equivalence_scopes=(
                        ("declared_scope", "partial_excludes_visible_assets")
                        if task["task_kind"] == "web_structure_builder"
                        else ("declared_scope",)
                    ),
                )
            elif strict_web and task["task_kind"] == "web_foundation":
                foundation_scopes = (
                    ("declared_scope", "partial_excludes_visible_assets")
                    if state["project"].get("web", {}).get("asset_rights") in {"reference_only", "unknown"}
                    else ("declared_scope",)
                )
                _verify_web_preflight(
                    state["project"]["code_root"],
                    task["preflight_report"],
                    task["preflight_sha256"],
                    task["preflight_scope_id"],
                    expected_scope_kind="page",
                    expected_project_id=state["project"]["project_id"],
                    expected_reference_fingerprint=_reference_identity_fingerprint(state["project"]["reference"]["identity"]),
                    allowed_equivalence_scopes=foundation_scopes,
                )
            state["tasks"][task_id] = task
            cycle_errors = [item for item in validate_state(state) if "dependency graph contains a cycle" in item]
            if cycle_errors:
                del state["tasks"][task_id]
                raise ReplicaCtlError("Task would create a dependency cycle", "invalid_input")
            state["events"].append(_event("task_added", timestamp, actor, task_id=task_id))
            return {"ok": True, "workspace": str(self.workspace), "task": task}, True

        return self.store.mutate(operation, now=timestamp)

    def update_gap(
        self,
        gap_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        scenario_ids: Optional[Iterable[str]] = None,
        reference_evidence: Optional[Iterable[str]] = None,
        replica_evidence: Optional[Iterable[str]] = None,
        acceptance: Optional[Iterable[str]] = None,
        remove_acceptance: Optional[Iterable[str]] = None,
        actor: str = "coordinator",
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """Atomically update audited evidence/contracts on an existing open Gap."""
        timestamp = _coerce_utc(now)
        gap_id = _safe_component(gap_id, "gap_id")
        actor = actor.strip()
        assert_safe_text("actor", actor)
        replacements: Dict[str, str] = {}
        if title is not None:
            if not isinstance(title, str) or not title.strip():
                raise ReplicaCtlError("gap title is required", "invalid_input")
            replacements["title"] = title.strip()
        if description is not None:
            if not isinstance(description, str):
                raise ReplicaCtlError("gap description must be a string", "invalid_input")
            replacements["description"] = description.strip()
        for field, value in replacements.items():
            assert_safe_text(field, value)
        additions = {
            "scenario_ids": _clean_list(scenario_ids, "scenario_id"),
            "reference_evidence": _clean_list(reference_evidence, "reference_evidence"),
            "replica_evidence": _clean_list(replica_evidence, "replica_evidence"),
            "acceptance": _clean_list(acceptance, "acceptance"),
        }
        acceptance_removals = _clean_list(remove_acceptance, "remove_acceptance")
        conflicting_acceptance = set(additions["acceptance"]).intersection(acceptance_removals)
        if conflicting_acceptance:
            raise ReplicaCtlError("The same acceptance cannot be added and removed", "invalid_input")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            gap = state["gaps"].get(gap_id)
            if gap is None:
                raise ReplicaCtlError("Gap %s does not exist" % gap_id, "not_found")
            if gap.get("status") != "open":
                raise ReplicaCtlError("Only open Gaps may be updated", "invalid_transition")
            current_acceptance = gap.setdefault("acceptance", [])
            missing_removals = [value for value in acceptance_removals if value not in current_acceptance]
            if missing_removals:
                raise ReplicaCtlError("Acceptance contract to remove does not exist", "not_found")
            removed: Dict[str, List[str]] = {}
            if acceptance_removals:
                gap["acceptance"] = [value for value in current_acceptance if value not in acceptance_removals]
                removed["acceptance"] = acceptance_removals
            added: Dict[str, List[str]] = {}
            for field, values in additions.items():
                current = gap.setdefault(field, [])
                new_values = [value for value in values if value not in current]
                if new_values:
                    current.extend(new_values)
                    added[field] = new_values
            replaced: Dict[str, Dict[str, str]] = {}
            for field, value in replacements.items():
                current = gap.get(field, "")
                if current != value:
                    gap[field] = value
                    replaced[field] = {"from": current, "to": value}
            if not added and not removed and not replaced:
                return {"ok": True, "workspace": str(self.workspace), "gap": gap, "changed": False}, False
            gap["updated_at"] = format_time(timestamp)
            state["events"].append(
                _event(
                    "gap_updated",
                    timestamp,
                    actor,
                    gap_id=gap_id,
                    added=added,
                    removed=removed,
                    replaced=replaced,
                )
            )
            return {
                "ok": True,
                "workspace": str(self.workspace),
                "gap": gap,
                "changed": True,
                "added": added,
                "removed": removed,
                "replaced": replaced,
            }, True

        return self.store.mutate(operation, now=timestamp)

    def claim(
        self,
        owner: str,
        task_id: Optional[str] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        owner = owner.strip()
        if not owner:
            raise ReplicaCtlError("owner is required", "invalid_input")
        assert_safe_text("owner", owner)
        if task_id is not None:
            task_id = _safe_component(task_id, "task_id")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1 or ttl_seconds > 86400:
            raise ReplicaCtlError("ttl_seconds must be an integer from 1 to 86400", "invalid_input")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            if task_id is not None:
                task = state["tasks"].get(task_id)
                if task is None:
                    raise ReplicaCtlError("Task %s does not exist" % task_id, "not_found")
                candidates = [task]
            else:
                candidates = self._runnable_tasks(state)
                if not candidates:
                    raise ReplicaCtlError("No runnable task is available", "no_runnable_task")
            task = candidates[0]
            if task["status"] != "ready" or task.get("lease") is not None:
                raise ReplicaCtlError("Task %s is not claimable" % task["task_id"], "task_unavailable")
            strict_web = _strict_web_execution(state)
            if task.get("task_kind") == "core_contract_builder":
                _verify_core_contract_editable_paths(task.get("editable_paths"))
                _verify_core_contract_forbidden_paths(task.get("forbidden_paths"))
            if task.get("task_kind", "generic") in {"web_builder", "web_structure_builder"}:
                if (
                    task.get("task_kind") == "web_structure_builder"
                    and state["project"].get("web", {}).get("asset_rights") not in {"reference_only", "unknown"}
                ):
                    raise ReplicaCtlError(
                        "web_structure_builder is only for reference_only/unknown asset-rights projects",
                        "gate_blocked",
                    )
                _verify_web_preflight(
                    state["project"]["code_root"],
                    task.get("preflight_report", ""),
                    task.get("preflight_sha256", ""),
                    task.get("preflight_scope_id", ""),
                    expected_project_id=state["project"]["project_id"],
                    expected_reference_fingerprint=_reference_identity_fingerprint(state["project"]["reference"]["identity"]),
                    allowed_equivalence_scopes=(
                        ("declared_scope", "partial_excludes_visible_assets")
                        if task.get("task_kind") == "web_structure_builder"
                        else ("declared_scope",)
                    ),
                )
            elif strict_web and task.get("task_kind") == "web_foundation":
                foundation_scopes = (
                    ("declared_scope", "partial_excludes_visible_assets")
                    if state["project"].get("web", {}).get("asset_rights") in {"reference_only", "unknown"}
                    else ("declared_scope",)
                )
                _verify_web_preflight(
                    state["project"]["code_root"],
                    task.get("preflight_report", ""),
                    task.get("preflight_sha256", ""),
                    task.get("preflight_scope_id", ""),
                    expected_scope_kind="page",
                    expected_project_id=state["project"]["project_id"],
                    expected_reference_fingerprint=_reference_identity_fingerprint(state["project"]["reference"]["identity"]),
                    allowed_equivalence_scopes=foundation_scopes,
                )
            if strict_web and task.get("task_kind") in {"web_foundation", "web_qa"} and task.get("editable_paths"):
                raise ReplicaCtlError("Web foundation and QA tasks cannot edit product paths", "gate_blocked")
            web_policy = state["project"].get("web")
            if (
                task.get("task_kind", "generic") == "generic"
                and isinstance(web_policy, Mapping)
                and web_policy.get("fidelity") in {"visual", "pixel"}
                and state["project"].get("reference", {}).get("platform") == "web"
                and state["project"].get("replica", {}).get("platform") == "web"
            ):
                raise ReplicaCtlError("visual/pixel Web projects cannot claim generic tasks", "gate_blocked")
            incomplete = [dependency for dependency in task["dependencies"] if state["tasks"][dependency]["status"] != "done"]
            if incomplete:
                raise ReplicaCtlError("Task dependencies are not done: %s" % ", ".join(incomplete), "dependency_blocked")
            conflicts = [resource for resource in task["resource_keys"] if resource in state["resource_leases"]]
            if conflicts:
                # An expired lease remains authoritative until an explicitly
                # confirmed reap.  Never steal merely because the clock moved.
                raise ReplicaCtlError("Resources are leased: %s" % ", ".join(conflicts), "resource_conflict")
            epoch = int(task["lease_epoch"]) + 1
            lease_id = uuid.uuid4().hex
            expires_at = timestamp + _datetime.timedelta(seconds=ttl_seconds)
            lease = {
                "lease_id": lease_id,
                "epoch": epoch,
                "owner": owner,
                "task_id": task["task_id"],
                "acquired_at": format_time(timestamp),
                "heartbeat_at": format_time(timestamp),
                "expires_at": format_time(expires_at),
                "ttl_seconds": ttl_seconds,
                "base_revision": task["base_revision"],
                "resource_keys": list(task["resource_keys"]),
            }
            task["status"] = "claimed"
            task["lease_epoch"] = epoch
            task["lease"] = lease
            task["updated_at"] = format_time(timestamp)
            for resource in task["resource_keys"]:
                state["resource_leases"][resource] = {
                    "resource_key": resource,
                    "task_id": task["task_id"],
                    "lease_id": lease_id,
                    "epoch": epoch,
                    "owner": owner,
                    "heartbeat_at": lease["heartbeat_at"],
                    "expires_at": lease["expires_at"],
                }
            state["events"].append(
                _event("task_claimed", timestamp, owner, task_id=task["task_id"], lease_epoch=epoch)
            )
            return {
                "ok": True,
                "workspace": str(self.workspace),
                "task": _task_snapshot(task),
                "lease": copy.deepcopy(lease),
                "heartbeat_by": format_time(timestamp + _datetime.timedelta(seconds=max(1, ttl_seconds // 3))),
            }, True

        return self.store.mutate(operation, now=timestamp)

    @staticmethod
    def _require_lease(
        state: Mapping[str, Any],
        task_id: str,
        owner: str,
        lease_id: Optional[str],
        lease_epoch: Optional[int],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        task = state["tasks"].get(task_id)
        if task is None:
            raise ReplicaCtlError("Task %s does not exist" % task_id, "not_found")
        lease = task.get("lease")
        if not isinstance(lease, dict):
            raise ReplicaCtlError("Task %s has no active lease" % task_id, "lease_not_found")
        if not lease_id and lease_epoch is None:
            raise ReplicaCtlError("lease_id or lease_epoch is required", "lease_identity_required")
        if lease["owner"] != owner:
            raise ReplicaCtlError("Lease owner does not match", "lease_mismatch")
        if lease_id and lease["lease_id"] != lease_id:
            raise ReplicaCtlError("lease_id does not match", "lease_mismatch")
        if lease_epoch is not None and lease["epoch"] != lease_epoch:
            raise ReplicaCtlError("lease_epoch does not match", "lease_mismatch")
        return task, lease

    def heartbeat(
        self,
        task_id: str,
        owner: str,
        lease_id: Optional[str] = None,
        lease_epoch: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        task_id = _safe_component(task_id, "task_id")
        owner = owner.strip()
        assert_safe_text("owner", owner)
        if lease_id:
            assert_safe_text("lease_id", lease_id)
        if ttl_seconds is not None and (
            isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1 or ttl_seconds > 86400
        ):
            raise ReplicaCtlError("ttl_seconds must be an integer from 1 to 86400", "invalid_input")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            task, lease = self._require_lease(state, task_id, owner, lease_id, lease_epoch)
            ttl = ttl_seconds if ttl_seconds is not None else int(lease["ttl_seconds"])
            lease["heartbeat_at"] = format_time(timestamp)
            lease["expires_at"] = format_time(timestamp + _datetime.timedelta(seconds=ttl))
            lease["ttl_seconds"] = ttl
            task["updated_at"] = format_time(timestamp)
            for resource in lease["resource_keys"]:
                resource_lease = state["resource_leases"][resource]
                resource_lease["heartbeat_at"] = lease["heartbeat_at"]
                resource_lease["expires_at"] = lease["expires_at"]
            state["events"].append(
                _event("lease_heartbeat", timestamp, owner, task_id=task_id, lease_epoch=lease["epoch"])
            )
            return {
                "ok": True,
                "workspace": str(self.workspace),
                "task_id": task_id,
                "lease_epoch": lease["epoch"],
                "heartbeat_at": lease["heartbeat_at"],
                "expires_at": lease["expires_at"],
            }, True

        return self.store.mutate(operation, now=timestamp)

    @staticmethod
    def _release_resources(state: Dict[str, Any], lease: Mapping[str, Any]) -> None:
        for resource in lease["resource_keys"]:
            current = state["resource_leases"].get(resource)
            if isinstance(current, dict) and current.get("lease_id") == lease["lease_id"]:
                del state["resource_leases"][resource]

    def handoff(
        self,
        task_id: str,
        owner: str,
        summary: str,
        result: str = "completed",
        lease_id: Optional[str] = None,
        lease_epoch: Optional[int] = None,
        changed_files: Optional[Iterable[str]] = None,
        commit_or_patch: str = "",
        validation: Optional[Iterable[str]] = None,
        evidence_ids: Optional[Iterable[str]] = None,
        remaining_uncertainty: Optional[Iterable[str]] = None,
        next_action: str = "",
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        task_id = _safe_component(task_id, "task_id")
        owner = owner.strip()
        summary = summary.strip()
        commit_or_patch = commit_or_patch.strip()
        next_action = next_action.strip()
        for field, value in (
            ("owner", owner),
            ("summary", summary),
            ("commit_or_patch", commit_or_patch),
            ("next_action", next_action),
        ):
            assert_safe_text(field, value)
        if not summary:
            raise ReplicaCtlError("handoff summary is required", "invalid_input")
        result_aliases = {
            "completed": "completed",
            "complete": "completed",
            "done": "completed",
            "ready": "completed",
            "partial": "partial",
            "blocked": "blocked",
        }
        if result not in result_aliases:
            raise ReplicaCtlError("result must be completed, ready, partial, or blocked", "invalid_input")
        normalized_result = result_aliases[result]
        if not next_action:
            next_action = {
                "completed": "Coordinator reviews and merges this handoff, then schedules independent QA.",
                "partial": "Coordinator requeues the remaining task scope for a new lease.",
                "blocked": "Coordinator resolves the recorded uncertainty before requeuing the task.",
            }[normalized_result]
        changed_files_list = _clean_list(changed_files, "changed_file")
        validation_list = _clean_list(validation, "validation")
        evidence_list = _clean_list(evidence_ids, "evidence_id")
        uncertainty_list = _clean_list(remaining_uncertainty, "remaining_uncertainty")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            task, lease = self._require_lease(state, task_id, owner, lease_id, lease_epoch)
            if task.get("task_kind") == "core_contract_builder":
                _verify_core_contract_changed_files(
                    task.get("editable_paths"),
                    task.get("forbidden_paths"),
                    changed_files_list,
                    require_non_empty=normalized_result == "completed",
                )
            handoff_id = "HO-%s-E%d-%s" % (task_id, lease["epoch"], uuid.uuid4().hex[:10])
            handoff = {
                "handoff_id": handoff_id,
                "created_at": format_time(timestamp),
                "owner": owner,
                "task_id": task_id,
                "lease_id": lease["lease_id"],
                "lease_epoch": lease["epoch"],
                "result": normalized_result,
                "summary": summary,
                "changed_files": changed_files_list,
                "commit_or_patch": commit_or_patch,
                "validation": validation_list,
                "evidence_ids": evidence_list,
                "remaining_uncertainty": uncertainty_list,
                "next_action": next_action,
                "sensitive_data_check": "passed",
                "decision": None,
                "task": _task_snapshot(task),
                "gaps": [_gap_snapshot(state["gaps"][gap_id]) for gap_id in task["gap_ids"]],
                "lease": copy.deepcopy(lease),
            }
            state["handoffs"][handoff_id] = handoff
            task["handoff_ids"].append(handoff_id)
            self._release_resources(state, lease)
            task["lease"] = None
            task["status"] = {"completed": "review", "partial": "ready", "blocked": "blocked"}[normalized_result]
            task["updated_at"] = format_time(timestamp)
            state["events"].append(
                _event(
                    "task_handoff",
                    timestamp,
                    owner,
                    task_id=task_id,
                    handoff_id=handoff_id,
                    lease_epoch=handoff["lease_epoch"],
                    result=normalized_result,
                )
            )
            return {
                "ok": True,
                "workspace": str(self.workspace),
                "released": True,
                "task_status": task["status"],
                "handoff": handoff,
            }, True

        return self.store.mutate(operation, now=timestamp)

    def accept_handoff(
        self,
        handoff_id: str,
        accepted_by: str,
        result: str,
        note: str = "",
        validation: Optional[Iterable[str]] = None,
        evidence_ids: Optional[Iterable[str]] = None,
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """Coordinator decision for a completed Worker handoff.

        A Worker can only move a task into review.  This separate transaction
        makes unmerged work visible and prevents a handoff from satisfying
        downstream dependencies before a Coordinator decision.
        """

        timestamp = _coerce_utc(now)
        handoff_id = _safe_component(handoff_id, "handoff_id")
        accepted_by = accepted_by.strip()
        note = note.strip()
        for field, value in (("accepted_by", accepted_by), ("note", note)):
            assert_safe_text(field, value)
        if not accepted_by:
            raise ReplicaCtlError("accepted_by is required", "invalid_input")
        if result not in {"merged", "rejected"}:
            raise ReplicaCtlError("result must be merged or rejected", "invalid_input")
        validation_list = _clean_list(validation, "validation")
        evidence_list = _clean_list(evidence_ids, "evidence_id")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            handoff = state["handoffs"].get(handoff_id)
            if handoff is None:
                raise ReplicaCtlError("Handoff %s does not exist" % handoff_id, "not_found")
            if handoff.get("result") != "completed":
                raise ReplicaCtlError("Only a completed handoff can be accepted", "handoff_not_reviewable")
            if handoff.get("decision") is not None:
                raise ReplicaCtlError("Handoff %s already has a decision" % handoff_id, "already_decided")
            task = state["tasks"].get(handoff["task_id"])
            if not isinstance(task, dict) or task.get("status") != "review":
                raise ReplicaCtlError("Task is not awaiting this handoff review", "handoff_not_reviewable")
            pending_for_task = [
                item
                for item in state["handoffs"].values()
                if item.get("task_id") == task["task_id"]
                and item.get("result") == "completed"
                and item.get("decision") is None
            ]
            if len(pending_for_task) != 1 or pending_for_task[0].get("handoff_id") != handoff_id:
                raise ReplicaCtlError("Task has an ambiguous pending handoff", "invalid_state")
            decision = {
                "decided_at": format_time(timestamp),
                "accepted_by": accepted_by,
                "result": result,
                "note": note,
                "validation": validation_list,
                "evidence_ids": evidence_list,
            }
            handoff["decision"] = decision
            task["status"] = "done" if result == "merged" else "ready"
            task["updated_at"] = format_time(timestamp)
            state["events"].append(
                _event(
                    "handoff_decided",
                    timestamp,
                    accepted_by,
                    task_id=task["task_id"],
                    handoff_id=handoff_id,
                    result=result,
                )
            )
            return {
                "ok": True,
                "workspace": str(self.workspace),
                "handoff_id": handoff_id,
                "task_id": task["task_id"],
                "task_status": task["status"],
                "decision": decision,
            }, True

        return self.store.mutate(operation, now=timestamp)

    def reap(
        self,
        confirm_inactive: bool,
        task_id: Optional[str] = None,
        owner: Optional[str] = None,
        confirmed_by: str = "coordinator",
        reason: str = "Agent/process/worktree confirmed inactive after lease expiry.",
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        if not confirm_inactive:
            raise ReplicaCtlError(
                "reap requires --confirm-inactive after checking the agent, process, and worktree",
                "confirmation_required",
            )
        timestamp = _coerce_utc(now)
        if task_id is not None:
            task_id = _safe_component(task_id, "task_id")
        owner = owner.strip() if owner else None
        confirmed_by = confirmed_by.strip()
        reason = reason.strip()
        for field, value in (("owner", owner), ("confirmed_by", confirmed_by), ("reason", reason)):
            assert_safe_text(field, value)
        if not confirmed_by or not reason:
            raise ReplicaCtlError("confirmed_by and reason are required", "invalid_input")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            reaped = []
            for task in state["tasks"].values():
                lease = task.get("lease")
                if not isinstance(lease, dict):
                    continue
                if task_id is not None and task["task_id"] != task_id:
                    continue
                if owner is not None and lease["owner"] != owner:
                    continue
                if parse_time(lease["expires_at"]) > timestamp:
                    continue
                abandoned_id = _new_id("ABANDONED")
                abandoned = {
                    "abandoned_id": abandoned_id,
                    "task_id": task["task_id"],
                    "owner": lease["owner"],
                    "lease_id": lease["lease_id"],
                    "lease_epoch": lease["epoch"],
                    "expired_at": lease["expires_at"],
                    "reaped_at": format_time(timestamp),
                    "confirmed_inactive": True,
                    "confirmed_by": confirmed_by,
                    "reason": reason,
                    "resource_keys": list(lease["resource_keys"]),
                }
                state["abandoned_leases"].append(abandoned)
                self._release_resources(state, lease)
                task["lease"] = None
                task["status"] = "ready"
                task["updated_at"] = format_time(timestamp)
                state["events"].append(
                    _event(
                        "lease_reaped",
                        timestamp,
                        confirmed_by,
                        task_id=task["task_id"],
                        lease_epoch=lease["epoch"],
                        abandoned_id=abandoned_id,
                    )
                )
                reaped.append(abandoned)
            result = {
                "ok": True,
                "workspace": str(self.workspace),
                "reaped_count": len(reaped),
                "reaped": reaped,
                "note": "Unexpired leases were not touched.",
            }
            return result, bool(reaped)

        return self.store.mutate(operation, now=timestamp)

    def close_gap(
        self,
        gap_id: str,
        qa_evidence: Iterable[str],
        qa_by: str = "qa",
        qa_report: str = "",
        qa_report_sha256: str = "",
        resolution: str = "verified",
        note: str = "",
        actor: str = "coordinator",
        now: Optional[_datetime.datetime] = None,
    ) -> Dict[str, Any]:
        timestamp = _coerce_utc(now)
        gap_id = _safe_component(gap_id, "gap_id")
        evidence = _clean_list(qa_evidence, "qa_evidence")
        if not evidence:
            raise ReplicaCtlError("close-gap requires at least one QA evidence ID", "qa_evidence_required")
        if resolution not in {"verified", "accepted_deviation"}:
            raise ReplicaCtlError("resolution must be verified or accepted_deviation", "invalid_input")
        qa_by = qa_by.strip()
        actor = actor.strip()
        note = note.strip()
        qa_report = qa_report.strip()
        qa_report_sha256 = qa_report_sha256.strip()
        for field, value in (("qa_by", qa_by), ("actor", actor), ("note", note), ("qa_report", qa_report), ("qa_report_sha256", qa_report_sha256)):
            assert_safe_text(field, value)
        if not qa_by or not actor:
            raise ReplicaCtlError("qa_by and actor are required", "invalid_input")

        def operation(state: Dict[str, Any]) -> Tuple[Any, bool]:
            gap = state["gaps"].get(gap_id)
            if gap is None:
                raise ReplicaCtlError("Gap %s does not exist" % gap_id, "not_found")
            if gap["status"] == "closed":
                raise ReplicaCtlError("Gap %s is already closed" % gap_id, "already_closed")
            web_policy = state["project"].get("web")
            qa_binding = None
            if isinstance(web_policy, Mapping) and web_policy.get("fidelity") in {"visual", "pixel"}:
                qa_binding = _verify_web_qa_report(
                    state["project"]["code_root"],
                    qa_report,
                    qa_report_sha256,
                    web_policy.get("fidelity") == "pixel" or _strict_web_execution(state),
                )
            gap["status"] = "closed"
            gap["updated_at"] = format_time(timestamp)
            gap["closure"] = {
                "closed_at": format_time(timestamp),
                "closed_by": actor,
                "qa_by": qa_by,
                "qa_evidence": evidence,
                "qa_report": qa_binding,
                "resolution": resolution,
                "note": note,
            }
            state["events"].append(
                _event("gap_closed", timestamp, actor, gap_id=gap_id, resolution=resolution)
            )
            return {"ok": True, "workspace": str(self.workspace), "gap": copy.deepcopy(gap)}, True

        return self.store.mutate(operation, now=timestamp)

    def validate(self) -> Dict[str, Any]:
        try:
            state = self.store.read_unvalidated()
        except ReplicaCtlError as exc:
            return {
                "ok": False,
                "valid": False,
                "workspace": str(self.workspace),
                "errors": [exc.message],
            }
        errors = validate_state(state)
        return {
            "ok": not errors,
            "valid": not errors,
            "workspace": str(self.workspace),
            "state_file": str(self.store.state_path),
            "project_id": state.get("project", {}).get("project_id") if isinstance(state.get("project"), dict) else None,
            "schema_version": state.get("schema_version"),
            "revision": state.get("revision"),
            "errors": errors,
        }


def discover_workspace(explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve(strict=False)
    cwd = Path.cwd().resolve()
    direct_candidates = [cwd / "state.json", cwd / ".replica" / "state.json"]
    for candidate in direct_candidates:
        if candidate.is_file():
            return candidate.parent
    root = cwd / ".replica"
    candidates = sorted(path.parent for path in root.glob("*/state.json")) if root.is_dir() else []
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise ReplicaCtlError(
            "Several replica projects exist; pass --workspace with the exact project directory",
            "ambiguous_workspace",
        )
    raise ReplicaCtlError(
        "No workspace selected; pass --workspace with the project directory returned by start",
        "workspace_required",
    )


def _add_command_workspace(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        dest="command_workspace",
        help="Project directory returned by start (may also be passed before the command).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Atomic Goal App Replica state, task, and lease controller.",
    )
    parser.add_argument("--workspace", help="Exact project workspace returned by start.")
    parser.add_argument(
        "--lock-timeout",
        type=float,
        default=DEFAULT_LOCK_TIMEOUT_SECONDS,
        help="Seconds to wait for the short-lived state lock (default: 5).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", aliases=["init"], help="Initialize a new project without overwriting state.")
    start.add_argument("--project-id", required=True)
    start.add_argument("--workspace-root", default=".replica")
    start.add_argument("--code-root", required=True)
    start.add_argument("--reference-id", required=True)
    start.add_argument("--reference-platform", required=True, choices=SUPPORTED_PLATFORMS)
    start.add_argument("--replica-id", required=True)
    start.add_argument("--replica-platform", required=True, choices=SUPPORTED_PLATFORMS)
    start.add_argument("--scope-id", default="unspecified")
    start.add_argument("--web-fidelity", default="functional", choices=sorted(WEB_FIDELITY_LEVELS))
    start.add_argument("--asset-rights", default="unknown", choices=sorted(ASSET_RIGHTS_LEVELS))
    start.add_argument(
        "--reference-write-policy",
        default="read_only",
        choices=("read_only", "reversible_test_writes", "writable_test"),
    )

    status = subparsers.add_parser("status", help="Read a non-mutating project summary.")
    _add_command_workspace(status)
    status.add_argument("--full", action="store_true", help="Return the complete validated state.")

    migrate_web = subparsers.add_parser(
        "migrate-web-policy",
        help="Migrate a legacy Web project to an audited workflow_version=2 policy.",
    )
    _add_command_workspace(migrate_web)
    migrate_web.add_argument("--web-fidelity", required=True, choices=sorted(WEB_FIDELITY_LEVELS))
    migrate_web.add_argument("--asset-rights", required=True, choices=sorted(ASSET_RIGHTS_LEVELS))
    migrate_web.add_argument("--expected-revision", required=True, type=int)
    migrate_web.add_argument("--expected-fingerprint", required=True)
    migrate_web.add_argument("--approval-ref", required=True)
    migrate_web.add_argument("--actor", default="coordinator")
    migrate_web.add_argument("--dry-run", action="store_true")
    migrate_web.add_argument("--resume-run", action="store_true")

    checkpoint = subparsers.add_parser("checkpoint", help="Record a durable Goal checkpoint.")
    _add_command_workspace(checkpoint)
    checkpoint.add_argument("--checkpoint-id")
    checkpoint.add_argument("--summary", required=True)
    checkpoint.add_argument("--actor", default="coordinator")
    checkpoint.add_argument("--phase")
    checkpoint.add_argument("--run-state", choices=sorted(RUN_STATES))
    checkpoint.add_argument("--next-action", action="append", default=[])
    checkpoint.add_argument("--evidence-id", "--evidence", dest="evidence_ids", action="append", default=[])
    checkpoint.add_argument("--dirty-file", action="append", default=[])
    checkpoint.add_argument("--blocker", action="append", default=[])

    add_gap = subparsers.add_parser("add-gap", help="Add a stable Gap without replacing an existing one.")
    _add_command_workspace(add_gap)
    add_gap.add_argument("--gap-id", required=True)
    add_gap.add_argument("--title", required=True)
    add_gap.add_argument("--description", default="")
    add_gap.add_argument("--priority", default="P1", choices=tuple(PRIORITY_ORDER))
    add_gap.add_argument("--scenario-id", action="append", default=[])
    add_gap.add_argument("--reference-evidence", action="append", default=[])
    add_gap.add_argument("--replica-evidence", action="append", default=[])
    add_gap.add_argument("--acceptance", action="append", default=[])
    add_gap.add_argument("--actor", default="coordinator")

    update_gap = subparsers.add_parser("update-gap", help="Atomically update evidence and Scenario contracts on an existing open Gap.")
    _add_command_workspace(update_gap)
    update_gap.add_argument("--gap-id", required=True)
    update_gap.add_argument("--title")
    update_gap.add_argument("--description")
    update_gap.add_argument("--scenario-id", action="append", default=[])
    update_gap.add_argument("--reference-evidence", action="append", default=[])
    update_gap.add_argument("--replica-evidence", action="append", default=[])
    update_gap.add_argument("--acceptance", action="append", default=[])
    update_gap.add_argument("--remove-acceptance", action="append", default=[])
    update_gap.add_argument("--actor", default="coordinator")

    add_task = subparsers.add_parser("add-task", help="Add a dependency-aware task and its resource set.")
    _add_command_workspace(add_task)
    add_task.add_argument("--task-id", required=True)
    goal_group = add_task.add_mutually_exclusive_group(required=True)
    goal_group.add_argument("--goal")
    goal_group.add_argument("--title", dest="title_goal")
    add_task.add_argument("--gap-id", action="append", default=[])
    add_task.add_argument("--priority", default="P1", choices=tuple(PRIORITY_ORDER))
    add_task.add_argument("--input", action="append", default=[])
    add_task.add_argument("--depends-on", "--dependency", dest="dependencies", action="append", default=[])
    add_task.add_argument("--resource-key", "--resource", dest="resource_keys", action="append", default=[])
    add_task.add_argument("--editable-path", action="append", default=[])
    add_task.add_argument("--forbidden-path", action="append", default=[])
    add_task.add_argument("--base-revision", default="")
    add_task.add_argument("--acceptance", action="append", default=[])
    add_task.add_argument("--expected-output", action="append", default=[])
    add_task.add_argument("--task-kind", default="generic", choices=tuple(sorted(TASK_KINDS)))
    add_task.add_argument("--preflight-report", default="")
    add_task.add_argument("--preflight-sha256", default="")
    add_task.add_argument("--preflight-scope-id", default="")
    add_task.add_argument("--actor", default="coordinator")

    claim = subparsers.add_parser("claim", help="Atomically claim a task and all exact resource leases.")
    _add_command_workspace(claim)
    claim.add_argument("--task-id")
    claim.add_argument("--owner", required=True)
    claim.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)

    heartbeat = subparsers.add_parser("heartbeat", help="Renew an owned lease after verifying its identity.")
    _add_command_workspace(heartbeat)
    heartbeat.add_argument("--task-id", required=True)
    heartbeat.add_argument("--owner", required=True)
    heartbeat.add_argument("--lease-id")
    heartbeat.add_argument("--lease-epoch", type=int)
    heartbeat.add_argument("--ttl-seconds", type=int)

    handoff = subparsers.add_parser("handoff", help="Write a self-contained handoff and release its lease.")
    _add_command_workspace(handoff)
    handoff.add_argument("--task-id", required=True)
    handoff.add_argument("--owner", required=True)
    handoff.add_argument("--lease-id")
    handoff.add_argument("--lease-epoch", type=int)
    handoff.add_argument("--result", default="completed", choices=("completed", "complete", "done", "ready", "partial", "blocked"))
    handoff.add_argument("--summary", required=True)
    handoff.add_argument("--changed-file", action="append", default=[])
    handoff.add_argument("--commit-or-patch", default="")
    handoff.add_argument("--validation", action="append", default=[])
    handoff.add_argument("--evidence-id", "--evidence", dest="evidence_ids", action="append", default=[])
    handoff.add_argument("--remaining-uncertainty", action="append", default=[])
    handoff.add_argument("--next-action", default="")

    accept_handoff = subparsers.add_parser(
        "accept-handoff",
        help="Coordinator marks a reviewed handoff merged or rejected.",
    )
    _add_command_workspace(accept_handoff)
    accept_handoff.add_argument("--handoff-id", required=True)
    accept_handoff.add_argument("--accepted-by", required=True)
    accept_handoff.add_argument("--result", required=True, choices=("merged", "rejected"))
    accept_handoff.add_argument("--note", default="")
    accept_handoff.add_argument("--validation", action="append", default=[])
    accept_handoff.add_argument("--evidence-id", "--evidence", dest="evidence_ids", action="append", default=[])

    reap = subparsers.add_parser("reap", help="Release expired leases only after positive inactivity confirmation.")
    _add_command_workspace(reap)
    reap.add_argument("--confirm-inactive", action="store_true")
    reap.add_argument("--task-id")
    reap.add_argument("--owner")
    reap.add_argument("--confirmed-by", default="coordinator")
    reap.add_argument("--reason", default="Agent/process/worktree confirmed inactive after lease expiry.")

    close_gap = subparsers.add_parser("close-gap", help="Close a Gap only with independent QA evidence.")
    _add_command_workspace(close_gap)
    close_gap.add_argument("--gap-id", required=True)
    close_gap.add_argument("--qa-evidence", "--qa-evidence-id", dest="qa_evidence", action="append", default=[])
    close_gap.add_argument("--qa-by", default="qa")
    close_gap.add_argument("--qa-report", default="")
    close_gap.add_argument("--qa-report-sha256", default="")
    close_gap.add_argument("--resolution", default="verified", choices=("verified", "accepted_deviation"))
    close_gap.add_argument("--note", default="")
    close_gap.add_argument("--actor", default="coordinator")

    validate = subparsers.add_parser("validate", help="Check schema, secret safety, and cross-record invariants.")
    _add_command_workspace(validate)
    return parser


def _print_json(value: Mapping[str, Any], stream: Any = sys.stdout) -> None:
    json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
    stream.write("\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command in {"start", "init"}:
            _, result = ReplicaController.start_project(
                project_id=args.project_id,
                workspace_root=Path(args.workspace_root),
                code_root=args.code_root,
                reference_id=args.reference_id,
                reference_platform=args.reference_platform,
                replica_id=args.replica_id,
                replica_platform=args.replica_platform,
                scope_id=args.scope_id,
                reference_write_policy=args.reference_write_policy,
                web_fidelity=args.web_fidelity,
                asset_rights=args.asset_rights,
                lock_timeout_seconds=args.lock_timeout,
            )
            _print_json(result)
            if not result.get("valid"):
                return 3
            return 0 if result.get("created") else 4

        explicit_workspace = getattr(args, "command_workspace", None) or args.workspace
        workspace = discover_workspace(explicit_workspace)
        controller = ReplicaController(workspace, lock_timeout_seconds=args.lock_timeout)

        if args.command == "status":
            result = controller.status(full=args.full)
        elif args.command == "migrate-web-policy":
            result = controller.migrate_web_policy(
                web_fidelity=args.web_fidelity,
                asset_rights=args.asset_rights,
                expected_revision=args.expected_revision,
                expected_fingerprint=args.expected_fingerprint,
                approval_ref=args.approval_ref,
                actor=args.actor,
                dry_run=args.dry_run,
                resume_run=args.resume_run,
            )
        elif args.command == "checkpoint":
            result = controller.checkpoint(
                checkpoint_id=args.checkpoint_id,
                summary=args.summary,
                actor=args.actor,
                phase=args.phase,
                run_state=args.run_state,
                next_actions=args.next_action,
                evidence_ids=args.evidence_ids,
                dirty_files=args.dirty_file,
                blockers=args.blocker,
            )
        elif args.command == "add-gap":
            result = controller.add_gap(
                gap_id=args.gap_id,
                title=args.title,
                description=args.description,
                priority=args.priority,
                scenario_ids=args.scenario_id,
                reference_evidence=args.reference_evidence,
                replica_evidence=args.replica_evidence,
                acceptance=args.acceptance,
                actor=args.actor,
            )
        elif args.command == "update-gap":
            result = controller.update_gap(
                gap_id=args.gap_id,
                title=args.title,
                description=args.description,
                scenario_ids=args.scenario_id,
                reference_evidence=args.reference_evidence,
                replica_evidence=args.replica_evidence,
                acceptance=args.acceptance,
                remove_acceptance=args.remove_acceptance,
                actor=args.actor,
            )
        elif args.command == "add-task":
            result = controller.add_task(
                task_id=args.task_id,
                goal=args.goal or args.title_goal,
                gap_ids=args.gap_id,
                priority=args.priority,
                inputs=args.input,
                dependencies=args.dependencies,
                resource_keys=args.resource_keys,
                editable_paths=args.editable_path,
                forbidden_paths=args.forbidden_path,
                base_revision=args.base_revision,
                acceptance=args.acceptance,
                expected_outputs=args.expected_output,
                task_kind=args.task_kind,
                preflight_report=args.preflight_report,
                preflight_sha256=args.preflight_sha256,
                preflight_scope_id=args.preflight_scope_id,
                actor=args.actor,
            )
        elif args.command == "claim":
            result = controller.claim(
                owner=args.owner,
                task_id=args.task_id,
                ttl_seconds=args.ttl_seconds,
            )
        elif args.command == "heartbeat":
            result = controller.heartbeat(
                task_id=args.task_id,
                owner=args.owner,
                lease_id=args.lease_id,
                lease_epoch=args.lease_epoch,
                ttl_seconds=args.ttl_seconds,
            )
        elif args.command == "handoff":
            result = controller.handoff(
                task_id=args.task_id,
                owner=args.owner,
                lease_id=args.lease_id,
                lease_epoch=args.lease_epoch,
                result=args.result,
                summary=args.summary,
                changed_files=args.changed_file,
                commit_or_patch=args.commit_or_patch,
                validation=args.validation,
                evidence_ids=args.evidence_ids,
                remaining_uncertainty=args.remaining_uncertainty,
                next_action=args.next_action,
            )
        elif args.command == "accept-handoff":
            result = controller.accept_handoff(
                handoff_id=args.handoff_id,
                accepted_by=args.accepted_by,
                result=args.result,
                note=args.note,
                validation=args.validation,
                evidence_ids=args.evidence_ids,
            )
        elif args.command == "reap":
            result = controller.reap(
                confirm_inactive=args.confirm_inactive,
                task_id=args.task_id,
                owner=args.owner,
                confirmed_by=args.confirmed_by,
                reason=args.reason,
            )
        elif args.command == "close-gap":
            result = controller.close_gap(
                gap_id=args.gap_id,
                qa_evidence=args.qa_evidence,
                qa_by=args.qa_by,
                qa_report=args.qa_report,
                qa_report_sha256=args.qa_report_sha256,
                resolution=args.resolution,
                note=args.note,
                actor=args.actor,
            )
        elif args.command == "validate":
            result = controller.validate()
            _print_json(result)
            return 0 if result["valid"] else 3
        else:  # pragma: no cover - argparse prevents this branch.
            raise ReplicaCtlError("Unknown command", "invalid_command")

        _print_json(result)
        return 0
    except StateValidationError as exc:
        _print_json({"ok": False, "error": exc.message, "code": exc.code, "errors": exc.errors}, sys.stderr)
        return 3
    except ReplicaCtlError as exc:
        _print_json({"ok": False, "error": exc.message, "code": exc.code}, sys.stderr)
        return 1
    except KeyboardInterrupt:
        _print_json({"ok": False, "error": "Interrupted", "code": "interrupted"}, sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
