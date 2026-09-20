#!/usr/bin/env python3
"""Fail-closed fidelity gate for locally captured Web assets.

The gate is intentionally conservative: a visible, in-scope asset is accepted
only when its use is authorized, its provenance is exact (or an explicit
deviation is approved), and every file can be verified inside the project
root. It never fetches an asset from the network. QA pixel recomputation reuses
the Pillow dependency already required by web_visual_diff.py.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import struct
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

try:
    from PIL import Image, ImageChops, ImageDraw
except ImportError:  # pragma: no cover - depends on the host runtime
    Image = None  # type: ignore[assignment]
    ImageChops = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]


SCHEMA_VERSION = 1
EXIT_PASS = 0
EXIT_GATE_FAILED = 2
EXIT_INVALID_MANIFEST = 3
GATE_STAGES = {"builder", "qa"}

FILE_ASSET_TYPES = {"image", "svg", "font", "video", "lottie", "sprite"}
ALLOWED_RIGHTS = {"user_owned", "licensed", "explicit_authorized"}
EXACT_RESOLUTIONS = {"exact_captured", "exact_provided", "exact_reconstructed"}
ALLOWED_RESOLUTIONS = EXACT_RESOLUTIONS | {"accepted_deviation"}
FORBIDDEN_PROVENANCE = {
    "ai_generated",
    "approximate_icon_library",
    "generated_lookalike",
    "guessed",
    "unapproved_placeholder",
    "unresolved",
}
EXACT_PROVENANCE_BY_RESOLUTION = {
    "exact_captured": {"captured_original"},
    "exact_provided": {"provided_original"},
    "exact_reconstructed": {"spec_reconstructed"},
}
DEVIATION_PROVENANCE = {
    "approved_omission",
    "approved_static_rasterization",
    "authorized_neutral_replacement",
    "user_provided_licensed_replacement",
}
SCOPE_EXCLUSION_REASONS = {
    "blocked_rights",
    "outside_component_scope",
    "declared_dynamic_region",
    "not_required_scenario",
}
PROVENANCE_FIELDS = {
    "resolution",
    "provenance",
    "origin",
    "source_kind",
    "source_type",
    "method",
    "acquisition",
    "asset_status",
    "status",
}
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "client_secret",
    "cookie",
    "credential",
    "expires",
    "id_token",
    "key",
    "password",
    "passwd",
    "pwd",
    "refresh_token",
    "secret",
    "session",
    "session_id",
    "sessionid",
    "sig",
    "signature",
    "token",
    "x_amz_credential",
    "x_amz_security_token",
    "x_amz_signature",
}
PASS_STATUSES = {"captured", "complete", "completed", "covered", "pass", "passed", "verified"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class ManifestInputError(Exception):
    """The file or JSON shape is not a schema-version-1 manifest."""

    def __init__(self, code: str, message: str, path: str = "$") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path


class JsonArgumentParser(argparse.ArgumentParser):
    """Turn argparse failures into the same JSON/exit-code contract."""

    def error(self, message: str) -> None:  # pragma: no cover - exact text belongs to argparse
        raise ManifestInputError("invalid_arguments", "--manifest and --project-root are required")


def _issue(
    code: str,
    message: str,
    path: str,
    asset_id: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {"code": code, "message": message, "path": path}
    if asset_id is not None:
        result["asset_id"] = asset_id
    return result


def _report_shell(
    status: str,
    manifest_path: Optional[Path],
    project_root: Optional[Path],
    schema_version: Any = None,
    stage: str = "qa",
) -> Dict[str, Any]:
    return {
        "gate": "web_fidelity_gate",
        "stage": stage,
        "status": status,
        "ok": status == "pass",
        "schema_version": schema_version if isinstance(schema_version, int) else None,
        "manifest": str(manifest_path) if manifest_path is not None else None,
        "manifest_sha256": None,
        "project_root": str(project_root) if project_root is not None else None,
        "summary": {
            "assets_total": 0,
            "assets_checked": 0,
            "assets_skipped": 0,
            "errors": 0,
            "warnings": 0,
            "duplicate_hash_groups": 0,
        },
        "errors": [],
        "warnings": [],
        "duplicate_hashes": [],
    }


def _normal_token(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    return re.sub(r"[\s-]+", "_", value.strip().lower())


def _normal_query_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _source_ref_issues(source_ref: Any, path: str, asset_id: str) -> List[Dict[str, Any]]:
    if source_ref is None:
        return []
    if not isinstance(source_ref, str):
        return [
            _issue(
                "source_ref_invalid",
                "source_ref must be a string when present",
                path,
                asset_id,
            )
        ]
    if not source_ref.strip():
        return [_issue("source_ref_invalid", "source_ref cannot be empty", path, asset_id)]

    try:
        parsed = urlsplit(source_ref)
    except ValueError:
        return [_issue("source_ref_invalid", "source_ref is not a valid URL or reference", path, asset_id)]

    problems: List[Dict[str, Any]] = []
    try:
        has_userinfo = parsed.username is not None or parsed.password is not None
    except ValueError:
        has_userinfo = True
    if has_userinfo:
        problems.append(
            _issue(
                "sensitive_source_ref",
                "source_ref URLs cannot contain user-info",
                path,
                asset_id,
            )
        )

    try:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        query_pairs = []
        problems.append(
            _issue(
                "source_ref_invalid",
                "source_ref contains a malformed query string",
                path,
                asset_id,
            )
        )
    if any(_normal_query_key(key) in SENSITIVE_QUERY_KEYS for key, _value in query_pairs):
        problems.append(
            _issue(
                "sensitive_source_ref",
                "source_ref URLs cannot contain sensitive query parameters",
                path,
                asset_id,
            )
        )

    try:
        hostname = parsed.hostname
    except ValueError:
        hostname = None
        problems.append(
            _issue(
                "source_ref_invalid",
                "source_ref contains an invalid hostname",
                path,
                asset_id,
            )
        )
    if parsed.scheme.lower() in {"http", "https"} and hostname and _is_private_hostname(hostname):
        problems.append(
            _issue(
                "private_remote_hotlink",
                "private or local remote hotlinks are not allowed",
                path,
                asset_id,
            )
        )
    return problems


def _is_private_hostname(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    if normalized.endswith((".internal", ".intranet", ".lan", ".local", ".localhost")):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        # A single-label DNS name is normally an intranet resource.  Public
        # domains and internationalized domains contain at least one dot.
        return "." not in normalized
    return not address.is_global


def _safe_project_path(raw_path: Any, root: Path) -> Tuple[Optional[Path], Optional[str]]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "must be a non-empty path"
    if "\x00" in raw_path:
        return None, "contains a NUL byte"
    try:
        supplied = Path(raw_path).expanduser()
        candidate = supplied if supplied.is_absolute() else root / supplied
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None, "does not resolve to a safe path inside project-root"
    return resolved, None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _normal_sha256(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    return normalized if re.fullmatch(r"[0-9a-f]{64}", normalized) else None


def _load_json_artifact(
    artifact_path: Optional[Path],
    expected_schema: str,
    issue_path: str,
    errors: List[Dict[str, Any]],
) -> Optional[Mapping[str, Any]]:
    if artifact_path is None:
        return None
    try:
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(_issue("capture_artifact_json_invalid", "capture artifact must be readable UTF-8 JSON", issue_path))
        return None
    if not isinstance(payload, Mapping) or payload.get("schemaVersion") != expected_schema:
        errors.append(
            _issue(
                "capture_artifact_schema_invalid",
                "capture artifact schemaVersion must equal %s" % expected_schema,
                issue_path,
            )
        )
        return None
    return payload


def _png_dimensions(
    artifact_path: Optional[Path],
    issue_path: str,
    errors: List[Dict[str, Any]],
) -> Optional[Tuple[int, int]]:
    if artifact_path is None:
        return None
    try:
        header = artifact_path.read_bytes()[:24]
    except OSError:
        return None
    if len(header) != 24 or header[:8] != PNG_SIGNATURE or header[12:16] != b"IHDR":
        errors.append(_issue("capture_screenshot_invalid", "capture screenshot must be a decodable PNG", issue_path))
        return None
    width, height = struct.unpack(">II", header[16:24])
    if width < 1 or height < 1:
        errors.append(_issue("capture_screenshot_invalid", "capture screenshot PNG dimensions must be positive", issue_path))
        return None
    if Image is not None:
        try:
            with Image.open(artifact_path) as image:
                image.verify()
        except (OSError, ValueError):
            errors.append(_issue("capture_screenshot_invalid", "capture screenshot PNG cannot be decoded", issue_path))
            return None
    return width, height


def _strong_mode(manifest: Mapping[str, Any]) -> bool:
    return manifest.get("fidelity") == "pixel" or manifest.get("enforcement_mode") == "capture_bundle_v2"


def _declared_discovery_count(manifest: Mapping[str, Any]) -> int:
    """Return a conservative count of already-discovered visible asset candidates.

    Legacy manifests predate the capture-bundle contract, but many of them still
    persist a reference summary.  Treating an empty ``assets`` list as complete
    when that summary reports images/SVG/video/font candidates is the exact
    failure mode that allowed builders to work from guessed visuals.
    """

    summaries = [manifest.get("reference_summary"), manifest.get("inventory_summary")]
    candidate_fields = (
        "asset_occurrences",
        "visible_asset_occurrences",
        "image",
        "images",
        "inlineSvg",
        "inline_svgs",
        "video",
        "videos",
        "font",
        "fonts",
    )
    discovered = 0
    for summary in summaries:
        if not isinstance(summary, Mapping):
            continue
        for field in candidate_fields:
            value = summary.get(field)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                discovered += value
    return discovered


def _validate_artifact_ref(
    value: Any,
    path: str,
    root: Path,
    errors: List[Dict[str, Any]],
) -> Optional[Path]:
    """Verify a fail-closed path+sha256 reference and return its local path."""

    if not isinstance(value, Mapping):
        errors.append(
            _issue(
                "strong_artifact_invalid",
                "strong-mode evidence must be an object with path and sha256",
                path,
            )
        )
        return None

    local_path, path_problem = _safe_project_path(value.get("path"), root)
    if path_problem is not None:
        errors.append(
            _issue(
                "strong_artifact_path_invalid",
                "artifact path %s" % path_problem,
                path + ".path",
            )
        )
        return None
    if local_path is None or not local_path.is_file():
        errors.append(
            _issue(
                "strong_artifact_missing",
                "strong-mode evidence artifact does not exist",
                path + ".path",
            )
        )
        return None

    expected_hash = _normal_sha256(value.get("sha256"))
    if expected_hash is None:
        errors.append(
            _issue(
                "strong_artifact_sha256_invalid",
                "artifact sha256 must be a 64-character hexadecimal digest",
                path + ".sha256",
            )
        )
        return local_path
    try:
        actual_hash = _sha256_file(local_path)
    except OSError:
        errors.append(
            _issue(
                "strong_artifact_unreadable",
                "strong-mode evidence artifact could not be read",
                path + ".path",
            )
        )
    else:
        if actual_hash != expected_hash:
            errors.append(
                _issue(
                    "strong_artifact_hash_mismatch",
                    "strong-mode evidence artifact does not match sha256",
                    path + ".sha256",
                )
            )
    return local_path


def _geometry_visible(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    width = value.get("width")
    height = value.get("height")
    if not isinstance(width, (int, float)) or isinstance(width, bool):
        return False
    if not isinstance(height, (int, float)) or isinstance(height, bool):
        return False
    if width <= 0 or height <= 0:
        return False
    rect_count = value.get("clientRectCount")
    return rect_count is None or (isinstance(rect_count, (int, float)) and rect_count > 0)


def _paint_visible(record: Mapping[str, Any]) -> bool:
    visibility = record.get("paintVisibility")
    if isinstance(visibility, Mapping) and visibility.get("paintedVisible") is False:
        return False
    return _geometry_visible(record.get("geometry"))


def _inventory_identity(record: Mapping[str, Any], index: int) -> str:
    explicit = record.get("occurrence_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    for field in ("domFingerprint", "locator"):
        candidate = record.get(field)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return "index-%d" % index


def _source_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if not isinstance(value, Mapping):
        return False
    kind = value.get("kind")
    if kind in {"blocked", "invalid"}:
        return False
    return any(value.get(field) not in (None, "") for field in ("url", "target", "mediaType", "kind"))


def _property_source_count(value: Any) -> int:
    if not isinstance(value, Mapping):
        return 0
    sources = value.get("sources")
    if isinstance(sources, list):
        return sum(1 for source in sources if _source_present(source))
    return 1 if value.get("value") not in (None, "", "none", "normal") else 0


def _derive_inventory_occurrence_ids(inventory: Mapping[str, Any]) -> set:
    """Derive stable visible asset slots from web_asset_probe/1.0 output."""

    occurrences = set()

    def add(collection: str, record: Mapping[str, Any], index: int, slot: str) -> None:
        occurrences.add("%s:%s:%s" % (collection, _inventory_identity(record, index), slot))

    for collection, source_fields in (
        ("images", ("currentSrc", "src")),
        ("imageInputs", ("currentSrc", "src")),
    ):
        records = inventory.get(collection)
        if not isinstance(records, list):
            continue
        for index, record in enumerate(records):
            if not isinstance(record, Mapping) or not _paint_visible(record):
                continue
            if any(_source_present(record.get(field)) for field in source_fields):
                add(collection, record, index, "content")

    videos = inventory.get("videos")
    if isinstance(videos, list):
        for index, record in enumerate(videos):
            if not isinstance(record, Mapping) or not _paint_visible(record):
                continue
            if any(_source_present(record.get(field)) for field in ("currentSrc", "src")):
                add("videos", record, index, "content")
            if _source_present(record.get("poster")):
                add("videos", record, index, "poster")

    for collection, slot in (
        ("inlineSvgs", "markup"),
        ("svgUses", "reference"),
        ("svgExternalReferences", "source"),
        ("canvases", "bitmap"),
        ("iframes", "content"),
    ):
        records = inventory.get(collection)
        if not isinstance(records, list):
            continue
        for index, record in enumerate(records):
            if isinstance(record, Mapping) and _paint_visible(record):
                add(collection, record, index, slot)

    visible_identities = set()
    visible_elements = inventory.get("visibleElements")
    if isinstance(visible_elements, list):
        for index, record in enumerate(visible_elements):
            if isinstance(record, Mapping):
                visible_identities.add(_inventory_identity(record, index))

    for collection in ("cssImages", "pseudoElements"):
        records = inventory.get(collection)
        if not isinstance(records, list):
            continue
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                continue
            identity = _inventory_identity(record, index)
            paint_visibility = record.get("paintVisibility")
            if isinstance(paint_visibility, Mapping) and paint_visibility.get("paintedVisible") is False:
                continue
            if not _paint_visible(record) and identity not in visible_identities:
                continue
            properties = record.get("properties")
            if isinstance(properties, Mapping):
                for property_name, value in sorted(properties.items()):
                    count = _property_source_count(value)
                    for source_index in range(count):
                        add(collection, record, index, "%s-%d" % (property_name, source_index))
            content = record.get("content")
            count = _property_source_count(content)
            for source_index in range(count):
                add(collection, record, index, "content-%d" % source_index)
    return occurrences


def _manifest_occurrence_ids(
    assets: Sequence[Mapping[str, Any]],
    errors: List[Dict[str, Any]],
) -> set:
    occurrences = set()
    for asset_index, asset in enumerate(assets):
        path = "$.assets[%d].occurrences" % asset_index
        entries = asset.get("occurrences")
        if not isinstance(entries, list) or not entries:
            errors.append(
                _issue(
                    "asset_occurrences_missing",
                    "strong-mode assets require a non-empty occurrences array",
                    path,
                    _asset_identifier(asset),
                )
            )
            continue
        for occurrence_index, occurrence in enumerate(entries):
            occurrence_path = "%s[%d].occurrence_id" % (path, occurrence_index)
            occurrence_id = occurrence.get("occurrence_id") if isinstance(occurrence, Mapping) else None
            if not isinstance(occurrence_id, str) or not occurrence_id.strip():
                errors.append(
                    _issue(
                        "occurrence_id_invalid",
                        "occurrence_id must be a non-empty string",
                        occurrence_path,
                        _asset_identifier(asset),
                    )
                )
                continue
            occurrence_id = occurrence_id.strip()
            if occurrence_id in occurrences:
                errors.append(
                    _issue(
                        "occurrence_id_duplicate",
                        "occurrence_id values must be unique across assets",
                        occurrence_path,
                        _asset_identifier(asset),
                    )
                )
            occurrences.add(occurrence_id)
    return occurrences


def _asset_identifier(asset: Mapping[str, Any]) -> Optional[str]:
    for field in ("asset_id", "id"):
        value = asset.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _asset_shape_errors(assets: Sequence[Any]) -> List[Dict[str, Any]]:
    errors: List[Dict[str, Any]] = []
    seen_ids = set()
    for index, asset in enumerate(assets):
        path = "$.assets[%d]" % index
        if not isinstance(asset, Mapping):
            errors.append(_issue("asset_invalid", "each asset must be an object", path))
            continue
        asset_id = _asset_identifier(asset)
        declared_ids = [
            asset[field].strip()
            for field in ("asset_id", "id")
            if isinstance(asset.get(field), str) and asset[field].strip()
        ]
        if len(set(declared_ids)) > 1:
            errors.append(
                _issue(
                    "asset_id_conflict",
                    "asset_id and id cannot disagree",
                    path,
                )
            )
        if asset_id is None:
            errors.append(
                _issue("asset_id_invalid", "asset_id must be a non-empty string", path + ".asset_id")
            )
        elif asset_id in seen_ids:
            errors.append(
                _issue("asset_id_duplicate", "asset ids must be unique", path + ".asset_id")
            )
        else:
            seen_ids.add(asset_id)
        for field in ("in_scope", "visible"):
            if field in asset and not isinstance(asset[field], bool):
                errors.append(
                    _issue(
                        "asset_flag_invalid",
                        "%s must be a boolean" % field,
                        path + "." + field,
                        asset_id,
                    )
                )
    return errors


def _requirement_id(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, Mapping):
        for field in ("id", "name", "viewport", "state"):
            candidate = value.get(field)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return None


def _entry_passed(value: Any, strings_are_passed: bool) -> Optional[bool]:
    if isinstance(value, str):
        return strings_are_passed
    if not isinstance(value, Mapping):
        return None
    for field in ("covered", "captured", "tested", "verified", "pass"):
        if field in value:
            return value[field] is True
    status = _normal_token(value.get("status"))
    if status is not None:
        return status in PASS_STATUSES
    return None


def _coverage_ids(value: Any) -> Optional[set]:
    if not isinstance(value, list):
        return None
    ids = set()
    for entry in value:
        entry_id = _requirement_id(entry)
        entry_failed = isinstance(entry, Mapping) and _entry_passed(entry, strings_are_passed=True) is False
        if entry_id is not None and not entry_failed:
            ids.add(entry_id)
    return ids


def _validate_required_collection(
    manifest: Mapping[str, Any],
    required_field: str,
    coverage_fields: Iterable[str],
    errors: List[Dict[str, Any]],
) -> List[Any]:
    entries = manifest.get(required_field)
    if not isinstance(entries, list) or not entries:
        errors.append(
            _issue(
                required_field + "_missing",
                "%s must be a non-empty array" % required_field,
                "$." + required_field,
            )
        )
        return []

    external_coverage: Optional[set] = None
    external_field: Optional[str] = None
    for field in coverage_fields:
        if field in manifest:
            external_field = field
            external_coverage = _coverage_ids(manifest[field])
            if external_coverage is None:
                errors.append(
                    _issue(
                        field + "_invalid",
                        "%s must be an array" % field,
                        "$." + field,
                    )
                )
                external_coverage = set()
            break

    seen = set()
    for index, entry in enumerate(entries):
        path = "$.%s[%d]" % (required_field, index)
        entry_id = _requirement_id(entry)
        if entry_id is None:
            errors.append(
                _issue(
                    required_field + "_entry_invalid",
                    "required entries need a non-empty id or name",
                    path,
                )
            )
            continue
        if entry_id in seen:
            errors.append(
                _issue(
                    required_field + "_duplicate",
                    "required entry ids must be unique",
                    path,
                )
            )
            continue
        seen.add(entry_id)
        if external_coverage is not None:
            passed = entry_id in external_coverage
            passed_path = "$." + str(external_field)
        else:
            passed = _entry_passed(entry, strings_are_passed=True)
            passed_path = path
        if passed is not True:
            errors.append(
                _issue(
                    required_field + "_uncovered",
                    "required entry has not been explicitly covered",
                    passed_path,
                )
            )
    return entries


def _reference_artifacts(entry: Mapping[str, Any]) -> Optional[List[Any]]:
    capture = entry.get("reference_capture")
    if capture is None:
        capture = entry.get("reference_evidence")
    if not isinstance(capture, Mapping):
        return None
    artifacts = capture.get("artifacts")
    return artifacts if isinstance(artifacts, list) else None


def _validate_strong_required_collection(
    manifest: Mapping[str, Any],
    required_field: str,
    root: Path,
    errors: List[Dict[str, Any]],
) -> List[Any]:
    entries = manifest.get(required_field)
    if not isinstance(entries, list) or not entries:
        errors.append(
            _issue(
                required_field + "_missing",
                "%s must be a non-empty array" % required_field,
                "$." + required_field,
            )
        )
        return []

    seen = set()
    seen_bundle_paths: set[str] = set()
    for index, entry in enumerate(entries):
        path = "$.%s[%d]" % (required_field, index)
        if not isinstance(entry, Mapping):
            errors.append(
                _issue(
                    "bare_coverage_forbidden",
                    "strong mode requires an object backed by reference capture evidence",
                    path,
                )
            )
            continue
        entry_id = _requirement_id(entry)
        if entry_id is None:
            errors.append(
                _issue(
                    required_field + "_entry_invalid",
                    "required entries need a non-empty id or name",
                    path,
                )
            )
            continue
        if entry_id in seen:
            errors.append(
                _issue(
                    required_field + "_duplicate",
                    "required entry ids must be unique",
                    path,
                )
            )
        seen.add(entry_id)

        artifacts = _reference_artifacts(entry)
        if artifacts is None or not artifacts:
            errors.append(
                _issue(
                    "reference_capture_evidence_missing",
                    "strong-mode coverage requires reference_capture.artifacts",
                    path + ".reference_capture",
                )
            )
            continue

        artifact_kinds = set()
        for artifact_index, artifact in enumerate(artifacts):
            artifact_path = "%s.reference_capture.artifacts[%d]" % (path, artifact_index)
            if not isinstance(artifact, Mapping):
                errors.append(
                    _issue(
                        "strong_artifact_invalid",
                        "reference capture artifact must be an object",
                        artifact_path,
                    )
                )
                continue
            kind = _normal_token(artifact.get("kind", artifact.get("type")))
            if kind is None:
                errors.append(
                    _issue(
                        "reference_capture_artifact_kind_missing",
                        "reference capture artifacts require kind or type",
                        artifact_path + ".kind",
                    )
                )
            else:
                artifact_kinds.add(kind)
            _validate_artifact_ref(artifact, artifact_path, root, errors)
        if not any("screenshot" in kind for kind in artifact_kinds):
            errors.append(
                _issue(
                    "reference_screenshot_evidence_missing",
                    "reference capture requires a screenshot artifact",
                    path + ".reference_capture.artifacts",
                )
            )
        if not any("probe" in kind or "style" in kind for kind in artifact_kinds):
            errors.append(
                _issue(
                    "reference_probe_style_evidence_missing",
                    "reference capture requires a probe or style artifact",
                    path + ".reference_capture.artifacts",
                )
            )
        bundle_artifacts = [
            artifact
            for artifact in artifacts
            if isinstance(artifact, Mapping)
            and _normal_token(artifact.get("kind", artifact.get("type"))) in {"capture-bundle", "capture_bundle"}
        ]
        if len(bundle_artifacts) != 1:
            errors.append(
                _issue(
                    "reference_capture_bundle_missing",
                    "each required viewport/state must bind exactly one capture bundle",
                    path + ".reference_capture.artifacts",
                )
            )
            continue
        bundle_ref = bundle_artifacts[0]
        bundle_ref_path = bundle_ref.get("path")
        if isinstance(bundle_ref_path, str):
            if bundle_ref_path in seen_bundle_paths:
                errors.append(
                    _issue(
                        "reference_capture_bundle_reused",
                        "one capture bundle cannot satisfy multiple required entries in the same collection",
                        path + ".reference_capture.artifacts",
                    )
                )
            seen_bundle_paths.add(bundle_ref_path)
        bundle_path = _validate_artifact_ref(bundle_ref, path + ".reference_capture.bundle", root, errors)
        if bundle_path is None:
            continue
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            bundle = None
        context = bundle.get("context") if isinstance(bundle, Mapping) else None
        expected_context_field = "viewportId" if required_field == "required_viewports" else "stateId"
        expected_context = {
            "projectId": manifest.get("project_id"),
            "pageId": manifest.get("page_id"),
            "scenarioId": manifest.get("scenario_id"),
            "baselineId": manifest.get("baseline_id"),
        }
        if (
            not isinstance(bundle, Mapping)
            or bundle.get("schemaVersion") != "web-capture-bundle/2.0"
            or not isinstance(context, Mapping)
            or context.get("side") != "reference"
            or context.get(expected_context_field) != entry_id
            or any(context.get(field) != value for field, value in expected_context.items())
        ):
            errors.append(
                _issue(
                    "reference_capture_bundle_context_mismatch",
                    "required entry id and project context must match its own reference capture bundle",
                    path + ".reference_capture.artifacts",
                )
            )
            continue
        bundle_payload_artifacts = bundle.get("artifacts")
        bundle_screenshot = bundle_payload_artifacts.get("screenshot") if isinstance(bundle_payload_artifacts, Mapping) else None
        screenshot_artifacts = [
            artifact for artifact in artifacts
            if isinstance(artifact, Mapping)
            and "screenshot" in str(_normal_token(artifact.get("kind", artifact.get("type"))) or "")
        ]
        if not isinstance(bundle_screenshot, Mapping) or not any(
            screenshot.get("path") == bundle_screenshot.get("path")
            and _normal_sha256(screenshot.get("sha256")) == _normal_sha256(bundle_screenshot.get("sha256"))
            for screenshot in screenshot_artifacts
        ):
            errors.append(
                _issue(
                    "reference_capture_bundle_screenshot_mismatch",
                    "required entry screenshot must be the screenshot from its bound capture bundle",
                    path + ".reference_capture.artifacts",
                )
            )
    return entries


def _recompute_visual_metrics(
    reference_path: Path,
    replica_path: Path,
    report: Mapping[str, Any],
) -> Optional[Dict[str, Any]]:
    if Image is None or ImageChops is None or ImageDraw is None:
        return None
    try:
        reference = Image.open(reference_path).convert("RGB")
        replica = Image.open(replica_path).convert("RGB")
    except (OSError, ValueError):
        return None
    if reference.size != replica.size:
        return {"dimension_mismatch": True}
    difference = ImageChops.difference(reference, replica)
    red, green, blue = difference.split()
    max_channel = ImageChops.lighter(ImageChops.lighter(red, green), blue)
    masks = report.get("masks") if isinstance(report.get("masks"), list) else []
    mask_bitmap = Image.new("1", reference.size, 0)
    for mask in masks:
        if not isinstance(mask, Mapping):
            continue
        try:
            x, y, width, height = int(mask["x"]), int(mask["y"]), int(mask["width"]), int(mask["height"])
        except (KeyError, TypeError, ValueError):
            continue
        box = (x, y, x + width - 1, y + height - 1)
        ImageDraw.Draw(max_channel).rectangle(box, fill=0)
        ImageDraw.Draw(mask_bitmap).rectangle(box, fill=1)
    histogram = max_channel.histogram()
    thresholds = report.get("thresholds") if isinstance(report.get("thresholds"), Mapping) else {}
    channel_threshold = thresholds.get("channel_threshold", 16)
    if not isinstance(channel_threshold, int) or isinstance(channel_threshold, bool) or not 0 <= channel_threshold <= 255:
        return None
    masked_pixels = int(sum(mask_bitmap.histogram()[1:]))
    compared_pixels = reference.width * reference.height - masked_pixels
    if compared_pixels <= 0:
        return None
    diff_pixels = int(sum(histogram[channel_threshold + 1 :]))
    exact_diff_pixels = int(sum(histogram[1:]))
    return {
        "dimension_mismatch": False,
        "diff_pixels": diff_pixels,
        "exact_diff_pixels": exact_diff_pixels,
        "compared_pixels": compared_pixels,
        "masked_pixels": masked_pixels,
        "diff_ratio": diff_pixels / compared_pixels,
    }


def _validate_stability_report(
    report_ref: Any,
    expected_screenshot: Any,
    expected_capture_bundle: Any,
    *,
    expected_side: str,
    expected_scope_id: Optional[str],
    expected_context: Mapping[str, Any],
    path: str,
    root: Path,
    errors: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Validate and independently recompute one exact stability proof."""

    report_path = _validate_artifact_ref(report_ref, path, root, errors)
    if report_path is None:
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(_issue("stability_report_invalid", "stability report must be readable UTF-8 JSON", path + ".path"))
        return None
    if (
        not isinstance(report, Mapping)
        or report.get("schema_version") != 1
        or report.get("gate") != "web_stability_gate"
        or report.get("ok") is not True
        or report.get("status") != "pass"
        or report.get("mode") != "pixel"
        or report.get("side") != expected_side
        or report.get("scope_id") != expected_scope_id
    ):
        errors.append(
            _issue(
                "stability_report_failed",
                "pixel QA requires a passing side/scope-bound web_stability_gate/1 report",
                path + ".path",
            )
        )
        return None

    canonical = report.get("canonical")
    if not isinstance(canonical, Mapping) or not isinstance(expected_screenshot, Mapping) or (
        canonical.get("path") != expected_screenshot.get("path")
        or _normal_sha256(canonical.get("sha256")) != _normal_sha256(expected_screenshot.get("sha256"))
    ):
        errors.append(
            _issue(
                "stability_canonical_mismatch",
                "stability report canonical screenshot must equal the critical diff screenshot",
                path + ".path",
            )
        )

    samples = report.get("samples")
    pair = report.get("stable_consecutive_pair")
    if not isinstance(samples, list) or len(samples) < 2 or not (
        isinstance(pair, list)
        and len(pair) == 2
        and all(isinstance(value, int) and not isinstance(value, bool) for value in pair)
        and pair[1] == pair[0] + 1
        and 0 <= pair[0] < pair[1] < len(samples)
    ):
        errors.append(_issue("stability_samples_invalid", "stability report requires a valid consecutive sample pair", path + ".path"))
        return None

    pair_canonical = samples[pair[1]]
    if not isinstance(pair_canonical, Mapping) or not isinstance(canonical, Mapping) or (
        pair_canonical.get("path") != canonical.get("path")
        or _normal_sha256(pair_canonical.get("sha256")) != _normal_sha256(canonical.get("sha256"))
    ):
        errors.append(
            _issue(
                "stability_canonical_not_from_pair",
                "canonical screenshot must be the second sample in the proven stable consecutive pair",
                path + ".path",
            )
        )

    sample_paths: List[Optional[Path]] = []
    seen_paths: set[Path] = set()
    for index, sample in enumerate(samples):
        sample_path = _validate_artifact_ref(sample, "%s.samples[%d]" % (path, index), root, errors)
        _png_dimensions(sample_path, "%s.samples[%d].path" % (path, index), errors)
        sample_paths.append(sample_path)
        if sample_path is not None:
            if sample_path in seen_paths:
                errors.append(_issue("stability_sample_reused", "stability samples must resolve to distinct artifact paths", path + ".path"))
            seen_paths.add(sample_path)

    capture_bundles = report.get("capture_bundles")
    if not isinstance(capture_bundles, list) or len(capture_bundles) != len(samples):
        errors.append(
            _issue(
                "stability_capture_bundles_missing",
                "pixel stability requires one context-bound capture bundle per screenshot sample",
                path + ".path",
            )
        )
        return None
    capture_records: List[Optional[Dict[str, Any]]] = []
    seen_bundles: set[Path] = set()
    for index, (bundle_ref, sample_ref) in enumerate(zip(capture_bundles, samples)):
        bundle_path = _validate_artifact_ref(bundle_ref, "%s.capture_bundles[%d]" % (path, index), root, errors)
        if bundle_path is None:
            capture_records.append(None)
            continue
        if bundle_path in seen_bundles:
            errors.append(_issue("stability_capture_bundle_reused", "stability capture bundles must resolve to distinct artifact paths", path + ".path"))
        seen_bundles.add(bundle_path)
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(_issue("stability_capture_bundle_invalid", "stability capture bundle must be readable UTF-8 JSON", path + ".path"))
            capture_records.append(None)
            continue
        context = bundle.get("context") if isinstance(bundle, Mapping) else None
        artifacts = bundle.get("artifacts") if isinstance(bundle, Mapping) else None
        screenshot = artifacts.get("screenshot") if isinstance(artifacts, Mapping) else None
        environment_ref = artifacts.get("environment") if isinstance(artifacts, Mapping) else None
        if (
            not isinstance(bundle, Mapping)
            or bundle.get("schemaVersion") != "web-capture-bundle/2.0"
            or bundle.get("contentPolicy") != "public-observable"
            or not isinstance(context, Mapping)
            or context.get("side") != expected_side
            or any(context.get(field) != value for field, value in expected_context.items())
            or not isinstance(screenshot, Mapping)
            or not isinstance(sample_ref, Mapping)
            or screenshot.get("path") != sample_ref.get("path")
            or _normal_sha256(screenshot.get("sha256")) != _normal_sha256(sample_ref.get("sha256"))
        ):
            errors.append(
                _issue(
                    "stability_capture_bundle_mismatch",
                    "each stability bundle must bind the same context/side and its corresponding screenshot",
                    path + ".path",
                )
            )
            capture_records.append(None)
            continue
        environment_path = _validate_artifact_ref(
            environment_ref,
            "%s.capture_bundles[%d].environment" % (path, index),
            root,
            errors,
        )
        try:
            environment = json.loads(environment_path.read_text(encoding="utf-8")) if environment_path is not None else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            environment = None
        if not isinstance(environment, Mapping) or environment.get("schemaVersion") != "web-capture-environment/1.0":
            errors.append(_issue("stability_environment_invalid", "stability capture environment is invalid", path + ".path"))
            capture_records.append(None)
            continue
        capture_records.append(
            {
                "bundle_ref": bundle_ref,
                "context": dict(context),
                "viewport": bundle.get("viewport"),
                "referenceFingerprint": bundle.get("referenceFingerprint"),
                "environmentLock": {
                    "browser": environment.get("browser"),
                    "probeViewport": environment.get("probeViewport"),
                    "renderingEnvironment": environment.get("renderingEnvironment"),
                    "screenshotPolicy": environment.get("screenshotPolicy"),
                },
            }
        )

    valid_records = [record for record in capture_records if isinstance(record, Mapping)]
    if len(valid_records) != len(samples):
        return None
    first_record = valid_records[0]
    for record in valid_records[1:]:
        if any(
            record.get(field) != first_record.get(field)
            for field in ("context", "viewport", "referenceFingerprint", "environmentLock")
        ):
            errors.append(
                _issue(
                    "stability_environment_mismatch",
                    "stability captures must share the same context, viewport, identity and rendering environment",
                    path + ".path",
                )
            )

    canonical_bundle_ref = capture_bundles[pair[1]]
    if not isinstance(canonical_bundle_ref, Mapping) or not isinstance(expected_capture_bundle, Mapping) or (
        canonical_bundle_ref.get("path") != expected_capture_bundle.get("path")
        or _normal_sha256(canonical_bundle_ref.get("sha256")) != _normal_sha256(expected_capture_bundle.get("sha256"))
    ):
        errors.append(
            _issue(
                "stability_canonical_bundle_mismatch",
                "the canonical stability sample must come from the capture bundle bound to the critical diff",
                path + ".path",
            )
        )

    left_path = sample_paths[pair[0]]
    right_path = sample_paths[pair[1]]
    recomputed = (
        _recompute_visual_metrics(
            left_path,
            right_path,
            {"thresholds": {"channel_threshold": 0}, "masks": []},
        )
        if left_path is not None and right_path is not None
        else None
    )
    if (
        not isinstance(recomputed, Mapping)
        or recomputed.get("dimension_mismatch") is not False
        or recomputed.get("exact_diff_pixels") != 0
    ):
        errors.append(
            _issue(
                "stability_recompute_failed",
                "the declared stable consecutive pair is not exactly equal when independently recomputed",
                path + ".path",
            )
        )
    canonical_record = capture_records[pair[1]]
    return canonical_record if isinstance(canonical_record, Mapping) else None


def _validate_font_report(
    report_ref: Any,
    reference_bundle_ref: Any,
    replica_bundle_ref: Any,
    *,
    expected_scope_id: Optional[str],
    expected_root_locator: Optional[str],
    path: str,
    root: Path,
    errors: List[Dict[str, Any]],
) -> None:
    report_path = _validate_artifact_ref(report_ref, path, root, errors)
    if report_path is None:
        return
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(_issue("font_report_invalid", "font report must be readable UTF-8 JSON", path + ".path"))
        return
    if (
        not isinstance(report, Mapping)
        or report.get("schema_version") != 1
        or report.get("gate") != "web_font_fallback"
        or report.get("ok") is not True
        or report.get("status") != "pass"
        or report.get("scope_id") != expected_scope_id
        or report.get("root_locator") != expected_root_locator
        or not isinstance(report.get("unexpected_fallbacks"), list)
        or report.get("unexpected_fallbacks")
    ):
        errors.append(_issue("font_report_failed", "pixel QA requires a passing scope-bound web_font_fallback/1 report", path + ".path"))
        return

    usage_payloads: Dict[str, Optional[Mapping[str, Any]]] = {}
    usage_refs: Dict[str, Any] = {}
    for side in ("reference", "replica"):
        usage_ref = report.get(side)
        usage_refs[side] = usage_ref
        usage_path = _validate_artifact_ref(usage_ref, path + "." + side, root, errors)
        try:
            usage = json.loads(usage_path.read_text(encoding="utf-8")) if usage_path is not None else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            usage = None
        if (
            not isinstance(usage, Mapping)
            or usage.get("schemaVersion") != "web-platform-font-usage/1.0"
            or usage.get("scanTruncated") is not False
            or usage.get("failedNodeCount") != 0
            or usage.get("unmappedNodeCount") != 0
            or not isinstance(usage.get("records"), list)
            or usage.get("queriedNodeCount") != len(usage.get("records", []))
            or not isinstance(usage.get("families"), list)
            or not isinstance(usage.get("expectedLocators"), list)
            or not isinstance(usage.get("expectedRecords"), list)
            or not isinstance(usage.get("pseudoDeclarations"), list)
        ):
            errors.append(_issue("font_usage_invalid", "font usage capture is incomplete or invalid", path + "." + side))
            usage_payloads[side] = None
        else:
            record_keys = {
                (record.get("locator"), record.get("pseudo"))
                for record in usage.get("records", []) if isinstance(record, Mapping)
            }
            expected_keys = set()
            expected_valid = True
            for expected in usage.get("expectedRecords", []):
                if (
                    not isinstance(expected, Mapping)
                    or not isinstance(expected.get("locator"), str)
                    or expected.get("pseudo") not in {None, "::before", "::after"}
                ):
                    expected_valid = False
                    continue
                expected_keys.add((expected.get("locator"), expected.get("pseudo")))
            pseudo_keys = {
                (declaration.get("locator"), declaration.get("pseudo"))
                for declaration in usage.get("pseudoDeclarations", []) if isinstance(declaration, Mapping)
            }
            if not expected_valid or not expected_keys.issubset(record_keys) or not pseudo_keys.issubset(record_keys):
                errors.append(_issue("font_usage_invalid", "font usage does not cover every expected rendered-text locator", path + "." + side))
                usage_payloads[side] = None
            else:
                usage_payloads[side] = usage

    reference_usage = usage_payloads.get("reference")
    replica_usage = usage_payloads.get("replica")
    if isinstance(reference_usage, Mapping) and isinstance(replica_usage, Mapping):
        def scoped_records(usage: Mapping[str, Any]) -> Optional[Dict[Tuple[str, Optional[str]], Tuple[Tuple[Any, ...], ...]]]:
            if not isinstance(expected_root_locator, str) or not expected_root_locator:
                return None
            indexed: Dict[Tuple[str, Optional[str]], Tuple[Tuple[Any, ...], ...]] = {}
            for record in usage.get("records", []):
                if not isinstance(record, Mapping):
                    return None
                locator = record.get("locator")
                pseudo = record.get("pseudo")
                ancestors = record.get("ancestorLocators")
                fonts = record.get("fonts")
                if not isinstance(locator, str) or pseudo not in {None, "::before", "::after"} or not isinstance(ancestors, list) or not isinstance(fonts, list):
                    return None
                in_scope = (
                    record.get("paintedVisible") is True
                    and (
                        expected_root_locator == "*"
                        or locator == expected_root_locator
                        or locator.startswith(expected_root_locator + " > ")
                        or locator.startswith(expected_root_locator + " >>> ")
                        or expected_root_locator in ancestors
                    )
                )
                if not in_scope:
                    continue
                key = (locator, pseudo)
                if key in indexed:
                    return None
                normalized_fonts = []
                for font in fonts:
                    if not isinstance(font, Mapping) or not isinstance(font.get("glyphCount"), int):
                        return None
                    normalized_fonts.append((
                        font.get("familyName"),
                        font.get("postScriptName"),
                        font.get("isCustomFont"),
                        font.get("glyphCount"),
                    ))
                indexed[key] = tuple(normalized_fonts)
            return indexed

        def scoped_pseudo(usage: Mapping[str, Any]) -> Optional[Dict[Tuple[str, str], Tuple[Any, ...]]]:
            if not isinstance(expected_root_locator, str) or not expected_root_locator:
                return None
            indexed: Dict[Tuple[str, str], Tuple[Any, ...]] = {}
            for declaration in usage.get("pseudoDeclarations", []):
                if not isinstance(declaration, Mapping):
                    return None
                locator = declaration.get("locator")
                pseudo = declaration.get("pseudo")
                ancestors = declaration.get("ancestorLocators")
                font = declaration.get("font")
                if (
                    not isinstance(locator, str)
                    or pseudo not in {"::before", "::after"}
                    or not isinstance(ancestors, list)
                    or not isinstance(font, Mapping)
                ):
                    return None
                in_scope = (
                    expected_root_locator == "*"
                    or locator == expected_root_locator
                    or locator.startswith(expected_root_locator + " > ")
                    or locator.startswith(expected_root_locator + " >>> ")
                    or expected_root_locator in ancestors
                )
                if not in_scope:
                    continue
                key = (locator, pseudo)
                if key in indexed:
                    return None
                indexed[key] = (
                    declaration.get("content"),
                    font.get("family"),
                    font.get("style"),
                    font.get("weight"),
                    font.get("stretch"),
                )
            return indexed

        reference_records = scoped_records(reference_usage)
        replica_records = scoped_records(replica_usage)
        reference_pseudo = scoped_pseudo(reference_usage)
        replica_pseudo = scoped_pseudo(replica_usage)
        if reference_records is None or replica_records is None or reference_pseudo is None or replica_pseudo is None:
            errors.append(_issue("font_usage_invalid", "font usage records are not scope-addressable", path + ".path"))
        elif reference_records != replica_records or reference_pseudo != replica_pseudo:
            errors.append(_issue("font_report_metrics_forged", "font report pass does not match actual platform-font usage", path + ".path"))

    for side, bundle_ref in (("reference", reference_bundle_ref), ("replica", replica_bundle_ref)):
        bundle_path = _validate_artifact_ref(bundle_ref, path + "." + side + "_bundle", root, errors)
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8")) if bundle_path is not None else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            bundle = None
        artifacts = bundle.get("artifacts") if isinstance(bundle, Mapping) else None
        font_usage_ref = artifacts.get("fontUsage") if isinstance(artifacts, Mapping) else None
        report_usage_ref = usage_refs.get(side)
        if not isinstance(font_usage_ref, Mapping) or not isinstance(report_usage_ref, Mapping) or (
            font_usage_ref.get("path") != report_usage_ref.get("path")
            or _normal_sha256(font_usage_ref.get("sha256")) != _normal_sha256(report_usage_ref.get("sha256"))
        ):
            errors.append(_issue("font_report_bundle_mismatch", "font report inputs must come from the canonical capture bundles", path + ".path"))


def _validate_structure_report(
    report_ref: Any,
    reference_bundle_ref: Any,
    replica_bundle_ref: Any,
    *,
    expected_root_locator: Optional[str],
    path: str,
    root: Path,
    errors: List[Dict[str, Any]],
) -> None:
    report_path = _validate_artifact_ref(report_ref, path, root, errors)
    if report_path is None:
        return
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(_issue("structure_report_invalid", "structure report must be readable UTF-8 JSON", path + ".path"))
        return
    scope = report.get("scope") if isinstance(report, Mapping) else None
    if (
        not isinstance(report, Mapping)
        or report.get("schema_version") != 1
        or report.get("gate") != "web_structure_diff"
        or report.get("ok") is not True
        or report.get("status") != "pass"
        or not isinstance(scope, Mapping)
        or scope.get("root_locator") != expected_root_locator
        or report.get("mismatches") != []
    ):
        errors.append(_issue("structure_report_failed", "pixel QA requires a passing scope-bound web_structure_diff/1 report", path + ".path"))
        return

    inventory_paths: Dict[str, Optional[Path]] = {}
    for side, bundle_ref in (("reference", reference_bundle_ref), ("replica", replica_bundle_ref)):
        bundle_path = _validate_artifact_ref(bundle_ref, path + "." + side + "_bundle", root, errors)
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8")) if bundle_path is not None else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            bundle = None
        artifacts = bundle.get("artifacts") if isinstance(bundle, Mapping) else None
        inventory_ref = artifacts.get("inventory") if isinstance(artifacts, Mapping) else None
        inventory_path = _validate_artifact_ref(inventory_ref, path + "." + side, root, errors)
        inventory_paths[side] = inventory_path
        report_inventory_ref = report.get(side)
        report_inventory_path = _validate_artifact_ref(report_inventory_ref, path + ".report_" + side, root, errors)
        if (
            not isinstance(inventory_ref, Mapping)
            or not isinstance(report_inventory_ref, Mapping)
            or inventory_path is None
            or report_inventory_path != inventory_path
            or _normal_sha256(inventory_ref.get("sha256")) != _normal_sha256(report_inventory_ref.get("sha256"))
        ):
            errors.append(_issue("structure_report_bundle_mismatch", "structure report inputs must come from canonical capture bundles", path + ".path"))

    reference_inventory = inventory_paths.get("reference")
    replica_inventory = inventory_paths.get("replica")
    if reference_inventory is None or replica_inventory is None:
        return
    try:
        module_path = Path(__file__).with_name("web_structure_diff.py")
        spec = importlib.util.spec_from_file_location("_goal_web_structure_diff", module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("structure diff module cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tolerance = report.get("thresholds", {}).get("geometry_tolerance_css_px", 0.5)
        recomputed, code = module.compare(
            reference_inventory,
            replica_inventory,
            root_locator=expected_root_locator,
            geometry_tolerance=float(tolerance),
        )
    except Exception:
        errors.append(_issue("structure_report_recompute_failed", "structure report could not be independently recomputed", path + ".path"))
        return
    if code != 0 or recomputed.get("mismatches") != []:
        errors.append(_issue("structure_report_metrics_forged", "structure report pass does not match canonical inventories", path + ".path"))


def _validate_strong_critical_diffs(
    manifest: Mapping[str, Any],
    root: Path,
    errors: List[Dict[str, Any]],
) -> None:
    diffs = manifest.get("critical_diffs")
    if not isinstance(diffs, list) or not diffs:
        return
    if manifest.get("fidelity") == "pixel":
        viewport_ids = {
            _requirement_id(entry) for entry in manifest.get("required_viewports", [])
            if _requirement_id(entry) is not None
        }
        state_ids = {
            _requirement_id(entry) for entry in manifest.get("required_states", [])
            if _requirement_id(entry) is not None
        }
        expected_pairs = {(viewport_id, state_id) for viewport_id in viewport_ids for state_id in state_ids}
        actual_pairs = {
            (diff.get("viewport_id"), diff.get("state_id"))
            for diff in diffs if isinstance(diff, Mapping)
            and isinstance(diff.get("viewport_id"), str)
            and isinstance(diff.get("state_id"), str)
        }
        for viewport_id, state_id in sorted(expected_pairs - actual_pairs):
            errors.append(
                _issue(
                    "critical_diff_matrix_missing",
                    "pixel QA requires a critical diff for required viewport/state %s / %s" % (viewport_id, state_id),
                    "$.critical_diffs",
                )
            )
        for viewport_id, state_id in sorted(actual_pairs - expected_pairs):
            errors.append(
                _issue(
                    "critical_diff_matrix_unknown",
                    "critical diff viewport/state %s / %s is outside the required matrix" % (viewport_id, state_id),
                    "$.critical_diffs",
                )
            )
    for index, diff in enumerate(diffs):
        if not isinstance(diff, Mapping):
            continue
        path = "$.critical_diffs[%d]" % index
        screenshot_paths: Dict[str, Optional[Path]] = {}
        for field in ("reference_screenshot", "replica_screenshot"):
            if field not in diff:
                errors.append(
                    _issue(
                        "critical_diff_evidence_missing",
                        "strong-mode critical diff requires %s path+sha256 evidence" % field,
                        path + "." + field,
                    )
                )
            else:
                screenshot_paths[field] = _validate_artifact_ref(diff[field], path + "." + field, root, errors)
                _png_dimensions(screenshot_paths[field], path + "." + field + ".path", errors)

        reference_path = screenshot_paths.get("reference_screenshot")
        replica_path = screenshot_paths.get("replica_screenshot")
        if reference_path is not None and replica_path is not None and reference_path == replica_path:
            errors.append(_issue("visual_diff_same_artifact", "reference and replica screenshots must be distinct artifacts", path))

        if manifest.get("fidelity") == "pixel":
            manifest_scope = manifest.get("scope")
            expected_scope_id = manifest_scope.get("scope_id") if isinstance(manifest_scope, Mapping) else manifest.get("scope_id")
            expected_root_locator = manifest_scope.get("root_locator") if isinstance(manifest_scope, Mapping) else None
            expected_context = {
                "projectId": manifest.get("project_id"),
                "pageId": manifest.get("page_id"),
                "scenarioId": manifest.get("scenario_id"),
                "baselineId": manifest.get("baseline_id"),
                "viewportId": diff.get("viewport_id"),
                "stateId": diff.get("state_id"),
            }
            for bundle_field, side in (
                ("reference_capture_bundle", "reference"),
                ("replica_capture_bundle", "replica"),
            ):
                if bundle_field not in diff:
                    errors.append(
                        _issue(
                            side + "_capture_bundle_missing",
                            "pixel QA requires context-bound capture bundles for both sides",
                            path + "." + bundle_field,
                        )
                    )
            stability_records: Dict[str, Optional[Dict[str, Any]]] = {}
            for field, screenshot_field, bundle_ref, side in (
                ("reference_stability", "reference_screenshot", diff.get("reference_capture_bundle"), "reference"),
                ("replica_stability", "replica_screenshot", diff.get("replica_capture_bundle"), "replica"),
            ):
                if field not in diff:
                    errors.append(
                        _issue(
                            "stability_evidence_missing",
                            "pixel QA requires repeated-capture stability evidence for both sides",
                            path + "." + field,
                        )
                    )
                else:
                    stability_records[side] = _validate_stability_report(
                        diff[field],
                        diff.get(screenshot_field),
                        bundle_ref,
                        expected_side=side,
                        expected_scope_id=expected_scope_id,
                        expected_context=expected_context,
                        path=path + "." + field,
                        root=root,
                        errors=errors,
                    )
            reference_record = stability_records.get("reference")
            replica_record = stability_records.get("replica")
            if isinstance(reference_record, Mapping) and isinstance(replica_record, Mapping):
                reference_context = dict(reference_record.get("context") or {})
                replica_context = dict(replica_record.get("context") or {})
                reference_context.pop("side", None)
                replica_context.pop("side", None)
                if (
                    reference_context != replica_context
                    or reference_record.get("viewport") != replica_record.get("viewport")
                    or reference_record.get("environmentLock") != replica_record.get("environmentLock")
                ):
                    errors.append(
                        _issue(
                            "paired_capture_environment_mismatch",
                            "reference and replica canonical captures must share the same context, viewport and rendering environment",
                            path,
                        )
                    )
            if "font_report" not in diff:
                errors.append(
                    _issue(
                        "font_report_missing",
                        "pixel QA requires an actual platform-font comparison report for each viewport/state diff",
                        path + ".font_report",
                    )
                )
            else:
                _validate_font_report(
                    diff["font_report"],
                    diff.get("reference_capture_bundle"),
                    diff.get("replica_capture_bundle"),
                    expected_scope_id=expected_scope_id,
                    expected_root_locator=expected_root_locator,
                    path=path + ".font_report",
                    root=root,
                    errors=errors,
                )
            if "structure_report" not in diff:
                errors.append(
                    _issue(
                        "structure_report_missing",
                        "pixel QA requires a canonical inventory structure comparison for each viewport/state diff",
                        path + ".structure_report",
                    )
                )
            else:
                _validate_structure_report(
                    diff["structure_report"],
                    diff.get("reference_capture_bundle"),
                    diff.get("replica_capture_bundle"),
                    expected_root_locator=expected_root_locator,
                    path=path + ".structure_report",
                    root=root,
                    errors=errors,
                )

        if "diff_report" not in diff:
            errors.append(
                _issue(
                    "critical_diff_evidence_missing",
                    "strong-mode QA requires a web_visual_diff report",
                    path + ".diff_report",
                )
            )
            continue
        report_path = _validate_artifact_ref(diff["diff_report"], path + ".diff_report", root, errors)
        if "overlay" in diff:
            _validate_artifact_ref(diff["overlay"], path + ".overlay", root, errors)
        if report_path is None:
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(_issue("visual_diff_report_invalid", "visual diff report must be readable UTF-8 JSON", path + ".diff_report.path"))
            continue
        if (
            not isinstance(report, Mapping)
            or report.get("schema_version") != 1
            or report.get("gate") != "web_visual_diff"
            or report.get("ok") is not True
            or report.get("status") != "pass"
        ):
            errors.append(_issue("visual_diff_report_failed", "visual diff report must be a passing web_visual_diff/1 report", path + ".diff_report.path"))
            continue
        recomputed = (
            _recompute_visual_metrics(reference_path, replica_path, report)
            if reference_path is not None and replica_path is not None
            else None
        )
        if recomputed is None:
            errors.append(_issue("visual_diff_recompute_failed", "QA Gate could not independently decode and recompute the visual diff", path))
        elif recomputed.get("dimension_mismatch") is True:
            errors.append(_issue("visual_diff_dimension_mismatch", "reference and replica screenshots have different dimensions", path))
        else:
            metrics = report.get("metrics")
            if not isinstance(metrics, Mapping) or any(
                metrics.get(field) != recomputed[field]
                for field in ("diff_pixels", "exact_diff_pixels", "compared_pixels", "masked_pixels")
            ) or not isinstance(metrics.get("diff_ratio"), (int, float)) or abs(float(metrics["diff_ratio"]) - float(recomputed["diff_ratio"])) > 1e-12:
                errors.append(_issue("visual_diff_metrics_forged", "visual diff metrics do not match an independent recomputation", path + ".diff_report.path"))
        if manifest.get("fidelity") == "pixel":
            metrics = report.get("metrics")
            exact_diff_pixels = metrics.get("exact_diff_pixels") if isinstance(metrics, Mapping) else None
            masks = report.get("masks")
            if (
                report.get("whole_page_pixel_equivalent") is not True
                or exact_diff_pixels != 0
                or not isinstance(recomputed, Mapping)
                or recomputed.get("exact_diff_pixels") != 0
                or (isinstance(masks, list) and masks)
            ):
                errors.append(
                    _issue(
                        "visual_diff_not_pixel_exact",
                        "pixel QA requires zero exact differing pixels and no masks",
                        path + ".diff_report.path",
                    )
                )
        for report_field, manifest_field in (("reference", "reference_screenshot"), ("replica", "replica_screenshot")):
            report_ref = report.get(report_field)
            manifest_ref = diff.get(manifest_field)
            if not isinstance(report_ref, Mapping) or not isinstance(manifest_ref, Mapping) or (
                report_ref.get("path") != manifest_ref.get("path")
                or _normal_sha256(report_ref.get("sha256")) != _normal_sha256(manifest_ref.get("sha256"))
            ):
                errors.append(_issue("visual_diff_input_mismatch", "visual diff report inputs must match critical diff screenshots", path + ".diff_report.path"))
        bundle_path = _validate_artifact_ref(diff.get("reference_capture_bundle"), path + ".reference_capture_bundle", root, errors)
        if bundle_path is not None:
            try:
                bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                bundle_payload = None
            bundle_artifacts = bundle_payload.get("artifacts") if isinstance(bundle_payload, Mapping) else None
            bundle_screenshot = bundle_artifacts.get("screenshot") if isinstance(bundle_artifacts, Mapping) else None
            reference_ref = diff.get("reference_screenshot")
            if not isinstance(bundle_screenshot, Mapping) or not isinstance(reference_ref, Mapping) or (
                bundle_screenshot.get("path") != reference_ref.get("path")
                or _normal_sha256(bundle_screenshot.get("sha256")) != _normal_sha256(reference_ref.get("sha256"))
            ):
                errors.append(_issue("visual_diff_reference_not_from_bundle", "reference screenshot must be the capture bundle screenshot", path + ".reference_screenshot"))
        report_artifacts = report.get("artifacts")
        if not isinstance(report_artifacts, Mapping):
            errors.append(_issue("visual_diff_artifacts_missing", "visual diff report requires overlay and diff artifacts", path + ".diff_report.path"))
        else:
            for field in ("overlay", "diff"):
                _validate_artifact_ref(report_artifacts.get(field), path + ".diff_report.artifacts." + field, root, errors)
        masks = report.get("masks")
        if isinstance(masks, list):
            for mask_index, mask in enumerate(masks):
                if not isinstance(mask, Mapping) or not isinstance(mask.get("deviation_id"), str) or not mask.get("deviation_id"):
                    errors.append(_issue("visual_diff_mask_unbound", "every visual diff mask must bind a deviation_id", path + ".diff_report.masks[%d]" % mask_index))


def _validate_component_spec(
    manifest: Mapping[str, Any],
    root: Path,
    errors: List[Dict[str, Any]],
) -> None:
    spec_path = _validate_artifact_ref(manifest.get("component_specs"), "$.component_specs", root, errors)
    if spec_path is None:
        return
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(_issue("component_spec_invalid", "component spec must be readable UTF-8 JSON", "$.component_specs.path"))
        return
    if not isinstance(spec, Mapping) or spec.get("schemaVersion") != "web-component-spec/1.0":
        errors.append(_issue("component_spec_schema_invalid", "component spec schemaVersion must be web-component-spec/1.0", "$.component_specs.path"))
        return
    component_id = spec.get("component_id")
    scope = spec.get("scope")
    scope_id = scope.get("scope_id") if isinstance(scope, Mapping) else None
    manifest_scope = manifest.get("scope")
    manifest_scope_id = manifest_scope.get("scope_id") if isinstance(manifest_scope, Mapping) else manifest.get("scope_id")
    if not isinstance(component_id, str) or not component_id.strip():
        errors.append(_issue("component_spec_component_missing", "component spec requires component_id", "$.component_specs.path"))
    if not isinstance(scope_id, str) or not scope_id.strip() or scope_id != manifest_scope_id:
        errors.append(_issue("component_spec_scope_mismatch", "component spec scope_id must match Manifest scope", "$.component_specs.path"))
    source_inventory = spec.get("source_inventory")
    probe_inventory = manifest.get("probe_inventory")
    if not isinstance(source_inventory, Mapping) or not isinstance(probe_inventory, Mapping) or (
        source_inventory.get("path") != probe_inventory.get("path")
        or _normal_sha256(source_inventory.get("sha256")) != _normal_sha256(probe_inventory.get("sha256"))
    ):
        errors.append(_issue("component_spec_inventory_mismatch", "component spec source_inventory must match Manifest probe_inventory", "$.component_specs.path"))
    inventory_path = _validate_artifact_ref(source_inventory, "$.component_specs.source_inventory", root, errors)
    inventory_payload: Optional[Mapping[str, Any]] = None
    if inventory_path is not None:
        try:
            loaded_inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(_issue("component_spec_inventory_invalid", "component spec inventory must be readable UTF-8 JSON", "$.component_specs.source_inventory.path"))
        else:
            if isinstance(loaded_inventory, Mapping) and loaded_inventory.get("schemaVersion") == "web-asset-inventory/1.0":
                inventory_payload = loaded_inventory
            else:
                errors.append(_issue("component_spec_inventory_invalid", "component spec inventory must use web-asset-inventory/1.0", "$.component_specs.source_inventory.path"))
    if not isinstance(spec.get("viewport"), str) or not spec.get("viewport"):
        errors.append(_issue("component_spec_viewport_missing", "component spec requires viewport", "$.component_specs.path"))
    states = spec.get("states")
    if not isinstance(states, list) or not states or any(not isinstance(item, str) or not item for item in states):
        errors.append(_issue("component_spec_states_missing", "component spec requires non-empty states", "$.component_specs.path"))
    if not isinstance(spec.get("capture_context"), Mapping):
        errors.append(_issue("component_spec_context_missing", "component spec requires capture_context", "$.component_specs.capture_context"))
    elements = spec.get("elements")
    if not isinstance(elements, list) or not elements:
        errors.append(_issue("component_spec_elements_missing", "component spec requires visible element records", "$.component_specs.path"))
        return
    inventory_elements = inventory_payload.get("visibleElements") if isinstance(inventory_payload, Mapping) else None
    inventory_by_locator = {
        element.get("locator"): element
        for element in inventory_elements
        if isinstance(element, Mapping) and isinstance(element.get("locator"), str)
    } if isinstance(inventory_elements, list) else {}
    spec_locators: set[str] = set()
    for index, element in enumerate(elements):
        path = "$.component_specs.elements[%d]" % index
        if not isinstance(element, Mapping) or not isinstance(element.get("locator"), str):
            errors.append(_issue("component_spec_element_invalid", "component spec element requires locator", path))
            continue
        locator = element["locator"]
        spec_locators.add(locator)
        source_element = inventory_by_locator.get(locator)
        if source_element is None:
            errors.append(_issue("component_spec_element_not_captured", "component spec element is absent from scoped inventory", path))
        elif dict(element) != dict(source_element):
            errors.append(_issue("component_spec_element_mismatch", "component spec element must exactly match the scoped inventory record", path))
        if not isinstance(element.get("geometry"), Mapping):
            errors.append(_issue("component_spec_geometry_missing", "component spec element requires geometry", path + ".geometry"))
        if not any(isinstance(element.get(section), Mapping) for section in ("font", "layout", "layer", "paint")):
            errors.append(_issue("component_spec_styles_missing", "component spec element requires computed style sections", path))
    if inventory_by_locator and spec_locators != set(inventory_by_locator):
        errors.append(_issue("component_spec_coverage_incomplete", "component spec must cover every scoped visible element exactly once", "$.component_specs.elements"))
    root_locator = scope.get("root_locator") if isinstance(scope, Mapping) else None
    scope_kind = scope.get("kind") if isinstance(scope, Mapping) else None
    if scope_kind == "component" and isinstance(root_locator, str) and root_locator not in spec_locators:
        errors.append(_issue("component_spec_root_missing", "component scope root must be present in component spec elements", "$.component_specs.elements"))


def _validate_state_witness_against_contract(
    contract: Mapping[str, Any],
    witness: Mapping[str, Any],
    expected_phase: str,
    issue_path: str,
    errors: List[Dict[str, Any]],
) -> Optional[datetime]:
    selectors = contract.get("selectors")
    document_rule = contract.get("document")
    if not isinstance(selectors, list) or not selectors or not isinstance(document_rule, Mapping):
        errors.append(_issue("capture_state_contract_invalid", "state contract requires document rules and at least one selector", issue_path))
        return None
    normalized_rules: List[Mapping[str, Any]] = []
    positive = False
    seen_selectors = set()
    for rule in selectors:
        if not isinstance(rule, Mapping) or not isinstance(rule.get("selector"), str) or not rule.get("selector") or rule.get("selector") in seen_selectors:
            errors.append(_issue("capture_state_contract_invalid", "state contract selectors must be unique non-empty strings", issue_path))
            return None
        seen_selectors.add(rule["selector"])
        values = {field: rule.get(field) for field in ("minCount", "minVisibleCount", "maxCount", "maxVisibleCount")}
        for field, value in values.items():
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                errors.append(_issue("capture_state_contract_invalid", "state contract selector counts must be non-negative integers or null", issue_path))
                return None
        min_count = values["minCount"] if values["minCount"] is not None else 0
        min_visible = values["minVisibleCount"] if values["minVisibleCount"] is not None else 0
        if min_count == 0 and min_visible == 0 and values["maxCount"] is None and values["maxVisibleCount"] is None:
            errors.append(_issue("capture_state_contract_invalid", "state contract contains an unconstrained selector", issue_path))
            return None
        positive = positive or min_count > 0 or min_visible > 0
        normalized_rules.append(dict(rule, minCount=min_count, minVisibleCount=min_visible))
    if not positive:
        errors.append(_issue("capture_state_contract_invalid", "state contract requires at least one positive selector assertion", issue_path))
        return None

    if witness.get("phase") != expected_phase:
        errors.append(_issue("capture_state_witness_phase_invalid", "state witness phase must be %s" % expected_phase, issue_path))
    try:
        observed_at = datetime.fromisoformat(str(witness.get("observedAt")).replace("Z", "+00:00"))
        if observed_at.tzinfo is None:
            raise ValueError
    except ValueError:
        observed_at = None
        errors.append(_issue("capture_state_witness_time_invalid", "state witness requires a timezone-aware observedAt", issue_path))

    expected_location = contract.get("expectedPublicLocation")
    if expected_location is not None and witness.get("publicLocation") != expected_location:
        errors.append(_issue("capture_state_witness_location_mismatch", "state witness publicLocation does not satisfy the contract", issue_path))
    metrics = witness.get("documentMetrics")
    for field, contract_field in (("scrollWidth", "minScrollWidth"), ("scrollHeight", "minScrollHeight")):
        actual = metrics.get(field) if isinstance(metrics, Mapping) else None
        minimum = document_rule.get(contract_field, 0)
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0 or not isinstance(actual, int) or isinstance(actual, bool) or actual < minimum:
            errors.append(_issue("capture_state_witness_document_mismatch", "state witness document metrics do not satisfy the contract", issue_path))
            break
    results = witness.get("selectorResults")
    if not isinstance(results, list) or len(results) != len(normalized_rules):
        errors.append(_issue("capture_state_witness_selector_mismatch", "state witness selector results must exactly cover the contract", issue_path))
    else:
        for rule, result in zip(normalized_rules, results):
            count = result.get("count") if isinstance(result, Mapping) else None
            visible_count = result.get("visibleCount") if isinstance(result, Mapping) else None
            valid_counts = isinstance(count, int) and not isinstance(count, bool) and count >= 0 and isinstance(visible_count, int) and not isinstance(visible_count, bool) and visible_count >= 0
            expected_pass = valid_counts and count >= rule["minCount"] and visible_count >= rule["minVisibleCount"]
            if rule.get("maxCount") is not None and valid_counts:
                expected_pass = expected_pass and count <= rule["maxCount"]
            if rule.get("maxVisibleCount") is not None and valid_counts:
                expected_pass = expected_pass and visible_count <= rule["maxVisibleCount"]
            if not isinstance(result, Mapping) or result.get("selector") != rule["selector"] or result.get("invalidSelector") is True or result.get("pass") is not expected_pass or not expected_pass:
                errors.append(_issue("capture_state_witness_selector_mismatch", "state witness selector counts do not satisfy the contract", issue_path))
                break
    if witness.get("pass") is not True:
        errors.append(_issue("capture_state_witness_failed", "state witness must pass every declared assertion", issue_path))
    return observed_at


def _validate_capture_bundle_v2(
    manifest: Mapping[str, Any],
    root: Path,
    errors: List[Dict[str, Any]],
) -> None:
    bundle_ref = manifest.get("capture_bundle")
    if not isinstance(bundle_ref, Mapping):
        errors.append(
            _issue(
                "capture_bundle_missing",
                "capture_bundle_v2 enforcement requires capture_bundle path+sha256",
                "$.capture_bundle",
            )
        )
        return

    bundle_path = _validate_artifact_ref(bundle_ref, "$.capture_bundle", root, errors)
    if bundle_path is None or not bundle_path.is_file():
        return
    try:
        with bundle_path.open("r", encoding="utf-8") as source:
            bundle = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append(
            _issue(
                "capture_bundle_invalid",
                "capture bundle must be valid UTF-8 JSON",
                "$.capture_bundle.path",
            )
        )
        return
    if not isinstance(bundle, Mapping):
        errors.append(
            _issue(
                "capture_bundle_invalid",
                "capture bundle root must be an object",
                "$.capture_bundle.path",
            )
        )
        return
    if bundle.get("schemaVersion") != "web-capture-bundle/2.0":
        errors.append(
            _issue(
                "capture_bundle_schema_invalid",
                "capture bundle schemaVersion must equal web-capture-bundle/2.0",
                "$.capture_bundle.path",
            )
        )
    if manifest.get("fidelity") == "pixel" and bundle.get("contentPolicy") != "public-observable":
        errors.append(
            _issue(
                "capture_bundle_content_policy_insufficient",
                "pixel fidelity requires a public-observable capture bundle",
                "$.capture_bundle.path",
            )
        )
    reference_fingerprint = _normal_sha256(bundle.get("referenceFingerprint"))
    if reference_fingerprint is None or reference_fingerprint != _normal_sha256(manifest.get("reference_fingerprint")):
        errors.append(
            _issue(
                "capture_reference_fingerprint_mismatch",
                "capture bundle referenceFingerprint must match Manifest reference identity fingerprint",
                "$.capture_bundle.path",
            )
        )
    context = bundle.get("context")
    required_context = {
        "projectId": manifest.get("project_id"),
        "pageId": manifest.get("page_id"),
        "scenarioId": manifest.get("scenario_id"),
        "baselineId": manifest.get("baseline_id"),
    }
    if not isinstance(context, Mapping):
        errors.append(_issue("capture_bundle_context_missing", "capture bundle requires a context object", "$.capture_bundle.path"))
        context = {}
    else:
        for field, expected in required_context.items():
            if not isinstance(expected, str) or not expected or context.get(field) != expected:
                errors.append(_issue("capture_bundle_context_mismatch", "capture bundle %s must match Manifest" % field, "$.capture_bundle.path"))
        if context.get("side") != "reference":
            errors.append(_issue("capture_bundle_side_invalid", "builder capture bundle side must be reference", "$.capture_bundle.path"))
        viewport_ids = {
            entry.get("id") for entry in manifest.get("required_viewports", []) if isinstance(entry, Mapping)
        }
        state_ids = {
            entry.get("id") for entry in manifest.get("required_states", []) if isinstance(entry, Mapping)
        }
        if context.get("viewportId") not in viewport_ids:
            errors.append(_issue("capture_bundle_viewport_mismatch", "capture bundle viewportId must match required_viewports", "$.capture_bundle.path"))
        if context.get("stateId") not in state_ids:
            errors.append(_issue("capture_bundle_state_mismatch", "capture bundle stateId must match required_states", "$.capture_bundle.path"))

    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, Mapping):
        errors.append(
            _issue(
                "capture_bundle_artifacts_missing",
                "capture bundle requires an artifacts object",
                "$.capture_bundle.path",
            )
        )
        return

    inventory_ref = artifacts.get("inventory")
    manifest_inventory = manifest.get("probe_inventory")
    if not isinstance(inventory_ref, Mapping) or not isinstance(manifest_inventory, Mapping):
        errors.append(
            _issue(
                "capture_bundle_inventory_missing",
                "capture bundle requires artifacts.inventory path+sha256",
                "$.capture_bundle.path",
            )
        )
    else:
        bundle_inventory_hash = _normal_sha256(inventory_ref.get("sha256"))
        manifest_inventory_hash = _normal_sha256(manifest_inventory.get("sha256"))
        if (
            inventory_ref.get("path") != manifest_inventory.get("path")
            or bundle_inventory_hash is None
            or bundle_inventory_hash != manifest_inventory_hash
        ):
            errors.append(
                _issue(
                    "capture_bundle_inventory_mismatch",
                    "bundle artifacts.inventory must exactly match manifest probe_inventory",
                    "$.capture_bundle.path",
                )
            )

    validated_paths: Dict[str, Optional[Path]] = {}
    for field in ("inventory", "environment", "domSnapshot", "axTree", "fontUsage", "stateContract", "stateWitness", "stateWitnessPost", "screenshot"):
        artifact_path = "$.capture_bundle.artifacts.%s" % field
        artifact = artifacts.get(field)
        if not isinstance(artifact, Mapping):
            errors.append(
                _issue(
                    "capture_bundle_artifact_missing",
                    "capture bundle requires %s path+sha256" % field,
                    artifact_path,
                )
            )
            continue
        validated_paths[field] = _validate_artifact_ref(artifact, artifact_path, root, errors)

    environment = _load_json_artifact(validated_paths.get("environment"), "web-capture-environment/1.0", "$.capture_bundle.artifacts.environment.path", errors)
    dom_snapshot = _load_json_artifact(validated_paths.get("domSnapshot"), "web-dom-render-tree/1.0", "$.capture_bundle.artifacts.domSnapshot.path", errors)
    ax_tree = _load_json_artifact(validated_paths.get("axTree"), "web-ax-tree-public/1.0", "$.capture_bundle.artifacts.axTree.path", errors)
    font_usage = _load_json_artifact(validated_paths.get("fontUsage"), "web-platform-font-usage/1.0", "$.capture_bundle.artifacts.fontUsage.path", errors)
    state_contract = _load_json_artifact(validated_paths.get("stateContract"), "web-capture-state-contract/1.0", "$.capture_bundle.artifacts.stateContract.path", errors)
    state_witness = _load_json_artifact(validated_paths.get("stateWitness"), "web-capture-state-witness/1.0", "$.capture_bundle.artifacts.stateWitness.path", errors)
    state_witness_post = _load_json_artifact(validated_paths.get("stateWitnessPost"), "web-capture-state-witness/1.0", "$.capture_bundle.artifacts.stateWitnessPost.path", errors)
    if isinstance(state_contract, Mapping):
        contract_hash = _normal_sha256(bundle.get("stateContractSha256"))
        artifact_hash = _normal_sha256(artifacts.get("stateContract", {}).get("sha256")) if isinstance(artifacts.get("stateContract"), Mapping) else None
        if contract_hash is None or contract_hash != artifact_hash:
            errors.append(_issue("capture_state_contract_hash_mismatch", "capture bundle must bind the state contract hash", "$.capture_bundle.stateContractSha256"))
    witness_times: List[Optional[datetime]] = []
    for artifact_field, bundle_hash_field, phase, witness in (
        ("stateWitness", "stateWitnessSha256", "pre", state_witness),
        ("stateWitnessPost", "stateWitnessPostSha256", "post", state_witness_post),
    ):
        if isinstance(witness, Mapping):
            witness_hash = _normal_sha256(bundle.get(bundle_hash_field))
            artifact_hash = _normal_sha256(artifacts.get(artifact_field, {}).get("sha256")) if isinstance(artifacts.get(artifact_field), Mapping) else None
            if witness_hash is None or witness_hash != artifact_hash:
                errors.append(_issue("capture_state_witness_hash_mismatch", "capture bundle must bind both state witness hashes", "$.capture_bundle.%s" % bundle_hash_field))
            if isinstance(state_contract, Mapping):
                witness_times.append(_validate_state_witness_against_contract(state_contract, witness, phase, "$.capture_bundle.artifacts.%s.path" % artifact_field, errors))
    if isinstance(artifacts.get("stateWitness"), Mapping) and isinstance(artifacts.get("stateWitnessPost"), Mapping) and artifacts["stateWitness"].get("path") == artifacts["stateWitnessPost"].get("path"):
        errors.append(_issue("capture_state_witness_not_independent", "pre and post state witnesses must use different immutable artifacts", "$.capture_bundle.artifacts.stateWitnessPost.path"))
    try:
        captured_at = datetime.fromisoformat(str(bundle.get("capturedAt")).replace("Z", "+00:00"))
        if captured_at.tzinfo is None:
            raise ValueError
    except ValueError:
        captured_at = None
        errors.append(_issue("capture_time_invalid", "capture bundle requires a timezone-aware capturedAt", "$.capture_bundle.capturedAt"))
    if len(witness_times) == 2 and all(value is not None for value in witness_times) and captured_at is not None and not (witness_times[0] <= witness_times[1] <= captured_at):
        errors.append(_issue("capture_state_witness_order_invalid", "pre/post state witness times must bracket capture work", "$.capture_bundle.artifacts.stateWitnessPost.path"))
    if isinstance(font_usage, Mapping):
        scope = manifest.get("scope")
        root_locator = scope.get("root_locator") if isinstance(scope, Mapping) else None
        scope_roots = font_usage.get("scopeRoots")
        if not isinstance(scope_roots, list) or not all(isinstance(value, str) and value for value in scope_roots) or (root_locator not in scope_roots and "*" not in scope_roots):
            errors.append(_issue("capture_font_scope_mismatch", "font usage must bind the current component root", "$.capture_bundle.artifacts.fontUsage.path"))
        if font_usage.get("scanTruncated") is not False or font_usage.get("failedNodeCount") != 0 or font_usage.get("unmappedNodeCount") != 0 or font_usage.get("budgetExhausted") is not False or font_usage.get("timedOutNodeCount") != 0 or font_usage.get("scopeMissing") is not False:
            errors.append(_issue("capture_font_usage_incomplete", "font usage must be complete, scoped and within budget", "$.capture_bundle.artifacts.fontUsage.path"))
    if bundle.get("captureMode") == "read-only-supported-browser-tab":
        receipt_ref = artifacts.get("sourceReceipt")
        receipt_path = _validate_artifact_ref(receipt_ref, "$.capture_bundle.artifacts.sourceReceipt", root, errors) if isinstance(receipt_ref, Mapping) else None
        if receipt_path is None:
            errors.append(_issue("capture_source_receipt_missing", "supported-browser capture requires a host-issued source receipt", "$.capture_bundle.artifacts.sourceReceipt"))
        else:
            receipt = _load_json_artifact(receipt_path, "web-capture-source-receipt/1.0", "$.capture_bundle.artifacts.sourceReceipt.path", errors)
            receipt_hash = _normal_sha256(bundle.get("sourceReceiptSha256"))
            artifact_hash = _normal_sha256(receipt_ref.get("sha256"))
            if receipt_hash is None or receipt_hash != artifact_hash:
                errors.append(_issue("capture_source_receipt_hash_mismatch", "capture bundle must bind the source receipt hash", "$.capture_bundle.sourceReceiptSha256"))
            if isinstance(receipt, Mapping):
                expected_context_fingerprint = hashlib.sha256(
                    json.dumps(dict(context), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                if receipt.get("contextFingerprint") != expected_context_fingerprint:
                    errors.append(_issue("capture_source_receipt_context_mismatch", "source receipt must bind the capture context", "$.capture_bundle.artifacts.sourceReceipt.path"))
                if not isinstance(state_contract, Mapping) or receipt.get("expectedPublicLocation") != state_contract.get("expectedPublicLocation"):
                    errors.append(_issue("capture_source_receipt_location_mismatch", "source receipt must bind the state contract public location", "$.capture_bundle.artifacts.sourceReceipt.path"))
                for field in ("receiptId", "adapter"):
                    if not isinstance(receipt.get(field), str) or not receipt.get(field) or len(receipt[field]) > 200:
                        errors.append(_issue("capture_source_receipt_invalid", "source receipt identifiers are invalid", "$.capture_bundle.artifacts.sourceReceipt.path"))
                for field in ("sessionAliasHash", "tabIdentityHash", "preStateWitnessSha256", "postStateWitnessSha256"):
                    if _normal_sha256(receipt.get(field)) is None:
                        errors.append(_issue("capture_source_receipt_invalid", "source receipt hashes are invalid", "$.capture_bundle.artifacts.sourceReceipt.path"))
                if _normal_sha256(receipt.get("preStateWitnessSha256")) != _normal_sha256(bundle.get("stateWitnessSha256")) or _normal_sha256(receipt.get("postStateWitnessSha256")) != _normal_sha256(bundle.get("stateWitnessPostSha256")):
                    errors.append(_issue("capture_source_receipt_witness_mismatch", "source receipt must bind both state witnesses", "$.capture_bundle.artifacts.sourceReceipt.path"))
                try:
                    issued_at = datetime.fromisoformat(str(receipt.get("issuedAt")).replace("Z", "+00:00"))
                    expires_at = datetime.fromisoformat(str(receipt.get("expiresAt")).replace("Z", "+00:00"))
                    captured_at = datetime.fromisoformat(str(bundle.get("capturedAt")).replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    issued_at = expires_at = captured_at = None
                if issued_at is not None and (issued_at.tzinfo is None or expires_at.tzinfo is None or captured_at.tzinfo is None):
                    issued_at = expires_at = captured_at = None
                if issued_at is None or expires_at is None or captured_at is None or expires_at - issued_at > timedelta(hours=1) or not (issued_at <= captured_at <= expires_at):
                    errors.append(_issue("capture_source_receipt_time_invalid", "source receipt must be valid when the bundle is captured", "$.capture_bundle.artifacts.sourceReceipt.path"))
    _png_dimensions(validated_paths.get("screenshot"), "$.capture_bundle.artifacts.screenshot.path", errors)
    if isinstance(environment, Mapping):
        probe_viewport = environment.get("probeViewport")
        bundle_viewport = bundle.get("viewport")
        if not isinstance(probe_viewport, Mapping) or not isinstance(bundle_viewport, Mapping):
            errors.append(_issue("capture_environment_viewport_missing", "capture environment and bundle require viewport measurements", "$.capture_bundle.artifacts.environment.path"))
        else:
            for field in ("innerWidth", "innerHeight", "devicePixelRatio"):
                if probe_viewport.get(field) != bundle_viewport.get(field):
                    errors.append(_issue("capture_environment_viewport_mismatch", "capture viewport measurements must agree", "$.capture_bundle.artifacts.environment.path"))
        if environment.get("navigationFingerprint") != bundle.get("navigationFingerprint"):
            errors.append(_issue("capture_navigation_fingerprint_mismatch", "capture environment navigation fingerprint must match bundle", "$.capture_bundle.artifacts.environment.path"))
        if environment.get("referenceFingerprint") != bundle.get("referenceFingerprint"):
            errors.append(_issue("capture_reference_fingerprint_mismatch", "capture environment reference fingerprint must match bundle", "$.capture_bundle.artifacts.environment.path"))
    if isinstance(dom_snapshot, Mapping) and dom_snapshot.get("normalizedObservableValuesPersisted") is not True:
        errors.append(_issue("capture_dom_values_missing", "pixel capture requires normalized observable DOM values", "$.capture_bundle.artifacts.domSnapshot.path"))
    if isinstance(ax_tree, Mapping) and ax_tree.get("normalizedObservableValuesPersisted") is not True:
        errors.append(_issue("capture_ax_values_missing", "pixel capture requires normalized observable AX values", "$.capture_bundle.artifacts.axTree.path"))


def _validate_strong_bundle(
    manifest: Mapping[str, Any],
    root: Path,
    errors: List[Dict[str, Any]],
    stage: str = "qa",
) -> None:
    inventory_path = _validate_artifact_ref(
        manifest.get("probe_inventory"),
        "$.probe_inventory",
        root,
        errors,
    )
    inventory: Optional[Mapping[str, Any]] = None
    if inventory_path is not None and inventory_path.is_file():
        try:
            with inventory_path.open("r", encoding="utf-8") as source:
                loaded_inventory = json.load(source)
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(
                _issue(
                    "probe_inventory_invalid",
                    "probe inventory must be valid UTF-8 JSON",
                    "$.probe_inventory.path",
                )
            )
        else:
            if not isinstance(loaded_inventory, Mapping):
                errors.append(
                    _issue(
                        "probe_inventory_invalid",
                        "probe inventory root must be an object",
                        "$.probe_inventory.path",
                    )
                )
            else:
                inventory = loaded_inventory

    if inventory is not None:
        if inventory.get("schemaVersion") != "web-asset-inventory/1.0":
            errors.append(
                _issue(
                    "probe_inventory_schema_invalid",
                    "probe inventory schemaVersion must equal web-asset-inventory/1.0",
                    "$.probe_inventory.path",
                )
            )
        dom = inventory.get("dom")
        scan_truncated = inventory.get("scanTruncated")
        if scan_truncated is None and isinstance(dom, Mapping):
            scan_truncated = dom.get("scanTruncated")
        if scan_truncated is not False:
            errors.append(
                _issue(
                    "probe_inventory_truncated",
                    "probe inventory must explicitly report scanTruncated=false",
                    "$.probe_inventory.path",
                )
            )

        derived_occurrences = _derive_inventory_occurrence_ids(inventory)
        manifest_occurrences = _manifest_occurrence_ids(manifest["assets"], errors)
        missing_occurrences = sorted(derived_occurrences - manifest_occurrences)
        unknown_occurrences = sorted(manifest_occurrences - derived_occurrences)
        if missing_occurrences:
            errors.append(
                _issue(
                    "asset_occurrence_coverage_incomplete",
                    "manifest occurrences do not cover inventory ids: %s"
                    % ", ".join(missing_occurrences[:20]),
                    "$.assets",
                )
            )
        if unknown_occurrences:
            errors.append(
                _issue(
                    "asset_occurrence_unknown",
                    "manifest occurrences are absent from inventory: %s"
                    % ", ".join(unknown_occurrences[:20]),
                    "$.assets",
                )
            )
        fonts = inventory.get("fonts")
        font_faces = fonts.get("faces") if isinstance(fonts, Mapping) else None
        if isinstance(font_faces, list) and font_faces:
            metadata = manifest.get("metadata")
            global_fonts = metadata.get("global_fonts") if isinstance(metadata, Mapping) else None
            resolved = bool(
                isinstance(global_fonts, Mapping)
                and global_fonts.get("status") == "RESOLVED"
                and isinstance(global_fonts.get("evidence"), list)
                and global_fonts.get("evidence")
            )
            rights_blocked = False
            if isinstance(global_fonts, Mapping) and stage == "builder":
                exclusion = global_fonts.get("scope_exclusion")
                rights_blocked = bool(
                    global_fonts.get("status") == "BLOCKED_RIGHTS"
                    and global_fonts.get("rights") in {"reference_only", "unknown"}
                    and isinstance(global_fonts.get("evidence"), list)
                    and global_fonts.get("evidence")
                    and isinstance(exclusion, Mapping)
                    and exclusion.get("reason") == "blocked_rights"
                    and isinstance(exclusion.get("evidence_ids"), list)
                    and exclusion.get("evidence_ids")
                )
            if not resolved and not rights_blocked:
                errors.append(
                    _issue(
                        "global_font_resolution_required",
                        "discovered font faces require resolved evidence; builder-only rights exclusions must be explicit and remain outside pixel claims",
                        "$.metadata.global_fonts",
                    )
                )
            elif isinstance(global_fonts, Mapping):
                for evidence_index, evidence in enumerate(global_fonts.get("evidence", [])):
                    _validate_artifact_ref(
                        evidence,
                        "$.metadata.global_fonts.evidence[%d]" % evidence_index,
                        root,
                        errors,
                    )

    _validate_component_spec(manifest, root, errors)
    if stage == "qa":
        _validate_strong_critical_diffs(manifest, root, errors)
    if manifest.get("enforcement_mode") == "capture_bundle_v2":
        _validate_capture_bundle_v2(manifest, root, errors)


def _viewport_class(entry: Any) -> Optional[str]:
    texts: List[str] = []
    width: Optional[int] = None
    if isinstance(entry, str):
        texts.append(entry)
        match = re.search(r"(?<!\d)(\d{3,4})\s*[x×]\s*\d{3,4}(?!\d)", entry)
        if match:
            width = int(match.group(1))
    elif isinstance(entry, Mapping):
        for field in ("id", "name", "kind", "class", "device_class", "platform", "viewport"):
            if isinstance(entry.get(field), str):
                texts.append(entry[field])
        candidate_width = entry.get("width")
        if isinstance(candidate_width, int) and not isinstance(candidate_width, bool):
            width = candidate_width
    joined = " ".join(texts).lower()
    if re.search(r"\b(mobile|phone|smartphone|android|ios|iphone)\b", joined):
        return "mobile"
    if re.search(r"\b(desktop|laptop|wide|web)\b", joined):
        return "desktop"
    if width is not None:
        if width <= 768:
            return "mobile"
        if width >= 1024:
            return "desktop"
    return None


def _validate_page_requirements(
    manifest: Mapping[str, Any],
    errors: List[Dict[str, Any]],
    root: Optional[Path] = None,
    strong_mode: bool = False,
    stage: str = "qa",
) -> None:
    if strong_mode:
        assert root is not None
        viewports = _validate_strong_required_collection(
            manifest,
            "required_viewports",
            root,
            errors,
        )
    else:
        viewports = _validate_required_collection(
            manifest,
            "required_viewports",
            ("covered_viewports", "captured_viewports", "tested_viewports", "verified_viewports"),
            errors,
        )
    classes = {_viewport_class(entry) for entry in viewports}
    scope = manifest.get("scope")
    scope_kind = scope.get("kind") if isinstance(scope, Mapping) else None
    require_dual_viewport = stage == "qa" and scope_kind != "component"
    if require_dual_viewport and viewports and "desktop" not in classes:
        errors.append(
            _issue(
                "required_desktop_viewport_missing",
                "required_viewports must include a desktop viewport",
                "$.required_viewports",
            )
        )
    if require_dual_viewport and viewports and "mobile" not in classes:
        errors.append(
            _issue(
                "required_mobile_viewport_missing",
                "required_viewports must include a mobile viewport",
                "$.required_viewports",
            )
        )

    if strong_mode:
        _validate_strong_required_collection(
            manifest,
            "required_states",
            root,
            errors,
        )
    else:
        _validate_required_collection(
            manifest,
            "required_states",
            ("covered_states", "captured_states", "tested_states", "verified_states"),
            errors,
        )

    if stage == "builder":
        return

    fallback = manifest.get("font_fallback")
    if fallback is None:
        errors.append(
            _issue(
                "font_fallback_missing",
                "font_fallback must record an explicit check and pass result",
                "$.font_fallback",
            )
        )
    elif isinstance(fallback, bool):
        if fallback is not True:
            errors.append(
                _issue("font_fallback_failed", "font fallback validation did not pass", "$.font_fallback")
            )
    elif isinstance(fallback, Mapping):
        checked_fields = [field for field in ("checked", "tested", "verified") if field in fallback]
        if not checked_fields or not any(fallback[field] is True for field in checked_fields):
            errors.append(
                _issue(
                    "font_fallback_unchecked",
                    "font_fallback must be checked, tested, or verified",
                    "$.font_fallback",
                )
            )
        if fallback.get("pass") is not True:
            errors.append(
                _issue(
                    "font_fallback_failed",
                    "font_fallback.pass must be true",
                    "$.font_fallback.pass",
                )
            )
        if fallback.get("used") is True or fallback.get("fallback_used") is True:
            errors.append(
                _issue(
                    "unexpected_font_fallback",
                    "unexpected font fallback was used",
                    "$.font_fallback",
                )
            )
        unexpected = fallback.get("unexpected_fallbacks")
        if isinstance(unexpected, list) and unexpected:
            errors.append(
                _issue(
                    "unexpected_font_fallback",
                    "unexpected_fallbacks must be empty",
                    "$.font_fallback.unexpected_fallbacks",
                )
            )
    else:
        errors.append(
            _issue("font_fallback_invalid", "font_fallback must be a boolean or object", "$.font_fallback")
        )

    if "critical_diffs" in manifest:
        critical_diffs = manifest.get("critical_diffs")
        if not isinstance(critical_diffs, list) or not critical_diffs:
            errors.append(
                _issue(
                    "critical_diffs_missing",
                    "critical_diffs must be a non-empty array",
                    "$.critical_diffs",
                )
            )
        else:
            for index, diff in enumerate(critical_diffs):
                path = "$.critical_diffs[%d]" % index
                if not isinstance(diff, Mapping):
                    errors.append(_issue("critical_diff_invalid", "critical diff must be an object", path))
                    continue
                diff_id = diff.get("id", diff.get("component_id"))
                if not isinstance(diff_id, str) or not diff_id.strip():
                    errors.append(
                        _issue(
                            "critical_diff_id_missing",
                            "critical diff id or component_id is required",
                            path,
                        )
                    )
                if diff.get("pass") is not True:
                    errors.append(
                        _issue(
                            "critical_diff_failed",
                            "every critical diff must explicitly pass",
                            path + ".pass",
                        )
                    )
    elif "critical_diff" in manifest:
        critical_diff = manifest.get("critical_diff")
        if not isinstance(critical_diff, Mapping) or critical_diff.get("pass") is not True:
            errors.append(
                _issue(
                    "critical_diff_failed",
                    "critical_diff.pass must be true",
                    "$.critical_diff.pass",
                )
            )
    elif manifest.get("critical_diff_pass") is not True:
        errors.append(
            _issue(
                "critical_diffs_missing",
                "critical_diffs with explicit pass fields are required",
                "$.critical_diffs",
            )
        )


def _validate_deviation(
    asset: Mapping[str, Any],
    path: str,
    asset_id: str,
    provenance: Any,
) -> List[Dict[str, Any]]:
    deviation = asset.get("accepted_deviation")
    if deviation is None:
        deviation = asset
        prefix = path
    elif isinstance(deviation, Mapping):
        prefix = path + ".accepted_deviation"
    else:
        return [
            _issue(
                "accepted_deviation_invalid",
                "accepted_deviation must be an object",
                path + ".accepted_deviation",
                asset_id,
            )
        ]

    errors: List[Dict[str, Any]] = []
    for field in ("deviation_id", "approved_by", "reason", "decision"):
        value = deviation.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(
                _issue(
                    "accepted_deviation_incomplete",
                    "%s is required for an accepted deviation" % field,
                    prefix + "." + field,
                    asset_id,
                )
            )
    decision = deviation.get("decision")
    if isinstance(decision, str) and decision.strip() and decision != provenance:
        errors.append(
            _issue(
                "accepted_deviation_decision_mismatch",
                "accepted deviation decision must exactly match provenance",
                prefix + ".decision",
                asset_id,
            )
        )
    return errors


def _validate_asset(
    asset: Mapping[str, Any],
    index: int,
    root: Path,
    hash_occurrences: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    path = "$.assets[%d]" % index
    asset_id = _asset_identifier(asset)
    assert asset_id is not None  # guaranteed by _asset_shape_errors
    errors: List[Dict[str, Any]] = []

    errors.extend(_source_ref_issues(asset.get("source_ref"), path + ".source_ref", asset_id))
    if asset.get("private_remote_hotlink") is True or asset.get("remote_hotlink") is True:
        errors.append(
            _issue(
                "private_remote_hotlink",
                "runtime remote hotlinks are not allowed for captured private assets",
                path,
                asset_id,
            )
        )

    # Excluded or non-visible inventory entries do not block fidelity.  Their
    # source_ref is still checked above so a manifest cannot retain credentials.
    if asset.get("visible", True) is True and asset.get("in_scope", True) is not True:
        exclusion = asset.get("scope_exclusion")
        if not isinstance(exclusion, Mapping) or exclusion.get("reason") not in SCOPE_EXCLUSION_REASONS:
            errors.append(
                _issue(
                    "scope_exclusion_missing",
                    "visible out-of-scope assets require a structured scope_exclusion reason",
                    path + ".scope_exclusion",
                    asset_id,
                )
            )
        elif not isinstance(exclusion.get("evidence_ids"), list) or not exclusion.get("evidence_ids"):
            errors.append(
                _issue(
                    "scope_exclusion_evidence_missing",
                    "scope_exclusion requires evidence_ids",
                    path + ".scope_exclusion.evidence_ids",
                    asset_id,
                )
            )
        return errors
    if asset.get("visible", True) is not True:
        return errors

    for field in PROVENANCE_FIELDS:
        marker = _normal_token(asset.get(field))
        if marker in FORBIDDEN_PROVENANCE:
            errors.append(
                _issue(
                    "forbidden_asset_provenance",
                    "%s assets cannot satisfy fidelity" % marker,
                    path + "." + field,
                    asset_id,
                )
            )

    rights = asset.get("rights")
    if rights not in ALLOWED_RIGHTS:
        errors.append(
            _issue(
                "rights_unapproved",
                "rights must be user_owned, licensed, or explicit_authorized",
                path + ".rights",
                asset_id,
            )
        )

    resolution = asset.get("resolution")
    provenance = asset.get("provenance")
    if not isinstance(provenance, str) or not provenance.strip():
        errors.append(
            _issue(
                "provenance_missing",
                "visible in-scope assets require a non-empty provenance",
                path + ".provenance",
                asset_id,
            )
        )
    if resolution not in ALLOWED_RESOLUTIONS:
        errors.append(
            _issue(
                "resolution_unapproved",
                "resolution must be exact or an accepted deviation",
                path + ".resolution",
                asset_id,
            )
        )
    elif resolution in EXACT_RESOLUTIONS:
        if provenance not in EXACT_PROVENANCE_BY_RESOLUTION[resolution]:
            errors.append(
                _issue(
                    "provenance_resolution_mismatch",
                    "exact resolution requires its matching exact provenance",
                    path + ".provenance",
                    asset_id,
                )
            )
    elif resolution == "accepted_deviation":
        if provenance not in DEVIATION_PROVENANCE:
            errors.append(
                _issue(
                    "accepted_deviation_provenance_invalid",
                    "accepted deviations require an approved non-approximate provenance",
                    path + ".provenance",
                    asset_id,
                )
            )
        errors.extend(_validate_deviation(asset, path, asset_id, provenance))

    evidence_ids = asset.get("evidence_ids")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or any(not isinstance(item, str) or not item.strip() for item in evidence_ids)
    ):
        errors.append(
            _issue(
                "evidence_ids_missing",
                "evidence_ids must be a non-empty array of strings",
                path + ".evidence_ids",
                asset_id,
            )
        )

    declared_types = [
        _normal_token(asset[field])
        for field in ("type", "asset_type", "kind")
        if field in asset and _normal_token(asset[field]) is not None
    ]
    if len(set(declared_types)) > 1:
        errors.append(
            _issue(
                "asset_type_conflict",
                "type, asset_type, and kind cannot disagree",
                path,
                asset_id,
            )
        )
    effective_type = declared_types[0] if declared_types else None
    if effective_type is None:
        errors.append(_issue("asset_type_missing", "asset type is required", path + ".type", asset_id))

    omission_without_file = (
        resolution == "accepted_deviation"
        and provenance == "approved_omission"
        and not any(asset.get(field) not in (None, "") for field in ("local_path", "sha256"))
    )
    if effective_type in FILE_ASSET_TYPES and not omission_without_file:
        local_path, path_problem = _safe_project_path(asset.get("local_path"), root)
        if path_problem is not None:
            errors.append(
                _issue(
                    "local_path_invalid",
                    "local_path %s" % path_problem,
                    path + ".local_path",
                    asset_id,
                )
            )
        elif local_path is None or not local_path.is_file():
            errors.append(
                _issue(
                    "asset_file_missing",
                    "local asset file does not exist",
                    path + ".local_path",
                    asset_id,
                )
            )
        else:
            expected_hash = _normal_sha256(asset.get("sha256"))
            if expected_hash is None:
                errors.append(
                    _issue(
                        "sha256_invalid",
                        "sha256 must be a 64-character hexadecimal digest",
                        path + ".sha256",
                        asset_id,
                    )
                )
            try:
                actual_hash = _sha256_file(local_path)
            except OSError:
                errors.append(
                    _issue(
                        "asset_file_unreadable",
                        "local asset file could not be read",
                        path + ".local_path",
                        asset_id,
                    )
                )
            else:
                hash_occurrences.setdefault(actual_hash, []).append(asset_id)
                if expected_hash is not None and actual_hash != expected_hash:
                    errors.append(
                        _issue(
                            "sha256_mismatch",
                            "local asset content does not match sha256",
                            path + ".sha256",
                            asset_id,
                        )
                    )

    if resolution == "exact_reconstructed":
        spec_path, path_problem = _safe_project_path(asset.get("spec_path"), root)
        if path_problem is not None:
            errors.append(
                _issue(
                    "spec_path_invalid",
                    "spec_path %s" % path_problem,
                    path + ".spec_path",
                    asset_id,
                )
            )
        elif spec_path is None or not spec_path.is_file():
            errors.append(
                _issue(
                    "reconstruction_spec_missing",
                    "exact_reconstructed assets require an existing spec_path",
                    path + ".spec_path",
                    asset_id,
                )
            )

    if effective_type == "font":
        if asset.get("fallback_used") is True:
            errors.append(
                _issue(
                    "unexpected_font_fallback",
                    "font asset reports fallback_used=true",
                    path + ".fallback_used",
                    asset_id,
                )
            )
        if "fallback_pass" in asset and asset.get("fallback_pass") is not True:
            errors.append(
                _issue(
                    "font_fallback_failed",
                    "font asset fallback_pass must be true",
                    path + ".fallback_pass",
                    asset_id,
                )
            )
    return errors


def evaluate_manifest(
    manifest: Mapping[str, Any],
    project_root: Path,
    manifest_path: Optional[Path] = None,
    stage: str = "qa",
) -> Dict[str, Any]:
    """Evaluate a previously shape-checked manifest and return its JSON report."""

    assets = manifest["assets"]
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    hash_occurrences: Dict[str, List[str]] = {}

    strong_mode = _strong_mode(manifest)
    scope = manifest.get("scope")
    scope_id = None
    if isinstance(scope, Mapping):
        scope_id = scope.get("scope_id", scope.get("id"))
    if not isinstance(scope_id, str) or not scope_id.strip():
        scope_id = manifest.get("scope_id")
    if stage == "builder" and strong_mode and (not isinstance(scope_id, str) or not scope_id.strip()):
        errors.append(
            _issue(
                "builder_scope_missing",
                "builder-stage strong Gate requires an explicit component or page scope_id",
                "$.scope",
            )
        )
    if stage == "builder" and not strong_mode:
        errors.append(
            _issue(
                "builder_strong_mode_required",
                "builder-stage Gate requires fidelity=pixel or enforcement_mode=capture_bundle_v2",
                "$.enforcement_mode",
            )
        )
    if stage not in GATE_STAGES:
        raise ValueError("unsupported gate stage")
    _validate_page_requirements(manifest, errors, project_root, strong_mode, stage)
    if strong_mode:
        _validate_strong_bundle(manifest, project_root, errors, stage)
    checked = 0
    skipped = 0
    for index, asset in enumerate(assets):
        if asset.get("in_scope", True) is True and asset.get("visible", True) is True:
            checked += 1
        else:
            skipped += 1
        errors.extend(_validate_asset(asset, index, project_root, hash_occurrences))

    discovered_asset_candidates = _declared_discovery_count(manifest)
    if discovered_asset_candidates > 0 and not assets:
        errors.append(
            _issue(
                "asset_manifest_empty_after_discovery",
                "reference evidence reports visible asset candidates but assets is empty",
                "$.assets",
            )
        )

    duplicate_hashes: List[Dict[str, Any]] = []
    for digest, asset_ids in sorted(hash_occurrences.items()):
        if len(asset_ids) > 1:
            duplicate_hashes.append(
                {
                    "sha256": digest,
                    "asset_ids": asset_ids,
                }
            )

    report = _report_shell(
        "fail" if errors else "pass",
        manifest_path,
        project_root,
        manifest.get("schema_version"),
        stage,
    )
    report["errors"] = errors
    report["warnings"] = warnings
    report["duplicate_hashes"] = duplicate_hashes
    metadata = manifest.get("metadata")
    global_fonts = metadata.get("global_fonts") if isinstance(metadata, Mapping) else None
    font_scope_blocked = bool(
        isinstance(global_fonts, Mapping) and global_fonts.get("status") == "BLOCKED_RIGHTS"
    )
    report["summary"] = {
        "assets_total": len(assets),
        "assets_checked": checked,
        "assets_skipped": skipped,
        "font_scope_blocked": font_scope_blocked,
        "errors": len(errors),
        "warnings": len(warnings),
        "duplicate_hash_groups": len(duplicate_hashes),
        "discovered_asset_candidates": discovered_asset_candidates,
    }
    report["strong_mode"] = strong_mode
    report["enforcement_mode"] = manifest.get("enforcement_mode")
    report["equivalence_scope"] = (
        "declared_scope"
        if skipped == 0 and not font_scope_blocked
        else "partial_excludes_visible_assets"
    )
    report["scope_id"] = scope_id.strip() if isinstance(scope_id, str) and scope_id.strip() else None
    report["scope_kind"] = scope.get("kind") if isinstance(scope, Mapping) else None
    for identity_field in ("project_id", "page_id", "scenario_id", "baseline_id"):
        report[identity_field] = manifest.get(identity_field)
    report["reference_fingerprint"] = manifest.get("reference_fingerprint")
    component_specs = manifest.get("component_specs")
    report["component_specs"] = dict(component_specs) if isinstance(component_specs, Mapping) else None
    if manifest_path is not None and manifest_path.is_file():
        try:
            report["manifest_sha256"] = _sha256_file(manifest_path)
            report["manifest_relative_path"] = manifest_path.resolve(strict=True).relative_to(
                project_root.resolve(strict=True)
            ).as_posix()
        except OSError:
            pass
        except ValueError:
            report["manifest_relative_path"] = None
    return report


def _load_and_shape_check(manifest_path: Path) -> Mapping[str, Any]:
    try:
        with manifest_path.open("r", encoding="utf-8") as source:
            manifest = json.load(source)
    except FileNotFoundError as exc:
        raise ManifestInputError("manifest_not_found", "manifest file does not exist") from exc
    except (OSError, UnicodeError) as exc:
        raise ManifestInputError("manifest_unreadable", "manifest file could not be read as UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ManifestInputError(
            "invalid_json",
            "manifest is not valid JSON (line %d, column %d)" % (exc.lineno, exc.colno),
        ) from exc

    if not isinstance(manifest, Mapping):
        raise ManifestInputError("manifest_invalid", "manifest root must be an object")
    schema_version = manifest.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
        raise ManifestInputError(
            "schema_version_invalid",
            "schema_version must equal 1",
            "$.schema_version",
        )
    assets = manifest.get("assets")
    if not isinstance(assets, list):
        raise ManifestInputError("assets_invalid", "assets must be an array", "$.assets")
    shape_errors = _asset_shape_errors(assets)
    if shape_errors:
        first = shape_errors[0]
        raise ManifestInputError(first["code"], first["message"], first["path"])
    return manifest


def run_gate(
    manifest_path: Path,
    project_root: Path,
    stage: str = "qa",
) -> Tuple[Dict[str, Any], int]:
    """Load, validate, and evaluate a manifest using the CLI exit contract."""

    try:
        root = project_root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        report = _report_shell("invalid_manifest", manifest_path, project_root, stage=stage)
        report["errors"] = [
            _issue("project_root_invalid", "project-root must be an existing directory", "$.project_root")
        ]
        report["summary"]["errors"] = 1
        return report, EXIT_INVALID_MANIFEST
    if not root.is_dir():
        report = _report_shell("invalid_manifest", manifest_path, root, stage=stage)
        report["errors"] = [
            _issue("project_root_invalid", "project-root must be an existing directory", "$.project_root")
        ]
        report["summary"]["errors"] = 1
        return report, EXIT_INVALID_MANIFEST

    manifest_digest: Optional[str] = None
    try:
        normalized_manifest_path = manifest_path.expanduser().resolve(strict=False)
        if normalized_manifest_path.is_file():
            manifest_digest = _sha256_file(normalized_manifest_path)
        manifest = _load_and_shape_check(normalized_manifest_path)
    except (OSError, ManifestInputError) as exc:
        if isinstance(exc, OSError):
            exc = ManifestInputError("manifest_unreadable", "manifest file could not be hashed")
        report = _report_shell("invalid_manifest", manifest_path, root, stage=stage)
        report["errors"] = [_issue(exc.code, exc.message, exc.path)]
        report["summary"]["errors"] = 1
        report["manifest_sha256"] = manifest_digest
        return report, EXIT_INVALID_MANIFEST

    report = evaluate_manifest(manifest, root, normalized_manifest_path, stage)
    report["manifest_sha256"] = manifest_digest
    return report, EXIT_PASS if report["ok"] else EXIT_GATE_FAILED


def _write_report_json(
    report: Mapping[str, Any],
    output_path: Path,
    project_root: Path,
    manifest_path: Path,
) -> None:
    try:
        root = project_root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ManifestInputError(
            "output_path_invalid",
            "--output requires a valid project-root",
            "$.output",
        ) from exc

    resolved, path_problem = _safe_project_path(str(output_path), root)
    if path_problem is not None or resolved is None:
        raise ManifestInputError(
            "output_path_invalid",
            "output path must stay inside project-root",
            "$.output",
        )
    try:
        normalized_manifest = manifest_path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        normalized_manifest = manifest_path
    if resolved == normalized_manifest:
        raise ManifestInputError(
            "output_path_invalid",
            "output path cannot overwrite the input manifest",
            "$.output",
        )
    if resolved.exists() and not resolved.is_file():
        raise ManifestInputError(
            "output_path_invalid",
            "output path must be a file",
            "$.output",
        )

    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".web-fidelity-gate-",
            suffix=".tmp",
            dir=str(resolved.parent),
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                json.dump(report, output, ensure_ascii=False, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(str(temporary_path), str(resolved))
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
    except OSError as exc:
        raise ManifestInputError(
            "output_write_failed",
            "output report could not be written atomically",
            "$.output",
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(description="Validate exact Web asset fidelity from a JSON manifest")
    parser.add_argument("--manifest", required=True, type=Path, help="schema-version-1 JSON manifest")
    parser.add_argument("--project-root", required=True, type=Path, help="root containing all local assets")
    parser.add_argument("--output", type=Path, help="optional JSON report path inside project-root")
    parser.add_argument(
        "--stage",
        choices=sorted(GATE_STAGES),
        default="qa",
        help="builder validates reference/spec inputs; qa additionally requires replica/diff/font evidence",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        arguments = build_parser().parse_args(argv)
        report, exit_code = run_gate(arguments.manifest, arguments.project_root, arguments.stage)
        if arguments.output is not None:
            _write_report_json(
                report,
                arguments.output,
                arguments.project_root,
                arguments.manifest,
            )
    except ManifestInputError as exc:
        report = _report_shell("invalid_manifest", None, None, stage="qa")
        report["errors"] = [_issue(exc.code, exc.message, exc.path)]
        report["summary"]["errors"] = 1
        exit_code = EXIT_INVALID_MANIFEST
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
