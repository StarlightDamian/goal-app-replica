#!/usr/bin/env python3
"""Compare actual platform-font usage captured through CDP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


EXIT_PASS = 0
EXIT_DIFF = 2
EXIT_INVALID = 3
SCHEMA = "web-platform-font-usage/1.0"


class FontDiffInputError(Exception):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path(raw: str, root: Path, *, must_exist: bool = False) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.expanduser().resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise FontDiffInputError("path escapes project root: %s" % raw) from exc
    if must_exist and not resolved.is_file():
        raise FontDiffInputError("file does not exist: %s" % raw)
    return resolved


def _relative(path: Path, root: Path) -> str:
    return path.resolve(strict=False).relative_to(root).as_posix()


def _load(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FontDiffInputError("font usage must be readable UTF-8 JSON") from exc
    if not isinstance(value, Mapping) or value.get("schemaVersion") != SCHEMA:
        raise FontDiffInputError("font usage schemaVersion is invalid")
    if (
        value.get("scanTruncated") is not False
        or value.get("failedNodeCount") != 0
        or value.get("unmappedNodeCount") != 0
    ):
        raise FontDiffInputError("font usage is incomplete or contains failed nodes")
    records = value.get("records")
    families = value.get("families")
    expected_locators = value.get("expectedLocators")
    expected_records = value.get("expectedRecords")
    pseudo_declarations = value.get("pseudoDeclarations")
    if (
        not isinstance(records, list)
        or not isinstance(families, list)
        or not isinstance(expected_locators, list)
        or not isinstance(expected_records, list)
        or not isinstance(pseudo_declarations, list)
    ):
        raise FontDiffInputError("font usage records, expectedRecords, families and pseudoDeclarations must be arrays")
    if value.get("queriedNodeCount") != len(records):
        raise FontDiffInputError("font usage queriedNodeCount does not match records")
    record_keys = {
        (record.get("locator"), record.get("pseudo")) for record in records if isinstance(record, Mapping)
    }
    expected_keys = set()
    for expected in expected_records:
        if not isinstance(expected, Mapping) or not isinstance(expected.get("locator"), str) or expected.get("pseudo") not in {None, "::before", "::after"}:
            raise FontDiffInputError("font usage expectedRecords entries are invalid")
        expected_keys.add((expected.get("locator"), expected.get("pseudo")))
    pseudo_keys = set()
    for declaration in pseudo_declarations:
        if isinstance(declaration, Mapping):
            pseudo_keys.add((declaration.get("locator"), declaration.get("pseudo")))
    if not expected_keys.issubset(record_keys) or not pseudo_keys.issubset(record_keys):
        raise FontDiffInputError("font usage does not cover every expected rendered-text locator")
    return value


def _family_index(value: Mapping[str, Any]) -> Dict[Tuple[Any, Any, Any], Mapping[str, Any]]:
    result: Dict[Tuple[Any, Any, Any], Mapping[str, Any]] = {}
    for entry in value.get("families", []):
        if not isinstance(entry, Mapping):
            raise FontDiffInputError("font family entries must be objects")
        key = (entry.get("familyName"), entry.get("postScriptName"), entry.get("isCustomFont"))
        if key in result:
            raise FontDiffInputError("font usage contains duplicate family identities")
        if not isinstance(entry.get("glyphCount"), int) or not isinstance(entry.get("nodeCount"), int):
            raise FontDiffInputError("font family counts must be integers")
        result[key] = entry
    return result


def _in_scope(record: Mapping[str, Any], root_locator: str) -> bool:
    if record.get("paintedVisible") is not True:
        return False
    if root_locator == "*":
        return True
    locator = record.get("locator")
    ancestors = record.get("ancestorLocators")
    return (
        locator == root_locator
        or (isinstance(locator, str) and (locator.startswith(root_locator + " > ") or locator.startswith(root_locator + " >>> ")))
        or (isinstance(ancestors, list) and root_locator in ancestors)
    )


def scoped_record_index(value: Mapping[str, Any], root_locator: str) -> Dict[Tuple[str, Optional[str]], Tuple[Tuple[Any, Any, Any, Any], ...]]:
    result: Dict[Tuple[str, Optional[str]], Tuple[Tuple[Any, Any, Any, Any], ...]] = {}
    for entry in value.get("records", []):
        if not isinstance(entry, Mapping):
            raise FontDiffInputError("font usage record entries must be objects")
        locator = entry.get("locator")
        pseudo = entry.get("pseudo")
        ancestors = entry.get("ancestorLocators")
        fonts = entry.get("fonts")
        if not isinstance(locator, str) or not locator or pseudo not in {None, "::before", "::after"} or not isinstance(ancestors, list) or not isinstance(fonts, list):
            raise FontDiffInputError("font usage records require locator, ancestorLocators and fonts")
        if not _in_scope(entry, root_locator):
            continue
        key = (locator, pseudo)
        if key in result:
            raise FontDiffInputError("font usage contains duplicate scoped locators")
        normalized = []
        for font in fonts:
            if not isinstance(font, Mapping) or not isinstance(font.get("glyphCount"), int):
                raise FontDiffInputError("font usage record fonts are invalid")
            normalized.append((
                font.get("familyName"),
                font.get("postScriptName"),
                font.get("isCustomFont"),
                font.get("glyphCount"),
            ))
        result[key] = tuple(normalized)
    return result


def scoped_pseudo_index(value: Mapping[str, Any], root_locator: str) -> Dict[Tuple[str, str], Tuple[Any, ...]]:
    result: Dict[Tuple[str, str], Tuple[Any, ...]] = {}
    for entry in value.get("pseudoDeclarations", []):
        if not isinstance(entry, Mapping):
            raise FontDiffInputError("pseudo font declarations must be objects")
        locator = entry.get("locator")
        pseudo = entry.get("pseudo")
        ancestors = entry.get("ancestorLocators")
        font = entry.get("font")
        scope_record = {
            "locator": locator,
            "ancestorLocators": ancestors,
            "paintedVisible": True,
        }
        if not isinstance(locator, str) or pseudo not in {"::before", "::after"} or not isinstance(ancestors, list) or not isinstance(font, Mapping):
            raise FontDiffInputError("pseudo font declarations require locator, pseudo, ancestorLocators and font")
        if not _in_scope(scope_record, root_locator):
            continue
        key = (locator, pseudo)
        if key in result:
            raise FontDiffInputError("font usage contains duplicate scoped pseudo declarations")
        result[key] = (
            entry.get("content"),
            font.get("family"),
            font.get("style"),
            font.get("weight"),
            font.get("stretch"),
        )
    return result


def compare(
    reference_path: Path,
    replica_path: Path,
    root: Path,
    scope_id: str,
    root_locator: str,
) -> Tuple[Dict[str, Any], int]:
    if reference_path.resolve(strict=True) == replica_path.resolve(strict=True):
        raise FontDiffInputError("reference and replica font usage must be distinct artifacts")
    if not scope_id.strip():
        raise FontDiffInputError("scope-id is required")
    if not root_locator.strip():
        raise FontDiffInputError("root-locator is required")
    reference = _load(reference_path)
    replica = _load(replica_path)
    reference_families = _family_index(reference)
    replica_families = _family_index(replica)
    reference_records = scoped_record_index(reference, root_locator)
    replica_records = scoped_record_index(replica, root_locator)
    reference_pseudo = scoped_pseudo_index(reference, root_locator)
    replica_pseudo = scoped_pseudo_index(replica, root_locator)
    unexpected = []
    for key in sorted(reference_records.keys() | replica_records.keys(), key=str):
        left = reference_records.get(key)
        right = replica_records.get(key)
        if left != right:
            unexpected.append({
                "kind": "platform_font",
                "locator": key[0],
                "pseudo": key[1],
                "reference": [list(font) for font in left] if left is not None else None,
                "replica": [list(font) for font in right] if right is not None else None,
            })
    for key in sorted(reference_pseudo.keys() | replica_pseudo.keys()):
        left = reference_pseudo.get(key)
        right = replica_pseudo.get(key)
        if left != right:
            unexpected.append({
                "kind": "pseudo_font_declaration",
                "locator": key[0],
                "pseudo": key[1],
                "reference": list(left) if left is not None else None,
                "replica": list(right) if right is not None else None,
            })
    passed = not unexpected
    report = {
        "schema_version": 1,
        "gate": "web_font_fallback",
        "status": "pass" if passed else "fail",
        "ok": passed,
        "scope_id": scope_id,
        "root_locator": root_locator,
        "reference": {"path": _relative(reference_path, root), "sha256": _sha256(reference_path)},
        "replica": {"path": _relative(replica_path, root), "sha256": _sha256(replica_path)},
        "reference_summary": {
            "queriedNodeCount": reference.get("queriedNodeCount"),
            "scopedNodeCount": len(reference_records),
            "scopedPseudoCount": len(reference_pseudo),
            "familyCount": len(reference_families),
        },
        "replica_summary": {
            "queriedNodeCount": replica.get("queriedNodeCount"),
            "scopedNodeCount": len(replica_records),
            "scopedPseudoCount": len(replica_pseudo),
            "familyCount": len(replica_families),
        },
        "unexpected_fallbacks": unexpected,
    }
    return report, EXIT_PASS if passed else EXIT_DIFF


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".web-font-diff-", suffix=".tmp", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare actual CDP platform-font usage")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--replica", required=True)
    parser.add_argument("--scope-id", required=True)
    parser.add_argument("--root-locator", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        root = args.project_root.expanduser().resolve(strict=False)
        if not root.is_dir():
            raise FontDiffInputError("project root does not exist")
        reference = _safe_path(args.reference, root, must_exist=True)
        replica = _safe_path(args.replica, root, must_exist=True)
        output = _safe_path(args.output, root)
        if output in {reference.resolve(strict=False), replica.resolve(strict=False)}:
            raise FontDiffInputError("output cannot overwrite font usage evidence")
        report, code = compare(reference, replica, root, args.scope_id, args.root_locator)
        _write_json_atomic(output, report)
    except (FontDiffInputError, OSError) as exc:
        report = {"schema_version": 1, "gate": "web_font_fallback", "status": "invalid_input", "ok": False, "error": str(exc)}
        code = EXIT_INVALID
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
