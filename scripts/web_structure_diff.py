#!/usr/bin/env python3
"""Compare two Web probe inventories and rank actionable geometry/style gaps."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


SCHEMA = "web-asset-inventory/1.0"
STYLE_SECTIONS = ("font", "layout", "layer", "transform", "replacedContent", "paint")
GEOMETRY_FIELDS = ("x", "y", "width", "height", "top", "right", "bottom", "left")
EXIT_PASS = 0
EXIT_DIFF = 2
EXIT_INVALID = 3


class DiffError(Exception):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path(raw: Path, root: Path, *, must_exist: bool = False) -> Path:
    candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.expanduser().resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise DiffError("path escapes project root") from exc
    if must_exist and not resolved.is_file():
        raise DiffError("input file does not exist")
    return resolved


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".web-structure-diff-", suffix=".tmp", dir=str(path.parent))
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


def _load(path: Path) -> Tuple[Dict[str, Any], Path]:
    try:
        resolved = path.expanduser().resolve(strict=True)
        value = json.loads(resolved.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DiffError("inventory must be readable UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != SCHEMA:
        raise DiffError(f"inventory schemaVersion must be {SCHEMA}")
    if not isinstance(value.get("visibleElements"), list):
        raise DiffError("inventory visibleElements must be an array")
    return value, resolved


def _in_scope(record: Mapping[str, Any], root: Optional[str]) -> bool:
    if not root or root == "*":
        return True
    locator = record.get("locator")
    ancestors = record.get("ancestorLocators")
    return (
        locator == root
        or (isinstance(locator, str) and (locator.startswith(root + " > ") or locator.startswith(root + " >>> ")))
        or (isinstance(ancestors, list) and root in ancestors)
    )


def _index(records: Iterable[Any], root: Optional[str]) -> Dict[str, Mapping[str, Any]]:
    result: Dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        locator = record.get("locator")
        if not isinstance(locator, str) or not locator or not _in_scope(record, root):
            continue
        if locator in result:
            raise DiffError("visibleElements contains a duplicate locator")
        result[locator] = record
    return result


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _flatten(value: Any, prefix: str = "") -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: Dict[str, Any] = {}
    for key in sorted(value):
        path = f"{prefix}.{key}" if prefix else str(key)
        child = value[key]
        if isinstance(child, Mapping):
            result.update(_flatten(child, path))
        else:
            result[path] = child
    return result


def compare(
    reference_path: Path,
    replica_path: Path,
    *,
    root_locator: Optional[str] = None,
    geometry_tolerance: float = 0.5,
    max_mismatches: int = 200,
) -> Tuple[Dict[str, Any], int]:
    if geometry_tolerance < 0:
        raise DiffError("geometry tolerance cannot be negative")
    reference, reference_resolved = _load(reference_path)
    replica, replica_resolved = _load(replica_path)
    if reference_resolved == replica_resolved:
        raise DiffError("reference and replica inventories must be distinct artifacts")
    reference_nodes = _index(reference["visibleElements"], root_locator)
    replica_nodes = _index(replica["visibleElements"], root_locator)
    mismatches = []

    for locator in sorted(reference_nodes.keys() - replica_nodes.keys()):
        mismatches.append({"kind": "missing_in_replica", "locator": locator, "score": 1000})
    for locator in sorted(replica_nodes.keys() - reference_nodes.keys()):
        mismatches.append({"kind": "extra_in_replica", "locator": locator, "score": 900})

    for locator in sorted(reference_nodes.keys() & replica_nodes.keys()):
        reference_node = reference_nodes[locator]
        replica_node = replica_nodes[locator]
        reference_geometry = reference_node.get("geometry") if isinstance(reference_node.get("geometry"), Mapping) else {}
        replica_geometry = replica_node.get("geometry") if isinstance(replica_node.get("geometry"), Mapping) else {}
        for field in GEOMETRY_FIELDS:
            left = _number(reference_geometry.get(field))
            right = _number(replica_geometry.get(field))
            if left is None and right is None:
                continue
            if left is None or right is None or abs(left - right) > geometry_tolerance:
                delta = None if left is None or right is None else right - left
                mismatches.append(
                    {
                        "kind": "geometry",
                        "locator": locator,
                        "property": field,
                        "reference": left,
                        "replica": right,
                        "delta": delta,
                        "score": 500 + (abs(delta) if delta is not None else 100),
                    }
                )
        for section in STYLE_SECTIONS:
            reference_style = _flatten(reference_node.get(section), section)
            replica_style = _flatten(replica_node.get(section), section)
            for property_name in sorted(reference_style.keys() | replica_style.keys()):
                left = reference_style.get(property_name)
                right = replica_style.get(property_name)
                if left != right:
                    mismatches.append(
                        {
                            "kind": "computed_style",
                            "locator": locator,
                            "property": property_name,
                            "reference": left,
                            "replica": right,
                            "score": 300,
                        }
                    )

    mismatches.sort(key=lambda item: (-float(item["score"]), item["locator"], item.get("property", "")))
    passed = not mismatches
    report = {
        "schema_version": 1,
        "gate": "web_structure_diff",
        "status": "pass" if passed else "fail",
        "ok": passed,
        "scope": {"root_locator": root_locator or "*"},
        "reference": {"path": str(reference_resolved), "sha256": _sha256(reference_resolved)},
        "replica": {"path": str(replica_resolved), "sha256": _sha256(replica_resolved)},
        "thresholds": {"geometry_tolerance_css_px": geometry_tolerance},
        "summary": {
            "reference_nodes": len(reference_nodes),
            "replica_nodes": len(replica_nodes),
            "matched_nodes": len(reference_nodes.keys() & replica_nodes.keys()),
            "mismatch_count": len(mismatches),
            "reported_mismatch_count": min(len(mismatches), max_mismatches),
        },
        "mismatches": mismatches[:max_mismatches],
    }
    return report, EXIT_PASS if passed else EXIT_DIFF


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare Web probe geometry and computed styles")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--replica", required=True, type=Path)
    parser.add_argument("--root-locator")
    parser.add_argument("--geometry-tolerance", type=float, default=0.5)
    parser.add_argument("--max-mismatches", type=int, default=200)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.max_mismatches < 1:
            raise DiffError("max mismatches must be positive")
        root = args.project_root.expanduser().resolve(strict=False)
        if not root.is_dir():
            raise DiffError("project root does not exist")
        reference = _safe_path(args.reference, root, must_exist=True)
        replica = _safe_path(args.replica, root, must_exist=True)
        output = _safe_path(args.output, root) if args.output else None
        if output is not None and output in {reference, replica}:
            raise DiffError("output cannot overwrite input evidence")
        report, code = compare(
            reference,
            replica,
            root_locator=args.root_locator,
            geometry_tolerance=args.geometry_tolerance,
            max_mismatches=args.max_mismatches,
        )
        if output:
            _write_json_atomic(output, report)
    except (DiffError, OSError) as exc:
        report = {"schema_version": 1, "gate": "web_structure_diff", "status": "invalid_input", "ok": False, "error": str(exc)}
        code = EXIT_INVALID
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
