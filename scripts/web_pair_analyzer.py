#!/usr/bin/env python3
"""Turn paired Web evidence into a deterministic next-fix work queue.

Raw heatmaps say *where* pixels differ but not *why*.  This helper combines a
paired PNG diff with the existing structured diff and ranks environment,
structure, geometry, typography, asset/paint and raster-only work without
guessing CSS values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from PIL import Image, ImageChops
except ImportError as exc:  # pragma: no cover
    Image = None  # type: ignore[assignment]
    ImageChops = None  # type: ignore[assignment]
    _PIL_IMPORT_ERROR = exc
else:
    _PIL_IMPORT_ERROR = None


EXIT_EXACT = 0
EXIT_DIFF = 2
EXIT_INVALID = 3
FONT_PROPERTIES = ("font", "lineHeight", "letterSpacing", "text")
ASSET_PROPERTIES = ("background", "mask", "content", "objectFit", "objectPosition", "paint")
PHASE_ORDER = {
    "environment": 0,
    "structure": 1,
    "geometry": 2,
    "typography": 3,
    "asset_paint": 4,
    "style": 5,
    "raster": 6,
}


class AnalyzerInputError(Exception):
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
        raise AnalyzerInputError("path escapes project root: %s" % raw) from exc
    if must_exist and not resolved.is_file():
        raise AnalyzerInputError("file does not exist: %s" % raw)
    return resolved


def _relative(path: Path, root: Path) -> str:
    return path.resolve(strict=False).relative_to(root).as_posix()


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".web-pair-analysis-", suffix=".tmp", dir=str(path.parent))
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


def _load_png(path: Path):
    if Image is None:
        raise AnalyzerInputError("Pillow is required for PNG decoding: %s" % _PIL_IMPORT_ERROR)
    try:
        image = Image.open(path)
        image.load()
        if image.format != "PNG":
            raise AnalyzerInputError("paired screenshots must be PNG")
        return image.convert("RGB")
    except (OSError, ValueError) as exc:
        raise AnalyzerInputError("paired screenshot cannot be decoded") from exc


def _load_structure(path: Optional[Path]) -> Optional[Mapping[str, Any]]:
    if path is None:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AnalyzerInputError("structure report must be readable UTF-8 JSON") from exc
    if not isinstance(value, Mapping) or value.get("gate") != "web_structure_diff":
        raise AnalyzerInputError("structure report must be web_structure_diff output")
    return value


def _diff_tiles(max_channel, tile_size: int, max_regions: int) -> Tuple[int, Optional[Tuple[int, int, int, int]], List[Dict[str, Any]]]:
    histogram = max_channel.histogram()
    exact = int(sum(histogram[1:]))
    bbox = max_channel.getbbox()
    regions: List[Dict[str, Any]] = []
    for y in range(0, max_channel.height, tile_size):
        for x in range(0, max_channel.width, tile_size):
            right = min(max_channel.width, x + tile_size)
            bottom = min(max_channel.height, y + tile_size)
            crop = max_channel.crop((x, y, right, bottom))
            crop_histogram = crop.histogram()
            changed = int(sum(crop_histogram[1:]))
            if not changed:
                continue
            area = (right - x) * (bottom - y)
            regions.append({
                "kind": "raster_region",
                "x": x,
                "y": y,
                "width": right - x,
                "height": bottom - y,
                "exact_diff_pixels": changed,
                "diff_ratio": changed / area,
                "max_channel_delta": max(index for index, count in enumerate(crop_histogram) if count),
                "score": changed * (1.0 + changed / area),
            })
    regions.sort(key=lambda item: (-float(item["score"]), item["y"], item["x"]))
    return exact, bbox, regions[:max_regions]


def _phase(item: Mapping[str, Any]) -> str:
    kind = str(item.get("kind") or "")
    if kind in {"missing_in_replica", "extra_in_replica"}:
        return "structure"
    if kind == "geometry":
        return "geometry"
    property_name = str(item.get("property") or "")
    if any(token.lower() in property_name.lower() for token in FONT_PROPERTIES):
        return "typography"
    if any(token.lower() in property_name.lower() for token in ASSET_PROPERTIES):
        return "asset_paint"
    if kind == "computed_style":
        return "style"
    return "raster"


def analyze(
    reference_path: Path,
    replica_path: Path,
    root: Path,
    *,
    structure_path: Optional[Path] = None,
    previous_path: Optional[Path] = None,
    tile_size: int = 32,
    max_regions: int = 50,
) -> Tuple[Dict[str, Any], int]:
    if tile_size < 4 or tile_size > 512:
        raise AnalyzerInputError("tile-size must be from 4 to 512")
    if max_regions < 1:
        raise AnalyzerInputError("max-regions must be positive")
    reference = _load_png(reference_path)
    replica = _load_png(replica_path)
    if reference_path.resolve(strict=True) == replica_path.resolve(strict=True):
        raise AnalyzerInputError("reference and replica must be distinct artifacts")
    structure = _load_structure(structure_path)
    previous = None
    if previous_path is not None:
        try:
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AnalyzerInputError("previous analyzer report must be readable UTF-8 JSON") from exc

    queue: List[Dict[str, Any]] = []
    if reference.size != replica.size:
        exact = None
        bbox = None
        raster_regions: List[Dict[str, Any]] = []
        queue.append({
            "priority": 1,
            "phase": "environment",
            "kind": "dimension_mismatch",
            "reference": {"width": reference.width, "height": reference.height},
            "replica": {"width": replica.width, "height": replica.height},
            "reason": "Lock viewport, DPR, screenshot scale and capture mode before CSS work.",
        })
    else:
        difference = ImageChops.difference(reference, replica)
        red, green, blue = difference.split()
        max_channel = ImageChops.lighter(ImageChops.lighter(red, green), blue)
        exact, bbox, raster_regions = _diff_tiles(max_channel, tile_size, max_regions)

    mismatches = structure.get("mismatches") if isinstance(structure, Mapping) else []
    if not isinstance(mismatches, list):
        mismatches = []
    structured_queue: List[Dict[str, Any]] = []
    for mismatch in mismatches:
        if not isinstance(mismatch, Mapping):
            continue
        structured_queue.append({
            "phase": _phase(mismatch),
            "kind": mismatch.get("kind"),
            "locator": mismatch.get("locator"),
            "property": mismatch.get("property"),
            "reference": mismatch.get("reference"),
            "replica": mismatch.get("replica"),
            "delta": mismatch.get("delta"),
            "source_score": mismatch.get("score") if isinstance(mismatch.get("score"), (int, float)) else 0,
            "reason": "Use the captured value; do not infer this property from the heatmap.",
        })
    structured_queue.sort(
        key=lambda item: (
            PHASE_ORDER.get(str(item["phase"]), 99),
            -float(item["source_score"]),
            str(item.get("locator") or ""),
            str(item.get("property") or ""),
        )
    )
    for item in structured_queue:
        item = dict(item)
        item.pop("source_score", None)
        item["priority"] = len(queue) + 1
        queue.append(item)
    for region in raster_regions:
        queue.append({
            "priority": len(queue) + 1,
            "phase": "raster",
            **{key: value for key, value in region.items() if key != "score"},
            "reason": "Inspect the highest-density unresolved region after structured mismatches converge.",
        })

    phase_counts = Counter(item["phase"] for item in queue)
    current_exact = exact if isinstance(exact, int) else None
    trend = "unknown"
    if isinstance(previous, Mapping):
        previous_exact = previous.get("metrics", {}).get("exact_diff_pixels") if isinstance(previous.get("metrics"), Mapping) else None
        if isinstance(previous_exact, int) and current_exact is not None:
            trend = "improved" if current_exact < previous_exact else "regressed" if current_exact > previous_exact else "unchanged"
    report: Dict[str, Any] = {
        "schema_version": 1,
        "analyzer": "web_pair_analyzer",
        "status": "exact" if current_exact == 0 and reference.size == replica.size else "diff",
        "reference": {"path": _relative(reference_path, root), "sha256": _sha256(reference_path)},
        "replica": {"path": _relative(replica_path, root), "sha256": _sha256(replica_path)},
        "image": {
            "reference": {"width": reference.width, "height": reference.height},
            "replica": {"width": replica.width, "height": replica.height},
        },
        "metrics": {
            "exact_diff_pixels": current_exact,
            "diff_bbox": list(bbox) if bbox is not None else None,
            "tile_size": tile_size,
            "reported_raster_regions": len(raster_regions),
        },
        "trend": trend,
        "phase_counts": dict(sorted(phase_counts.items())),
        "work_queue": queue[:max_regions],
    }
    return report, EXIT_EXACT if report["status"] == "exact" else EXIT_DIFF


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rank actionable fixes from paired Web evidence")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--replica", required=True)
    parser.add_argument("--structure-report")
    parser.add_argument("--previous-report")
    parser.add_argument("--tile-size", type=int, default=32)
    parser.add_argument("--max-regions", type=int, default=50)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        root = args.project_root.expanduser().resolve(strict=False)
        if not root.is_dir():
            raise AnalyzerInputError("project root does not exist")
        reference = _safe_path(args.reference, root, must_exist=True)
        replica = _safe_path(args.replica, root, must_exist=True)
        structure = _safe_path(args.structure_report, root, must_exist=True) if args.structure_report else None
        previous = _safe_path(args.previous_report, root, must_exist=True) if args.previous_report else None
        output = _safe_path(args.output, root)
        inputs = {reference.resolve(strict=False), replica.resolve(strict=False)}
        if structure is not None:
            inputs.add(structure.resolve(strict=False))
        if previous is not None:
            inputs.add(previous.resolve(strict=False))
        if output in inputs:
            raise AnalyzerInputError("output cannot overwrite an input artifact")
        report, code = analyze(
            reference,
            replica,
            root,
            structure_path=structure,
            previous_path=previous,
            tile_size=args.tile_size,
            max_regions=args.max_regions,
        )
        _write_json_atomic(output, report)
    except (AnalyzerInputError, OSError) as exc:
        report = {
            "schema_version": 1,
            "analyzer": "web_pair_analyzer",
            "status": "invalid_input",
            "error": str(exc),
        }
        code = EXIT_INVALID
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
