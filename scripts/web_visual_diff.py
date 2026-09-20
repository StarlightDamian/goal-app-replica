#!/usr/bin/env python3
"""Deterministic paired screenshot diff for authorized Web replica evidence.

This tool never captures or downloads a page. It compares two already-stored
images, writes an overlay and a visual diff, and emits a hash-bound JSON report.
Masks are allowed only when every rectangle names an approved deviation. A
masked report can pass only for the unmasked region; it never claims whole-page
pixel equivalence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageStat
except ImportError as exc:  # pragma: no cover - depends on host runtime
    Image = None  # type: ignore[assignment]
    _PIL_IMPORT_ERROR = exc
else:
    _PIL_IMPORT_ERROR = None


EXIT_PASS = 0
EXIT_DIFF_FAILED = 2
EXIT_INVALID_INPUT = 3


class DiffInputError(Exception):
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
        raise DiffInputError("path escapes project root: %s" % raw) from exc
    if must_exist and not resolved.is_file():
        raise DiffInputError("file does not exist: %s" % raw)
    return resolved


def _relative(path: Path, root: Path) -> str:
    return path.resolve(strict=False).relative_to(root).as_posix()


def _load_masks(path: Optional[Path], width: int, height: int) -> List[Dict[str, Any]]:
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DiffInputError("mask JSON is unreadable or invalid") from exc
    entries = payload.get("masks") if isinstance(payload, Mapping) else None
    if not isinstance(entries, list):
        raise DiffInputError("mask JSON must contain a masks array")
    masks: List[Dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise DiffInputError("mask %d must be an object" % index)
        deviation_id = entry.get("deviation_id")
        if not isinstance(deviation_id, str) or not deviation_id.strip():
            raise DiffInputError("mask %d requires deviation_id" % index)
        try:
            x = int(entry["x"])
            y = int(entry["y"])
            mask_width = int(entry["width"])
            mask_height = int(entry["height"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DiffInputError("mask %d requires integer x/y/width/height" % index) from exc
        if x < 0 or y < 0 or mask_width < 1 or mask_height < 1:
            raise DiffInputError("mask %d has invalid bounds" % index)
        right = min(width, x + mask_width)
        bottom = min(height, y + mask_height)
        if x >= width or y >= height or right <= x or bottom <= y:
            raise DiffInputError("mask %d does not intersect the image" % index)
        masks.append(
            {
                "x": x,
                "y": y,
                "width": right - x,
                "height": bottom - y,
                "deviation_id": deviation_id.strip(),
                "reason": str(entry.get("reason") or "").strip(),
            }
        )
    return masks


def _masked_pixel_count(masks: Iterable[Mapping[str, Any]], width: int, height: int) -> int:
    # Rectangles may overlap. Rasterizing a one-bit mask gives an exact union.
    bitmap = Image.new("1", (width, height), 0)
    draw = ImageDraw.Draw(bitmap)
    for mask in masks:
        x, y = int(mask["x"]), int(mask["y"])
        draw.rectangle(
            (x, y, x + int(mask["width"]) - 1, y + int(mask["height"]) - 1),
            fill=1,
        )
    return int(sum(bitmap.histogram()[1:]))


def compare(
    reference: Path,
    replica: Path,
    root: Path,
    output_dir: Path,
    channel_threshold: int,
    max_diff_ratio: float,
    max_diff_pixels: Optional[int],
    masks_path: Optional[Path],
) -> Tuple[Dict[str, Any], int]:
    if Image is None:
        raise DiffInputError("Pillow is required for image decoding: %s" % _PIL_IMPORT_ERROR)
    if channel_threshold < 0 or channel_threshold > 255:
        raise DiffInputError("channel threshold must be from 0 to 255")
    if max_diff_ratio < 0 or max_diff_ratio > 1:
        raise DiffInputError("max diff ratio must be from 0 to 1")
    if max_diff_pixels is not None and max_diff_pixels < 0:
        raise DiffInputError("max diff pixels cannot be negative")

    try:
        reference_image = Image.open(reference).convert("RGB")
        replica_image = Image.open(replica).convert("RGB")
    except (OSError, ValueError) as exc:
        raise DiffInputError("reference or replica image cannot be decoded") from exc
    if reference_image.size != replica_image.size:
        raise DiffInputError(
            "image dimensions differ: reference=%s replica=%s"
            % (reference_image.size, replica_image.size)
        )

    width, height = reference_image.size
    masks = _load_masks(masks_path, width, height)
    raw_difference = ImageChops.difference(reference_image, replica_image)
    red, green, blue = raw_difference.split()
    max_channel = ImageChops.lighter(ImageChops.lighter(red, green), blue)
    for mask in masks:
        x, y = int(mask["x"]), int(mask["y"])
        box = (x, y, x + int(mask["width"]) - 1, y + int(mask["height"]) - 1)
        ImageDraw.Draw(max_channel).rectangle(box, fill=0)

    histogram = max_channel.histogram()
    exact_diff_pixels = int(sum(histogram[1:]))
    diff_pixels = int(sum(histogram[channel_threshold + 1 :]))
    masked_pixels = _masked_pixel_count(masks, width, height)
    compared_pixels = width * height - masked_pixels
    if compared_pixels <= 0:
        raise DiffInputError("masks cover the entire image")
    diff_ratio = diff_pixels / compared_pixels
    ratio_pass = diff_ratio <= max_diff_ratio
    pixel_pass = max_diff_pixels is None or diff_pixels <= max_diff_pixels
    passed = ratio_pass and pixel_pass

    output_dir.mkdir(parents=True, exist_ok=True)
    overlay_path = output_dir / "overlay.png"
    diff_path = output_dir / "diff.png"
    overlay = Image.blend(reference_image, replica_image, 0.5)
    diff_visual = ImageEnhance.Contrast(raw_difference).enhance(4.0)
    if masks:
        draw = ImageDraw.Draw(diff_visual)
        for mask in masks:
            x, y = int(mask["x"]), int(mask["y"])
            draw.rectangle(
                (x, y, x + int(mask["width"]) - 1, y + int(mask["height"]) - 1),
                fill=(96, 96, 96),
            )
    overlay.save(overlay_path, format="PNG")
    diff_visual.save(diff_path, format="PNG")

    mean_channels = ImageStat.Stat(raw_difference).mean
    report: Dict[str, Any] = {
        "schema_version": 1,
        "gate": "web_visual_diff",
        "status": "pass" if passed else "fail",
        "ok": passed,
        "scope": "unmasked_regions_only" if masks else "whole_image",
        "visual_equivalent_within_threshold": passed,
        "whole_page_pixel_equivalent": bool(passed and not masks and exact_diff_pixels == 0),
        "reference": {
            "path": _relative(reference, root),
            "sha256": _sha256(reference),
        },
        "replica": {
            "path": _relative(replica, root),
            "sha256": _sha256(replica),
        },
        "image": {"width": width, "height": height, "pixels": width * height},
        "thresholds": {
            "channel_threshold": channel_threshold,
            "max_diff_ratio": max_diff_ratio,
            "max_diff_pixels": max_diff_pixels,
        },
        "metrics": {
            "diff_pixels": diff_pixels,
            "exact_diff_pixels": exact_diff_pixels,
            "diff_ratio": diff_ratio,
            "compared_pixels": compared_pixels,
            "masked_pixels": masked_pixels,
            "masked_ratio": masked_pixels / (width * height),
            "mean_absolute_channel_difference": sum(mean_channels) / (3 * 255),
        },
        "masks": masks,
        "artifacts": {
            "overlay": {"path": _relative(overlay_path, root), "sha256": _sha256(overlay_path)},
            "diff": {"path": _relative(diff_path, root), "sha256": _sha256(diff_path)},
        },
    }
    return report, EXIT_PASS if passed else EXIT_DIFF_FAILED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a hash-bound paired Web screenshot diff")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--replica", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--report", default="report.json")
    parser.add_argument("--channel-threshold", type=int, default=16)
    parser.add_argument("--max-diff-ratio", type=float, default=0.0)
    parser.add_argument("--max-diff-pixels", type=int)
    parser.add_argument("--mask-json")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        root = args.project_root.expanduser().resolve(strict=False)
        if not root.is_dir():
            raise DiffInputError("project root does not exist")
        reference = _safe_path(args.reference, root, must_exist=True)
        replica = _safe_path(args.replica, root, must_exist=True)
        output_dir = _safe_path(args.output_dir, root)
        report_path = _safe_path(str(Path(args.output_dir) / args.report), root)
        masks_path = _safe_path(args.mask_json, root, must_exist=True) if args.mask_json else None
        report, exit_code = compare(
            reference,
            replica,
            root,
            output_dir,
            args.channel_threshold,
            args.max_diff_ratio,
            args.max_diff_pixels,
            masks_path,
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (DiffInputError, OSError) as exc:
        report = {
            "schema_version": 1,
            "gate": "web_visual_diff",
            "status": "invalid_input",
            "ok": False,
            "error": str(exc),
        }
        exit_code = EXIT_INVALID_INPUT
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
