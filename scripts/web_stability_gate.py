#!/usr/bin/env python3
"""Prove that repeated captures of one Web state are raster-stable.

The gate consumes screenshots that were already captured under the same
viewport/state/environment.  It never opens a browser.  Pixel mode requires
two consecutive, byte-independent PNG artifacts whose decoded RGB pixels are
exactly equal.  The JSON report is intentionally self-contained and can be
independently recomputed by ``web_fidelity_gate.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from PIL import Image, ImageChops
except ImportError as exc:  # pragma: no cover - depends on host runtime
    Image = None  # type: ignore[assignment]
    ImageChops = None  # type: ignore[assignment]
    _PIL_IMPORT_ERROR = exc
else:
    _PIL_IMPORT_ERROR = None


EXIT_PASS = 0
EXIT_UNSTABLE = 2
EXIT_INVALID = 3


class StabilityInputError(Exception):
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
        raise StabilityInputError("path escapes project root: %s" % raw) from exc
    if must_exist and not resolved.is_file():
        raise StabilityInputError("file does not exist: %s" % raw)
    return resolved


def _relative(path: Path, root: Path) -> str:
    return path.resolve(strict=False).relative_to(root).as_posix()


def _artifact(path: Path, root: Path) -> Dict[str, str]:
    return {"path": _relative(path, root), "sha256": _sha256(path)}


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".web-stability-", suffix=".tmp", dir=str(path.parent))
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


def _capture_bundle(
    bundle_path: Path,
    sample_path: Path,
    root: Path,
    side: str,
) -> Dict[str, Any]:
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StabilityInputError("capture bundle must be readable UTF-8 JSON") from exc
    if not isinstance(bundle, Mapping) or bundle.get("schemaVersion") != "web-capture-bundle/2.0":
        raise StabilityInputError("capture bundle schemaVersion must be web-capture-bundle/2.0")
    context = bundle.get("context")
    if not isinstance(context, Mapping) or context.get("side") != side:
        raise StabilityInputError("capture bundle side does not match the stability report side")
    artifacts = bundle.get("artifacts")
    screenshot = artifacts.get("screenshot") if isinstance(artifacts, Mapping) else None
    environment = artifacts.get("environment") if isinstance(artifacts, Mapping) else None
    if not isinstance(screenshot, Mapping) or not isinstance(environment, Mapping):
        raise StabilityInputError("capture bundle requires screenshot and environment artifacts")
    screenshot_path = _safe_path(str(screenshot.get("path") or ""), root, must_exist=True)
    if screenshot_path != sample_path.resolve(strict=True) or screenshot.get("sha256") != _sha256(sample_path):
        raise StabilityInputError("capture bundle screenshot does not match its stability sample")
    environment_path = _safe_path(str(environment.get("path") or ""), root, must_exist=True)
    if environment.get("sha256") != _sha256(environment_path):
        raise StabilityInputError("capture bundle environment hash does not match its artifact")
    try:
        environment_payload = json.loads(environment_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StabilityInputError("capture environment must be readable UTF-8 JSON") from exc
    if not isinstance(environment_payload, Mapping) or environment_payload.get("schemaVersion") != "web-capture-environment/1.0":
        raise StabilityInputError("capture environment schemaVersion is invalid")
    environment_lock = {
        "browser": environment_payload.get("browser"),
        "probeViewport": environment_payload.get("probeViewport"),
        "renderingEnvironment": environment_payload.get("renderingEnvironment"),
        "screenshotPolicy": environment_payload.get("screenshotPolicy"),
    }
    return {
        "artifact": _artifact(bundle_path, root),
        "context": dict(context),
        "viewport": bundle.get("viewport"),
        "contentPolicy": bundle.get("contentPolicy"),
        "referenceFingerprint": bundle.get("referenceFingerprint"),
        "navigationFingerprint": bundle.get("navigationFingerprint"),
        "environmentLock": environment_lock,
    }


def _png(path: Path):
    if Image is None:
        raise StabilityInputError("Pillow is required for PNG decoding: %s" % _PIL_IMPORT_ERROR)
    try:
        image = Image.open(path)
        image.load()
        if image.format != "PNG":
            raise StabilityInputError("every stability sample must be a PNG")
        return image.convert("RGB")
    except (OSError, ValueError) as exc:
        raise StabilityInputError("a stability sample cannot be decoded as PNG") from exc


def _metrics(left, right, channel_threshold: int) -> Dict[str, Any]:
    if left.size != right.size:
        return {"dimension_mismatch": True}
    difference = ImageChops.difference(left, right)
    red, green, blue = difference.split()
    max_channel = ImageChops.lighter(ImageChops.lighter(red, green), blue)
    histogram = max_channel.histogram()
    pixels = left.width * left.height
    exact = int(sum(histogram[1:]))
    thresholded = int(sum(histogram[channel_threshold + 1 :]))
    return {
        "dimension_mismatch": False,
        "pixels": pixels,
        "exact_diff_pixels": exact,
        "diff_pixels": thresholded,
        "diff_ratio": thresholded / pixels if pixels else 0.0,
    }


def compare(
    samples: Sequence[Path],
    root: Path,
    *,
    capture_bundles: Optional[Sequence[Path]] = None,
    side: str,
    scope_id: str,
    mode: str = "pixel",
    channel_threshold: int = 0,
    max_diff_ratio: float = 0.0,
) -> Tuple[Dict[str, Any], int]:
    if len(samples) < 2:
        raise StabilityInputError("at least two independently saved samples are required")
    if len({sample.resolve(strict=True) for sample in samples}) != len(samples):
        raise StabilityInputError("stability samples must use distinct artifact paths")
    if side not in {"reference", "replica"}:
        raise StabilityInputError("side must be reference or replica")
    if not scope_id.strip():
        raise StabilityInputError("scope-id is required")
    if mode not in {"pixel", "visual"}:
        raise StabilityInputError("mode must be pixel or visual")
    if mode == "pixel" and (capture_bundles is None or len(capture_bundles) != len(samples)):
        raise StabilityInputError("pixel stability requires one capture bundle per screenshot sample")
    if not 0 <= channel_threshold <= 255:
        raise StabilityInputError("channel threshold must be from 0 to 255")
    if not 0 <= max_diff_ratio <= 1:
        raise StabilityInputError("max diff ratio must be from 0 to 1")

    images = [_png(sample) for sample in samples]
    captures = [
        _capture_bundle(bundle, sample, root, side)
        for bundle, sample in zip(capture_bundles or (), samples)
    ]
    if captures:
        if len({capture["artifact"]["path"] for capture in captures}) != len(captures):
            raise StabilityInputError("stability capture bundles must use distinct artifact paths")
        first = captures[0]
        for capture in captures[1:]:
            if any(
                capture[field] != first[field]
                for field in ("context", "viewport", "contentPolicy", "referenceFingerprint", "environmentLock")
            ):
                raise StabilityInputError("stability samples were not captured under the same context and rendering environment")
    comparisons: List[Dict[str, Any]] = []
    stable_pair: Optional[List[int]] = None
    for index in range(len(images) - 1):
        metrics = _metrics(images[index], images[index + 1], channel_threshold)
        pair_pass = (
            metrics.get("dimension_mismatch") is False
            and (
                metrics.get("exact_diff_pixels") == 0
                if mode == "pixel"
                else float(metrics.get("diff_ratio", 1.0)) <= max_diff_ratio
            )
        )
        comparisons.append({"left_index": index, "right_index": index + 1, "pass": pair_pass, **metrics})
        if pair_pass and stable_pair is None:
            stable_pair = [index, index + 1]

    passed = stable_pair is not None
    canonical_index = stable_pair[1] if stable_pair else len(samples) - 1
    records = [
        {"path": _relative(sample, root), "sha256": _sha256(sample)}
        for sample in samples
    ]
    report: Dict[str, Any] = {
        "schema_version": 1,
        "gate": "web_stability_gate",
        "status": "pass" if passed else "fail",
        "ok": passed,
        "mode": mode,
        "side": side,
        "scope_id": scope_id,
        "thresholds": {
            "channel_threshold": channel_threshold,
            "max_diff_ratio": max_diff_ratio,
        },
        "samples": records,
        "capture_bundles": [capture["artifact"] for capture in captures],
        "comparisons": comparisons,
        "stable_consecutive_pair": stable_pair,
        "canonical": records[canonical_index],
    }
    return report, EXIT_PASS if passed else EXIT_UNSTABLE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify repeated Web screenshot stability")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--sample", required=True, action="append")
    parser.add_argument("--capture-bundle", action="append")
    parser.add_argument("--side", required=True, choices=("reference", "replica"))
    parser.add_argument("--scope-id", required=True)
    parser.add_argument("--mode", default="pixel", choices=("pixel", "visual"))
    parser.add_argument("--channel-threshold", type=int, default=0)
    parser.add_argument("--max-diff-ratio", type=float, default=0.0)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        root = args.project_root.expanduser().resolve(strict=False)
        if not root.is_dir():
            raise StabilityInputError("project root does not exist")
        samples = [_safe_path(value, root, must_exist=True) for value in args.sample]
        capture_bundles = [
            _safe_path(value, root, must_exist=True) for value in (args.capture_bundle or [])
        ]
        output = _safe_path(args.output, root)
        if output in {path.resolve(strict=False) for path in [*samples, *capture_bundles]}:
            raise StabilityInputError("output cannot overwrite a screenshot or capture bundle input")
        report, code = compare(
            samples,
            root,
            capture_bundles=capture_bundles,
            side=args.side,
            scope_id=args.scope_id,
            mode=args.mode,
            channel_threshold=args.channel_threshold,
            max_diff_ratio=args.max_diff_ratio,
        )
        _write_json_atomic(output, report)
    except (StabilityInputError, OSError) as exc:
        report = {
            "schema_version": 1,
            "gate": "web_stability_gate",
            "status": "invalid_input",
            "ok": False,
            "error": str(exc),
        }
        code = EXIT_INVALID
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
