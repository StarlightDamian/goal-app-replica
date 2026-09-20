"""Tests for exact repeated-capture stability evidence."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_stability_gate.py"
SPEC = importlib.util.spec_from_file_location("web_stability_gate", SCRIPT)
assert SPEC and SPEC.loader
web_stability_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_stability_gate)


@unittest.skipIf(Image is None, "Pillow is unavailable")
class WebStabilityGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = self.root / "environment.json"
        self.environment.write_text(
            json.dumps({
                "schemaVersion": "web-capture-environment/1.0",
                "browser": {"product": "Chrome/fixture"},
                "probeViewport": {"innerWidth": 4, "innerHeight": 4, "devicePixelRatio": 1},
                "renderingEnvironment": {"locale": "en-US"},
                "screenshotPolicy": {"scale": "device"},
            }),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def image(self, name: str, color=(255, 255, 255)) -> Path:
        path = self.root / name
        Image.new("RGB", (4, 4), color).save(path, format="PNG")
        return path

    def bundle(self, name: str, sample: Path, side: str) -> Path:
        path = self.root / name
        artifact = lambda value: {
            "path": value.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(value.read_bytes()).hexdigest(),
        }
        path.write_text(
            json.dumps({
                "schemaVersion": "web-capture-bundle/2.0",
                "contentPolicy": "public-observable",
                "context": {
                    "projectId": "project", "pageId": "home", "scenarioId": "SCN",
                    "baselineId": "BL", "viewportId": "4x4@1", "stateId": "default", "side": side,
                },
                "viewport": {"innerWidth": 4, "innerHeight": 4, "devicePixelRatio": 1},
                "referenceFingerprint": "1" * 64,
                "navigationFingerprint": "2" * 64,
                "artifacts": {"screenshot": artifact(sample), "environment": artifact(self.environment)},
            }),
            encoding="utf-8",
        )
        return path

    def test_pixel_mode_accepts_two_distinct_exact_samples(self) -> None:
        first = self.image("first.png")
        second = self.image("second.png")
        report, code = web_stability_gate.compare(
            [first, second], self.root,
            capture_bundles=[self.bundle("first-bundle.json", first, "reference"), self.bundle("second-bundle.json", second, "reference")],
            side="reference", scope_id="CMP-home"
        )
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["stable_consecutive_pair"], [0, 1])
        self.assertEqual(report["canonical"]["path"], "second.png")
        self.assertEqual(report["comparisons"][0]["exact_diff_pixels"], 0)

    def test_pixel_mode_rejects_self_noise(self) -> None:
        first = self.image("first.png")
        second = self.image("second.png")
        changed = Image.open(second).convert("RGB")
        changed.putpixel((1, 1), (254, 255, 255))
        changed.save(second, format="PNG")
        report, code = web_stability_gate.compare(
            [first, second], self.root,
            capture_bundles=[self.bundle("first-bundle.json", first, "replica"), self.bundle("second-bundle.json", second, "replica")],
            side="replica", scope_id="CMP-home"
        )
        self.assertEqual(code, 2)
        self.assertFalse(report["ok"])
        self.assertEqual(report["comparisons"][0]["exact_diff_pixels"], 1)

    def test_duplicate_artifact_path_is_not_independent_evidence(self) -> None:
        sample = self.image("sample.png")
        with self.assertRaises(web_stability_gate.StabilityInputError):
            web_stability_gate.compare(
                [sample, sample], self.root, side="reference", scope_id="CMP-home"
            )

    def test_pixel_mode_requires_capture_bundle_provenance(self) -> None:
        first = self.image("first.png")
        second = self.image("second.png")
        with self.assertRaises(web_stability_gate.StabilityInputError):
            web_stability_gate.compare(
                [first, second], self.root, side="reference", scope_id="CMP-home"
            )

    def test_cli_refuses_to_overwrite_sample_input(self) -> None:
        first = self.image("first.png")
        second = self.image("second.png")
        first_bundle = self.bundle("first-bundle.json", first, "reference")
        second_bundle = self.bundle("second-bundle.json", second, "reference")
        with mock.patch("sys.stdout", io.StringIO()):
            code = web_stability_gate.main([
                "--project-root", str(self.root), "--sample", str(first), "--sample", str(second),
                "--capture-bundle", str(first_bundle), "--capture-bundle", str(second_bundle),
                "--side", "reference", "--scope-id", "CMP-home", "--output", str(first),
            ])
        self.assertEqual(code, 3)
        with Image.open(first) as image:
            self.assertEqual(image.format, "PNG")


if __name__ == "__main__":
    unittest.main(verbosity=2)
