"""Tests for the deterministic paired-evidence work queue."""

from __future__ import annotations

import importlib.util
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


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_pair_analyzer.py"
SPEC = importlib.util.spec_from_file_location("web_pair_analyzer", SCRIPT)
assert SPEC and SPEC.loader
web_pair_analyzer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_pair_analyzer)


@unittest.skipIf(Image is None, "Pillow is unavailable")
class WebPairAnalyzerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def image(self, name: str, size=(64, 64), color=(255, 255, 255)) -> Path:
        path = self.root / name
        Image.new("RGB", size, color).save(path, format="PNG")
        return path

    def test_identical_pair_is_exact(self) -> None:
        reference = self.image("reference.png")
        replica = self.image("replica.png")
        report, code = web_pair_analyzer.analyze(reference, replica, self.root)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "exact")
        self.assertEqual(report["metrics"]["exact_diff_pixels"], 0)

    def test_same_artifact_cannot_masquerade_as_a_pair(self) -> None:
        reference = self.image("reference.png")
        with self.assertRaises(web_pair_analyzer.AnalyzerInputError):
            web_pair_analyzer.analyze(reference, reference, self.root)

    def test_cli_refuses_to_overwrite_input_evidence(self) -> None:
        reference = self.image("reference.png")
        replica = self.image("replica.png")
        with mock.patch("sys.stdout", io.StringIO()):
            code = web_pair_analyzer.main([
                "--project-root", str(self.root), "--reference", str(reference),
                "--replica", str(replica), "--output", str(reference),
            ])
        self.assertEqual(code, 3)
        with Image.open(reference) as image:
            self.assertEqual(image.format, "PNG")

    def test_dimension_mismatch_prioritizes_environment(self) -> None:
        reference = self.image("reference.png", size=(64, 64))
        replica = self.image("replica.png", size=(63, 64))
        report, code = web_pair_analyzer.analyze(reference, replica, self.root)
        self.assertEqual(code, 2)
        self.assertEqual(report["work_queue"][0]["phase"], "environment")

    def test_structured_root_causes_precede_raster_tiles(self) -> None:
        reference = self.image("reference.png")
        replica = self.image("replica.png")
        changed = Image.open(replica).convert("RGB")
        changed.putpixel((40, 40), (0, 0, 0))
        changed.save(replica, format="PNG")
        structure = self.root / "structure.json"
        structure.write_text(
            json.dumps({
                "gate": "web_structure_diff",
                "mismatches": [
                    {"kind": "computed_style", "locator": "button#buy", "property": "layout.display", "reference": "flex", "replica": "block"},
                    {"kind": "missing_in_replica", "locator": "span.label", "score": 1000},
                    {"kind": "geometry", "locator": "button#buy", "property": "width", "reference": 100, "replica": 98, "delta": -2},
                    {"kind": "computed_style", "locator": "button#buy", "property": "font.family", "reference": "JD", "replica": "Arial"},
                ],
            }),
            encoding="utf-8",
        )
        report, code = web_pair_analyzer.analyze(
            reference, replica, self.root, structure_path=structure, tile_size=32
        )
        self.assertEqual(code, 2)
        phases = [item["phase"] for item in report["work_queue"][:5]]
        self.assertEqual(phases, ["structure", "geometry", "typography", "style", "raster"])
        self.assertEqual(report["metrics"]["exact_diff_pixels"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
