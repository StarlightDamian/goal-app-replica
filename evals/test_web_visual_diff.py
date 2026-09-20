"""Behavioral tests for the paired screenshot diff gate."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_visual_diff.py"
SPEC = importlib.util.spec_from_file_location("web_visual_diff", SCRIPT)
assert SPEC and SPEC.loader
web_visual_diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_visual_diff)


@unittest.skipIf(Image is None, "Pillow is unavailable")
class WebVisualDiffTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.reference = self.root / "reference.png"
        self.replica = self.root / "replica.png"
        Image.new("RGB", (20, 10), "white").save(self.reference)
        Image.new("RGB", (20, 10), "white").save(self.replica)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def compare(self, masks=None, ratio=0.0):
        mask_path = None
        if masks is not None:
            mask_path = self.root / "masks.json"
            mask_path.write_text(json.dumps({"masks": masks}), encoding="utf-8")
        return web_visual_diff.compare(
            self.reference,
            self.replica,
            self.root,
            self.root / "out",
            16,
            ratio,
            None,
            mask_path,
        )

    def test_identical_images_pass_and_are_hash_bound(self):
        report, exit_code = self.compare()
        self.assertEqual(0, exit_code)
        self.assertTrue(report["ok"])
        self.assertTrue(report["whole_page_pixel_equivalent"])
        self.assertEqual(64, len(report["reference"]["sha256"]))
        self.assertTrue((self.root / report["artifacts"]["overlay"]["path"]).is_file())

    def test_unmasked_difference_fails(self):
        replica = Image.open(self.replica)
        replica.putpixel((2, 2), (0, 0, 0))
        replica.save(self.replica)
        report, exit_code = self.compare()
        self.assertEqual(2, exit_code)
        self.assertFalse(report["ok"])
        self.assertEqual(1, report["metrics"]["diff_pixels"])

    def test_below_threshold_difference_can_pass_visual_but_not_pixel_claim(self):
        replica = Image.open(self.replica)
        replica.putpixel((2, 2), (250, 250, 250))
        replica.save(self.replica)

        report, exit_code = self.compare()

        self.assertEqual(0, exit_code)
        self.assertTrue(report["visual_equivalent_within_threshold"])
        self.assertEqual(0, report["metrics"]["diff_pixels"])
        self.assertEqual(1, report["metrics"]["exact_diff_pixels"])
        self.assertFalse(report["whole_page_pixel_equivalent"])

    def test_mask_requires_deviation_and_never_claims_whole_page(self):
        replica = Image.open(self.replica)
        replica.putpixel((2, 2), (0, 0, 0))
        replica.save(self.replica)
        with self.assertRaises(web_visual_diff.DiffInputError):
            self.compare([{"x": 0, "y": 0, "width": 5, "height": 5}])
        report, exit_code = self.compare(
            [{"x": 0, "y": 0, "width": 5, "height": 5, "deviation_id": "DEV-1"}]
        )
        self.assertEqual(0, exit_code)
        self.assertTrue(report["ok"])
        self.assertEqual("unmasked_regions_only", report["scope"])
        self.assertFalse(report["whole_page_pixel_equivalent"])

    def test_dimension_mismatch_is_invalid(self):
        Image.new("RGB", (21, 10), "white").save(self.replica)
        with self.assertRaises(web_visual_diff.DiffInputError):
            self.compare()


if __name__ == "__main__":
    unittest.main()
