"""Behavioral tests for actionable Web geometry/style comparison."""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_structure_diff.py"
SPEC = importlib.util.spec_from_file_location("web_structure_diff", SCRIPT)
assert SPEC and SPEC.loader
web_structure_diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_structure_diff)


class WebStructureDiffTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inventory(self, x=10, width=500, display="flex"):
        return {
            "schemaVersion": "web-asset-inventory/1.0",
            "dom": {"scanTruncated": False},
            "visibleElements": [
                {
                    "locator": "#header",
                    "geometry": {"x": x, "y": 20, "width": width, "height": 80},
                    "font": {"family": "Arial", "size": "14px"},
                    "layout": {"display": display, "gap": "16px"},
                    "layer": {"position": "static"},
                    "paint": {"backgroundColor": "rgb(255, 255, 255)"},
                }
            ],
        }

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_identical_structure_passes(self):
        reference = self.write("reference.json", self.inventory())
        replica = self.write("replica.json", self.inventory())
        report, code = web_structure_diff.compare(reference, replica)
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])

    def test_one_pixel_and_style_mismatch_are_ranked(self):
        reference = self.write("reference.json", self.inventory())
        replica = self.write("replica.json", self.inventory(x=11, display="grid"))
        report, code = web_structure_diff.compare(reference, replica, geometry_tolerance=0.5)
        self.assertEqual(code, 2)
        self.assertFalse(report["ok"])
        pairs = {(item["kind"], item.get("property")) for item in report["mismatches"]}
        self.assertIn(("geometry", "x"), pairs)
        self.assertIn(("computed_style", "layout.display"), pairs)

    def test_component_scope_ignores_outside_nodes(self):
        reference_value = self.inventory()
        replica_value = self.inventory()
        reference_value["visibleElements"].append({"locator": "#footer", "geometry": {"x": 0, "y": 900, "width": 100, "height": 20}})
        reference = self.write("reference.json", reference_value)
        replica = self.write("replica.json", replica_value)
        report, code = web_structure_diff.compare(reference, replica, root_locator="#header")
        self.assertEqual(code, 0, report["mismatches"])

    def test_component_scope_includes_unique_child_via_ancestor_locator(self):
        reference_value = self.inventory()
        replica_value = self.inventory()
        reference_value["visibleElements"].append({
            "locator": "span.unique",
            "ancestorLocators": ["#header"],
            "geometry": {"x": 5, "y": 30, "width": 20, "height": 10},
        })
        replica_value["visibleElements"].append({
            "locator": "span.unique",
            "ancestorLocators": ["#header"],
            "geometry": {"x": 50, "y": 30, "width": 20, "height": 10},
        })
        reference = self.write("reference.json", reference_value)
        replica = self.write("replica.json", replica_value)
        report, code = web_structure_diff.compare(reference, replica, root_locator="#header")
        self.assertEqual(code, 2)
        self.assertTrue(any(item["locator"] == "span.unique" for item in report["mismatches"]))

    def test_same_inventory_cannot_masquerade_as_pair(self):
        reference = self.write("reference.json", self.inventory())
        with self.assertRaises(web_structure_diff.DiffError):
            web_structure_diff.compare(reference, reference)

    def test_cli_refuses_output_overwrite(self):
        reference = self.write("reference.json", self.inventory())
        replica = self.write("replica.json", self.inventory())
        with contextlib.redirect_stdout(io.StringIO()):
            code = web_structure_diff.main([
                "--project-root", str(self.root),
                "--reference", str(reference),
                "--replica", str(replica),
                "--output", str(reference),
            ])
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
