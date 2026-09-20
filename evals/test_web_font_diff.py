"""Tests for actual platform-font usage comparison."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_font_diff.py"
SPEC = importlib.util.spec_from_file_location("web_font_diff", SCRIPT)
assert SPEC and SPEC.loader
web_font_diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_font_diff)


class WebFontDiffTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def usage(self, name: str, family: str = "Arial", *, second_family: str | None = None) -> Path:
        records = [{
            "documentIndex": 0,
            "nodeIndex": 1,
            "locator": "#button",
            "ancestorLocators": ["#card"],
            "paintedVisible": True,
            "fonts": [{"familyName": family, "postScriptName": family, "isCustomFont": False, "glyphCount": 5}],
        }]
        families = [{"familyName": family, "postScriptName": family, "isCustomFont": False, "glyphCount": 5, "nodeCount": 1}]
        if second_family is not None:
            records.append({
                "documentIndex": 0,
                "nodeIndex": 2,
                "locator": "#other",
                "ancestorLocators": ["#page"],
                "paintedVisible": True,
                "fonts": [{"familyName": second_family, "postScriptName": second_family, "isCustomFont": False, "glyphCount": 5}],
            })
            families.append({"familyName": second_family, "postScriptName": second_family, "isCustomFont": False, "glyphCount": 5, "nodeCount": 1})
        path = self.root / name
        path.write_text(json.dumps({
            "schemaVersion": "web-platform-font-usage/1.0",
            "candidateNodeCount": 1,
            "queriedNodeCount": len(records),
            "failedNodeCount": 0,
            "unmappedNodeCount": 0,
            "scanTruncated": False,
            "expectedLocators": [record["locator"] for record in records],
            "expectedRecords": [{"locator": record["locator"], "pseudo": None} for record in records],
            "records": records,
            "families": families,
            "pseudoDeclarations": [],
        }), encoding="utf-8")
        return path

    def test_identical_actual_usage_passes(self) -> None:
        reference = self.usage("reference.json")
        replica = self.usage("replica.json")
        report, code = web_font_diff.compare(reference, replica, self.root, "CMP-home", "#button")
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])

    def test_platform_font_fallback_fails(self) -> None:
        reference = self.usage("reference.json", "JD Sans")
        replica = self.usage("replica.json", "Arial")
        report, code = web_font_diff.compare(reference, replica, self.root, "CMP-home", "#button")
        self.assertEqual(code, 2)
        self.assertEqual(len(report["unexpected_fallbacks"]), 1)

    def test_incomplete_capture_is_invalid(self) -> None:
        reference = self.usage("reference.json")
        replica = self.usage("replica.json")
        payload = json.loads(replica.read_text(encoding="utf-8"))
        payload["failedNodeCount"] = 1
        replica.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(web_font_diff.FontDiffInputError):
            web_font_diff.compare(reference, replica, self.root, "CMP-home", "#button")

    def test_per_node_font_swap_cannot_cancel_in_aggregate(self) -> None:
        reference = self.usage("reference.json", "Arial", second_family="Times")
        replica = self.usage("replica.json", "Times", second_family="Arial")
        report, code = web_font_diff.compare(reference, replica, self.root, "CMP-page", "*")
        self.assertEqual(code, 2)
        self.assertEqual({item["locator"] for item in report["unexpected_fallbacks"]}, {"#button", "#other"})

    def test_component_scope_does_not_use_outside_font_to_cancel(self) -> None:
        reference = self.usage("reference.json", "Arial", second_family="Times")
        replica = self.usage("replica.json", "Times", second_family="Arial")
        report, code = web_font_diff.compare(reference, replica, self.root, "CMP-button", "#button")
        self.assertEqual(code, 2)
        self.assertEqual([item["locator"] for item in report["unexpected_fallbacks"]], ["#button"])

    def test_missing_expected_rendered_text_record_is_invalid(self) -> None:
        reference = self.usage("reference.json")
        replica = self.usage("replica.json")
        payload = json.loads(replica.read_text(encoding="utf-8"))
        payload["records"] = []
        payload["queriedNodeCount"] = 0
        replica.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(web_font_diff.FontDiffInputError):
            web_font_diff.compare(reference, replica, self.root, "CMP-button", "#button")

    def test_pseudo_font_declaration_mismatch_fails(self) -> None:
        reference = self.usage("reference.json")
        replica = self.usage("replica.json")
        for path, family in ((reference, "JD Icon"), (replica, "Arial")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["pseudoDeclarations"] = [{
                "locator": "#button",
                "ancestorLocators": ["#card"],
                "pseudo": "::before",
                "content": "\\e001",
                "font": {"family": family, "style": "normal", "weight": "400", "stretch": "100%"},
            }]
            payload["records"].append({
                "documentIndex": 0,
                "nodeIndex": 3,
                "locator": "#button",
                "pseudo": "::before",
                "ancestorLocators": ["#card"],
                "paintedVisible": True,
                "fonts": [{"familyName": family, "postScriptName": family, "isCustomFont": False, "glyphCount": 1}],
            })
            payload["expectedRecords"].append({"locator": "#button", "pseudo": "::before"})
            payload["queriedNodeCount"] = len(payload["records"])
            path.write_text(json.dumps(payload), encoding="utf-8")
        report, code = web_font_diff.compare(reference, replica, self.root, "CMP-button", "#button")
        self.assertEqual(code, 2)
        self.assertIn("pseudo_font_declaration", {item["kind"] for item in report["unexpected_fallbacks"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
