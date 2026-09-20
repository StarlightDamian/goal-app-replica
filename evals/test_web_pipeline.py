"""Behavioral tests for the dependency-free Web pipeline."""

from __future__ import annotations

import importlib.util
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_pipeline.py"
GATE_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_fidelity_gate.py"
SPEC = importlib.util.spec_from_file_location("web_pipeline", SCRIPT)
assert SPEC and SPEC.loader
web_pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_pipeline)
GATE_SPEC = importlib.util.spec_from_file_location("web_fidelity_gate_for_pipeline", GATE_SCRIPT)
assert GATE_SPEC and GATE_SPEC.loader
web_fidelity_gate = importlib.util.module_from_spec(GATE_SPEC)
GATE_SPEC.loader.exec_module(web_fidelity_gate)


class WebPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inventory_path = self.root / "probe.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inventory(self):
        return {
            "schemaVersion": "web-asset-inventory/1.0",
            "dom": {"scanTruncated": False, "discoveredElementCount": 4},
            "images": [
                {
                    "tag": "img",
                    "locator": "#hero",
                    "domFingerprint": "fnv1a32:1",
                    "geometry": {"width": 800, "height": 300, "clientRectCount": 1},
                    "src": {"kind": "url", "url": "https://cdn.example.test/hero.jpg?token=never-emit#x"},
                    "currentSrc": {"kind": "url", "url": "https://cdn.example.test/hero@2x.jpg?sig=never-emit"},
                    "srcset": [
                        {"source": {"kind": "url", "url": "https://cdn.example.test/hero-sm.jpg?auth=never-emit"}, "descriptor": "1x"},
                        {"source": {"kind": "url", "url": "https://cdn.example.test/hero-lg.jpg?key=never-emit"}, "descriptor": "2x"},
                    ],
                    "picture": {
                        "sources": [
                            {
                                "srcset": [
                                    {"source": {"kind": "url", "url": "https://cdn.example.test/hero.webp?session=never-emit"}, "descriptor": "1x"}
                                ]
                            }
                        ]
                    },
                }
            ],
            "imageInputs": [],
            "videos": [],
            "sources": [],
            "inlineSvgs": [],
            "svgUses": [],
            "svgExternalReferences": [],
            "cssImages": [],
            "pseudoElements": [],
            "canvases": [],
            "iframes": [],
            "visibleElements": [],
            "fonts": {"faces": [], "visibleFamilyDeclarations": []},
        }

    def write_inventory(self, inventory) -> None:
        self.inventory_path.write_text(json.dumps(inventory), encoding="utf-8")

    def import_result(self):
        return web_pipeline.import_probe(
            self.inventory_path,
            project_id="project-a",
            page_id="home",
            scenario_id="SCN-home",
            baseline_id="BL-1",
            side="reference",
            viewport="1440x900@1",
            state="default",
            rights="explicit_authorized",
        )

    def test_resource_probe_becomes_non_empty_unresolved_manifest(self):
        self.write_inventory(self.inventory())
        result = self.import_result()
        self.assertEqual(result["fidelity"], "pixel")
        self.assertTrue(result["assets"])
        self.assertEqual(result["unresolved_summary"]["asset_count"], len(result["assets"]))
        self.assertEqual(result["unresolved_summary"]["blocker_count"], len(result["assets"]))
        for asset in result["assets"]:
            self.assertTrue(asset["in_scope"])
            self.assertTrue(asset["visible"])
            self.assertEqual(asset["resolution"], "unresolved")
            self.assertEqual(asset["provenance"], "unresolved")
            self.assertTrue(asset["occurrences"])
            self.assertTrue(asset["asset_id"].startswith("AST-"))
            self.assertIn(":", asset["occurrences"][0]["occurrence_id"])
        self.assertEqual(result["inventory_binding"]["discovered_asset_count"], len(result["assets"]))
        self.assertEqual(len(result["inventory_binding"]["sha256"]), 64)

    def test_ancestor_clipped_assets_are_not_treated_as_visible_occurrences(self):
        inventory = self.inventory()
        inventory["images"][0]["paintVisibility"] = {
            "paintedVisible": False,
            "hitTestVisible": False,
            "clippedByAncestors": True,
            "visibleRect": None,
        }
        inventory["cssImages"] = [
            {
                "locator": "#clipped-icon",
                "domFingerprint": "fnv1a32:clipped",
                "geometry": {"width": 14, "height": 14, "clientRectCount": 1},
                "paintVisibility": {
                    "paintedVisible": False,
                    "hitTestVisible": False,
                    "clippedByAncestors": True,
                    "visibleRect": None,
                },
                "properties": {"backgroundImage": "url(https://cdn.example.test/hidden.png)"},
            }
        ]
        inventory["visibleElements"] = [
            {
                "locator": "#clipped-icon",
                "domFingerprint": "fnv1a32:clipped",
                "geometry": {"width": 14, "height": 14, "clientRectCount": 1},
            }
        ]
        self.write_inventory(inventory)

        result = self.import_result()

        self.assertEqual(result["assets"], [])
        self.assertEqual(result["unresolved_summary"]["asset_count"], 0)

    def test_component_scope_excludes_unrelated_page_font_faces(self):
        inventory = self.inventory()
        inventory["visibleElements"] = [
            {
                "locator": "#category",
                "ancestorLocators": ["body", "html"],
                "font": {"family": "'Used Sans', Arial"},
            },
            {
                "locator": "#hero",
                "ancestorLocators": ["body", "html"],
                "font": {"family": "Brand Display"},
            },
        ]
        inventory["fonts"] = {
            "status": "loaded",
            "faces": [
                {"family": "Used Sans", "weight": "400"},
                {"family": "iconfont", "weight": "400"},
                {"family": "Brand Display", "weight": "700"},
            ],
            "visibleFamilyDeclarations": [
                {"family": "'Used Sans', Arial", "visibleElementCount": 1},
                {"family": "iconfont", "visibleElementCount": 1},
                {"family": "Brand Display", "visibleElementCount": 1},
            ],
        }
        inventory["pseudoElements"] = [
            {
                "locator": "#category",
                "ancestorLocators": ["body", "html"],
                "pseudo": "::before",
                "font": {"family": "iconfont"},
            }
        ]

        component = web_pipeline._scoped_inventory(inventory, "CMP-category", "#category")
        self.assertEqual(
            [item["family"] for item in component["fonts"]["faces"]],
            ["Used Sans", "iconfont"],
        )
        self.assertEqual(len(component["fonts"]["visibleFamilyDeclarations"]), 2)

        page = web_pipeline._scoped_inventory(inventory, "PAGE-home", "*")
        self.assertEqual(len(page["fonts"]["faces"]), 3)

    def test_compile_builder_links_scoped_bundle_spec_and_gate(self):
        inventory = self.inventory()
        inventory["images"][0]["locator"] = "img.logo"
        inventory["images"][0]["ancestorLocators"] = ["#header", "body", "html"]
        inventory["visibleElements"] = [
            {
                "tag": "header",
                "locator": "#header",
                "domFingerprint": "fnv1a32:root",
                "geometry": {"x": 0, "y": 0, "width": 1440, "height": 90, "clientRectCount": 1},
                "font": {"family": "Arial", "size": "14px"},
                "layer": {"display": "flex", "position": "static"},
                "paint": {"backgroundColor": "rgb(255, 255, 255)"},
            },
            {
                "tag": "img",
                "locator": "img.logo",
                "ancestorLocators": ["#header", "body", "html"],
                "domFingerprint": "fnv1a32:1",
                "geometry": {"x": 20, "y": 10, "width": 160, "height": 60, "clientRectCount": 1},
                "font": {"family": "Arial", "size": "14px"},
                "layer": {"display": "block", "position": "static"},
                "paint": {"backgroundColor": "rgba(0, 0, 0, 0)"},
            },
        ]
        self.write_inventory(inventory)

        def artifact(name, content):
            path = self.root / name
            path.write_bytes(content)
            return {"path": name, "sha256": hashlib.sha256(content).hexdigest()}

        navigation_fingerprint = "1" * 64
        reference_fingerprint = "2" * 64
        artifacts = {
            "inventory": artifact("probe.json", self.inventory_path.read_bytes()),
            "environment": artifact("environment.json", json.dumps({
                "schemaVersion": "web-capture-environment/1.0",
                "probeViewport": {"innerWidth": 1440, "innerHeight": 900, "devicePixelRatio": 1},
                "navigationFingerprint": navigation_fingerprint,
                "referenceFingerprint": reference_fingerprint,
            }, sort_keys=True).encode("utf-8")),
            "domSnapshot": artifact("dom.json", json.dumps({
                "schemaVersion": "web-dom-render-tree/1.0", "normalizedObservableValuesPersisted": True, "documents": []
            }, sort_keys=True).encode("utf-8")),
            "axTree": artifact("ax.json", json.dumps({
                "schemaVersion": "web-ax-tree-public/1.0", "normalizedObservableValuesPersisted": True, "nodes": []
            }, sort_keys=True).encode("utf-8")),
            "fontUsage": artifact("font-usage.json", json.dumps({
                "schemaVersion": "web-platform-font-usage/1.0", "candidateNodeCount": 0,
                "queriedNodeCount": 0, "failedNodeCount": 0, "unmappedNodeCount": 0,
                "scanTruncated": False, "scopeRoots": ["#header"], "expectedLocators": [],
                "expectedRecords": [], "records": [], "families": [], "pseudoDeclarations": [],
                "budgetExhausted": False, "timedOutNodeCount": 0, "scopeMissing": False,
            }, sort_keys=True).encode("utf-8")),
            "stateContract": artifact("state-contract.json", json.dumps({
                "schemaVersion": "web-capture-state-contract/1.0",
                "expectedPublicLocation": "https://target.example.test/home",
                "document": {"minScrollWidth": 1, "minScrollHeight": 1},
                "selectors": [{"selector": "#header", "minCount": 1, "minVisibleCount": 1, "maxCount": 1, "maxVisibleCount": 1}],
            }, sort_keys=True).encode("utf-8")),
            "stateWitness": artifact("state-witness.json", json.dumps({
                "schemaVersion": "web-capture-state-witness/1.0", "pass": True,
                "phase": "pre", "observedAt": "2026-01-01T00:00:00Z",
                "checks": {"publicLocation": True, "minScrollWidth": True, "minScrollHeight": True, "selectors": True},
                "publicLocation": "https://target.example.test/home",
                "documentMetrics": {"scrollWidth": 1440, "scrollHeight": 900},
                "selectorResults": [{"selector": "#header", "invalidSelector": False, "count": 1, "visibleCount": 1, "pass": True}],
            }, sort_keys=True).encode("utf-8")),
            "stateWitnessPost": artifact("state-witness-post.json", json.dumps({
                "schemaVersion": "web-capture-state-witness/1.0", "pass": True,
                "phase": "post", "observedAt": "2026-01-01T00:00:01Z",
                "checks": {"publicLocation": True, "minScrollWidth": True, "minScrollHeight": True, "selectors": True},
                "publicLocation": "https://target.example.test/home",
                "documentMetrics": {"scrollWidth": 1440, "scrollHeight": 900},
                "selectorResults": [{"selector": "#header", "invalidSelector": False, "count": 1, "visibleCount": 1, "pass": True}],
            }, sort_keys=True).encode("utf-8")),
            "screenshot": artifact("reference.png", base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")),
        }
        bundle_path = self.root / "capture-bundle.json"
        bundle_path.write_text(
            json.dumps({
                "schemaVersion": "web-capture-bundle/2.0",
                "capturedAt": "2026-01-01T00:00:02Z",
                "contentPolicy": "public-observable",
                "context": {
                    "projectId": "project-a", "pageId": "home", "scenarioId": "SCN-home",
                    "baselineId": "BL-1", "viewportId": "1440x900@1", "stateId": "default", "side": "reference",
                },
                "navigationFingerprint": navigation_fingerprint,
                "referenceFingerprint": reference_fingerprint,
                "stateContractSha256": artifacts["stateContract"]["sha256"],
                "stateWitnessSha256": artifacts["stateWitness"]["sha256"],
                "stateWitnessPostSha256": artifacts["stateWitnessPost"]["sha256"],
                "viewport": {"innerWidth": 1440, "innerHeight": 900, "devicePixelRatio": 1},
                "artifacts": artifacts,
            }),
            encoding="utf-8",
        )
        manifest_path = self.root / "builder-manifest.json"
        first = web_pipeline.compile_builder(
            bundle_path,
            project_root=self.root,
            output_path=manifest_path,
            project_id="project-a",
            page_id="home",
            scenario_id="SCN-home",
            baseline_id="BL-1",
            scope_id="CMP-header",
            root_locator="#header",
            viewport="1440x900@1",
            state="default",
            rights="explicit_authorized",
        )
        self.assertEqual(first["scope"]["scope_id"], "CMP-header")
        self.assertEqual(first["component_specs"]["path"], "CMP-header-builder-evidence/component-spec.json")
        self.assertTrue(first["assets"])
        scoped_bundle = json.loads((self.root / first["capture_bundle"]["path"]).read_text(encoding="utf-8"))
        self.assertIn("fontUsage", scoped_bundle["artifacts"])
        self.assertIn("stateWitnessPost", scoped_bundle["artifacts"])

        asset_file = self.root / "hero.bin"
        asset_file.write_bytes(b"authorized exact bytes")
        patch = {
            "schemaVersion": "web-asset-resolution/1.0",
            "assets": {
                asset["asset_id"]: {
                    "rights": "explicit_authorized",
                    "resolution": "exact_captured",
                    "provenance": "captured_original",
                    "local_path": "hero.bin",
                    "sha256": hashlib.sha256(asset_file.read_bytes()).hexdigest(),
                    "evidence_ids": ["EVD-header"],
                }
                for asset in first["assets"]
            },
        }
        patch_path = self.root / "resolution.json"
        patch_path.write_text(json.dumps(patch), encoding="utf-8")
        web_pipeline.compile_builder(
            bundle_path,
            project_root=self.root,
            output_path=manifest_path,
            project_id="project-a",
            page_id="home",
            scenario_id="SCN-home",
            baseline_id="BL-1",
            scope_id="CMP-header",
            root_locator="#header",
            viewport="1440x900@1",
            state="default",
            rights="explicit_authorized",
            resolution_patch=patch_path,
        )
        report, code = web_fidelity_gate.run_gate(manifest_path, self.root, "builder")
        self.assertEqual(code, 0, report["errors"])
        self.assertEqual(report["scope_id"], "CMP-header")

    def test_css_pseudo_and_srcset_sources_are_extracted(self):
        inventory = self.inventory()
        inventory["cssImages"] = [
            {
                "tag": "div",
                "locator": ".card",
                "domFingerprint": "fnv1a32:2",
                "geometry": {"width": 200, "height": 100, "clientRectCount": 1},
                "properties": {
                    "backgroundImage": {
                        "value": "url(redacted)",
                        "sources": [{"kind": "url", "url": "https://cdn.example.test/bg.png?token=nope"}],
                    }
                },
            }
        ]
        inventory["pseudoElements"] = [
            {
                "tag": "button",
                "locator": ".buy",
                "domFingerprint": "fnv1a32:3",
                "geometry": {"width": 20, "height": 20, "clientRectCount": 1},
                "pseudo": "::before",
                "content": {
                    "value": "url(redacted)",
                    "sources": [{"kind": "url", "url": "https://cdn.example.test/content.svg?sig=nope"}],
                },
                "properties": {
                    "maskImage": {
                        "value": "url(redacted)",
                        "sources": [{"kind": "url", "url": "https://cdn.example.test/mask.svg?auth=nope"}],
                    }
                },
            }
        ]
        self.write_inventory(inventory)
        result = self.import_result()
        refs = {asset["source_ref"] for asset in result["assets"]}
        responsive_refs = {
            candidate["source_ref"]
            for asset in result["assets"]
            for candidate in asset.get("responsive_candidates", [])
        }
        self.assertIn("https://cdn.example.test/bg.png", refs)
        self.assertIn("https://cdn.example.test/content.svg", refs)
        self.assertIn("https://cdn.example.test/mask.svg", refs)
        self.assertIn("https://cdn.example.test/hero-sm.jpg", responsive_refs)
        self.assertIn("https://cdn.example.test/hero-lg.jpg", responsive_refs)

    def test_scan_truncated_is_rejected_with_explicit_exit_code(self):
        inventory = self.inventory()
        inventory["dom"]["scanTruncated"] = True
        self.write_inventory(inventory)
        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "import-probe",
                "--inventory",
                str(self.inventory_path),
                "--project-id",
                "project-a",
                "--page-id",
                "home",
                "--scenario-id",
                "SCN-home",
                "--baseline-id",
                "BL-1",
                "--side",
                "reference",
                "--viewport",
                "1440x900@1",
                "--state",
                "default",
                "--rights",
                "explicit_authorized",
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(process.returncode, web_pipeline.EXIT_TRUNCATED)
        report = json.loads(process.stdout)
        self.assertEqual(report["error"]["code"], "scan_truncated")
        self.assertEqual(report["exit_code"], web_pipeline.EXIT_TRUNCATED)

    def test_query_credentials_and_tokens_never_leak(self):
        inventory = self.inventory()
        inventory["images"][0]["src"] = {
            "kind": "url",
            "url": "https://username:password@cdn.example.test/private.png?access_token=TOP_SECRET&sig=SIGNED_VALUE#fragment",
        }
        inventory["images"][0]["currentSrc"] = None
        self.write_inventory(inventory)
        encoded = json.dumps(self.import_result(), ensure_ascii=False)
        for forbidden in ("username", "password", "TOP_SECRET", "SIGNED_VALUE", "access_token="):
            self.assertNotIn(forbidden, encoded)
        self.assertIn("https://cdn.example.test/private.png", encoded)

    def test_occurrences_exactly_match_gate_derivation_and_fonts_are_global(self):
        inventory = self.inventory()
        visible_geometry = {"width": 32, "height": 24, "clientRectCount": 1}
        inventory["imageInputs"] = [
            {
                "domFingerprint": "fp-input",
                "geometry": visible_geometry,
                "currentSrc": None,
                "src": {"kind": "url", "url": "https://cdn.example.test/input.png?token=hidden"},
            }
        ]
        inventory["videos"] = [
            {
                "domFingerprint": "fp-video",
                "geometry": visible_geometry,
                "currentSrc": {"kind": "url", "url": "https://cdn.example.test/current.mp4?sig=hidden"},
                "src": {"kind": "url", "url": "https://cdn.example.test/fallback.mp4"},
                "poster": {"kind": "url", "url": "https://cdn.example.test/poster.jpg"},
                "sources": [
                    {"src": {"kind": "url", "url": "https://cdn.example.test/alternate.mp4"}, "srcset": []}
                ],
            }
        ]
        inventory["inlineSvgs"] = [
            {"domFingerprint": "fp-inline", "geometry": visible_geometry, "sanitizedMarkupFingerprint": "fnv1a32:a"}
        ]
        inventory["svgUses"] = [
            {
                "domFingerprint": "fp-use",
                "geometry": visible_geometry,
                "source": {"kind": "url", "url": "https://cdn.example.test/sprite.svg?token=hidden"},
                "fragmentTarget": "cart",
            }
        ]
        inventory["svgExternalReferences"] = [
            {"domFingerprint": "fp-external", "geometry": visible_geometry, "source": None}
        ]
        inventory["canvases"] = [
            {"domFingerprint": "fp-canvas", "geometry": visible_geometry, "bitmapWidth": 64, "bitmapHeight": 48}
        ]
        inventory["iframes"] = [
            {
                "domFingerprint": "fp-iframe",
                "geometry": visible_geometry,
                "src": {"kind": "url", "url": "https://frame.example.test/page?session=hidden"},
            }
        ]
        inventory["cssImages"] = [
            {
                "domFingerprint": "fp-css",
                "geometry": visible_geometry,
                "properties": {
                    "backgroundImage": {
                        "value": "images",
                        "sources": [
                            {"kind": "url", "url": "https://cdn.example.test/a.png"},
                            {"kind": "blocked", "scheme": "javascript"},
                            {"kind": "data", "mediaType": "image/png"},
                        ],
                    }
                },
            }
        ]
        inventory["pseudoElements"] = [
            {
                "domFingerprint": "fp-pseudo",
                "geometry": None,
                "properties": {
                    "maskImage": {
                        "value": "url(mask)",
                        "sources": [{"kind": "url", "url": "https://cdn.example.test/mask.svg"}],
                    }
                },
                "content": {"value": "glyph"},
            }
        ]
        inventory["visibleElements"] = [{"domFingerprint": "fp-pseudo"}]
        inventory["fonts"] = {
            "status": "loaded",
            "faces": [{"family": "Replica Sans", "weight": "400"}],
            "visibleFamilyDeclarations": [{"family": "Replica Sans", "visibleElementCount": 2}],
        }
        self.write_inventory(inventory)
        result = self.import_result()

        expected = web_fidelity_gate._derive_inventory_occurrence_ids(inventory)
        actual = {
            occurrence["occurrence_id"]
            for asset in result["assets"]
            for occurrence in asset["occurrences"]
        }
        occurrence_list = [
            occurrence["occurrence_id"]
            for asset in result["assets"]
            for occurrence in asset["occurrences"]
        ]
        self.assertEqual(actual, expected)
        self.assertEqual(len(occurrence_list), len(actual))
        self.assertNotIn("font", {asset["kind"] for asset in result["assets"]})
        self.assertEqual(result["metadata"]["global_fonts"]["status"], "UNRESOLVED")
        self.assertEqual(
            [item["code"] for item in result["blockers"]].count("global_font_resolution_required"),
            1,
        )
        image_content = next(
            asset for asset in result["assets"] if any(item["occurrence_id"] == "images:fnv1a32:1:content" for item in asset["occurrences"])
        )
        self.assertEqual(image_content["source_ref"], "https://cdn.example.test/hero@2x.jpg")

    def test_same_input_is_deterministic_and_capture_plan_is_cartesian(self):
        self.write_inventory(self.inventory())
        first = self.import_result()
        second = self.import_result()
        self.assertEqual(first, second)
        plan = web_pipeline.capture_plan(
            project_id="project-a",
            page_id="home",
            scenario_id="SCN-home",
            baseline_id="BL-1",
            viewports=["1440x900@1", "390x844@3"],
            states=["default", "hover"],
        )
        self.assertEqual(len(plan["matrix"]), 4)
        self.assertEqual(plan["summary"]["capture_count"], 8)
        self.assertTrue(all(set(item) >= {"reference", "replica", "comparison"} for item in plan["matrix"]))


if __name__ == "__main__":
    unittest.main()
