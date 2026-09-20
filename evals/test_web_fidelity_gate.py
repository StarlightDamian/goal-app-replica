"""Behavioral tests for the dependency-free Web fidelity gate."""

from __future__ import annotations

import hashlib
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_fidelity_gate.py"
SPEC = importlib.util.spec_from_file_location("web_fidelity_gate", SCRIPT)
assert SPEC and SPEC.loader
web_fidelity_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_fidelity_gate)


class WebFidelityGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        (self.root / "assets").mkdir()
        self.asset_path = self.root / "assets" / "logo.bin"
        self.asset_path.write_bytes(b"captured logo bytes")
        self.asset_hash = hashlib.sha256(self.asset_path.read_bytes()).hexdigest()
        self.manifest_path = self.root / "fidelity-manifest.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def good_manifest(self):
        return {
            "schema_version": 1,
            "required_viewports": [
                {"id": "desktop-1440x900", "kind": "desktop", "covered": True},
                {"id": "mobile-390x844", "kind": "mobile", "covered": True},
            ],
            "required_states": [
                {"id": "default", "covered": True},
                {"id": "hover", "covered": True},
            ],
            "font_fallback": {"checked": True, "pass": True, "unexpected_fallbacks": []},
            "critical_diffs": [
                {"component_id": "home-default-desktop", "critical": True, "pass": True},
                {"component_id": "home-default-mobile", "critical": True, "pass": True},
            ],
            "assets": [
                {
                    "asset_id": "logo",
                    "kind": "image",
                    "in_scope": True,
                    "visible": True,
                    "rights": "explicit_authorized",
                    "resolution": "exact_captured",
                    "provenance": "captured_original",
                    "evidence_ids": ["EVD-LOGO-1"],
                    "local_path": "assets/logo.bin",
                    "sha256": self.asset_hash,
                    "source_ref": "https://public.example.test/assets/logo",
                }
            ],
        }

    def artifact(self, relative_path: str, content: bytes):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {
            "path": relative_path,
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def strong_manifest(self):
        hero_element = {
            "locator": "img#hero",
            "geometry": {"x": 0, "y": 0, "width": 320, "height": 180},
            "layout": {"display": "block"},
            "paint": {"backgroundColor": "rgba(0, 0, 0, 0)"},
        }
        inventory = {
            "schemaVersion": "web-asset-inventory/1.0",
            "dom": {"scanTruncated": False},
            "images": [
                {
                    "locator": "img#hero",
                    "currentSrc": {"kind": "url", "url": "https://public.example.test/hero.png"},
                    "geometry": {"width": 320, "height": 180, "clientRectCount": 1},
                }
            ],
            "imageInputs": [],
            "videos": [],
            "inlineSvgs": [],
            "svgUses": [],
            "svgExternalReferences": [],
            "cssImages": [],
            "pseudoElements": [],
            "visibleElements": [hero_element],
            "canvases": [],
            "iframes": [],
        }
        inventory_bytes = json.dumps(inventory, sort_keys=True).encode("utf-8")
        probe = self.artifact("evidence/probe-inventory.json", inventory_bytes)
        png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
        screenshot = self.artifact("evidence/reference.png", png)
        style = self.artifact("evidence/reference-style.json", b"{}")
        component_specs = self.artifact(
            "evidence/component-specs.json",
            json.dumps(
                {
                    "schemaVersion": "web-component-spec/1.0",
                    "component_id": "CMP-home",
                    "scope": {"scope_id": "CMP-home", "kind": "component", "root_locator": "img#hero"},
                    "source_inventory": probe,
                    "viewport": "desktop-1440x900",
                    "states": ["default"],
                    "capture_context": {
                        "projectId": "project-1", "pageId": "home", "scenarioId": "SCN-home",
                        "baselineId": "BL-home", "viewportId": "desktop-1440x900",
                        "stateId": "default", "side": "reference",
                    },
                    "elements": [hero_element],
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        replica = self.artifact("evidence/replica.png", png)
        reference_stability_sample = self.artifact("evidence/reference-stability-sample.png", png)
        replica_stability_sample = self.artifact("evidence/replica-stability-sample.png", png)
        reference_stability = self.artifact(
            "evidence/reference-stability.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "gate": "web_stability_gate",
                    "status": "pass",
                    "ok": True,
                    "mode": "pixel",
                    "side": "reference",
                    "scope_id": "CMP-home",
                    "thresholds": {"channel_threshold": 0, "max_diff_ratio": 0.0},
                    "samples": [reference_stability_sample, screenshot],
                    "comparisons": [
                        {"left_index": 0, "right_index": 1, "pass": True, "dimension_mismatch": False, "pixels": 1, "exact_diff_pixels": 0, "diff_pixels": 0, "diff_ratio": 0.0}
                    ],
                    "stable_consecutive_pair": [0, 1],
                    "canonical": screenshot,
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        replica_stability = self.artifact(
            "evidence/replica-stability.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "gate": "web_stability_gate",
                    "status": "pass",
                    "ok": True,
                    "mode": "pixel",
                    "side": "replica",
                    "scope_id": "CMP-home",
                    "thresholds": {"channel_threshold": 0, "max_diff_ratio": 0.0},
                    "samples": [replica_stability_sample, replica],
                    "comparisons": [
                        {"left_index": 0, "right_index": 1, "pass": True, "dimension_mismatch": False, "pixels": 1, "exact_diff_pixels": 0, "diff_pixels": 0, "diff_ratio": 0.0}
                    ],
                    "stable_consecutive_pair": [0, 1],
                    "canonical": replica,
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        overlay = self.artifact("evidence/overlay.png", b"overlay bytes")
        diff_image = self.artifact("evidence/diff.png", b"diff bytes")
        diff_report = self.artifact(
            "evidence/diff-report.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "gate": "web_visual_diff",
                    "status": "pass",
                    "ok": True,
                    "scope": "whole_image",
                    "whole_page_pixel_equivalent": True,
                    "reference": screenshot,
                    "replica": replica,
                    "image": {"width": 1, "height": 1, "pixels": 1},
                    "thresholds": {"channel_threshold": 16, "max_diff_ratio": 0.0, "max_diff_pixels": None},
                    "metrics": {"diff_pixels": 0, "exact_diff_pixels": 0, "diff_ratio": 0.0, "compared_pixels": 1, "masked_pixels": 0},
                    "masks": [],
                    "artifacts": {"overlay": overlay, "diff": diff_image},
                },
                sort_keys=True,
            ).encode("utf-8"),
        )

        manifest = self.good_manifest()
        manifest.update(
            {
                "fidelity": "pixel",
                "enforcement_mode": "capture_bundle_v2",
                "project_id": "project-1",
                "page_id": "home",
                "scenario_id": "SCN-home",
                "baseline_id": "BL-home",
                "scope": {"scope_id": "CMP-home", "kind": "component", "root_locator": "img#hero"},
                "probe_inventory": probe,
                "component_specs": component_specs,
                "required_viewports": [
                    {
                        "id": "desktop-1440x900",
                        "kind": "desktop",
                        "reference_capture": {
                            "artifacts": [
                                dict(screenshot, kind="screenshot"),
                                dict(style, kind="style"),
                            ]
                        },
                    },
                ],
                "required_states": [
                    {
                        "id": "default",
                        "reference_capture": {
                            "artifacts": [
                                dict(screenshot, kind="screenshot"),
                                dict(probe, kind="probe"),
                            ]
                        },
                    },
                ],
                "critical_diffs": [
                    {
                        "component_id": "home-default-desktop",
                        "pass": True,
                        "reference_screenshot": screenshot,
                        "replica_screenshot": replica,
                        "reference_stability": reference_stability,
                        "replica_stability": replica_stability,
                        "overlay": overlay,
                        "diff_report": diff_report,
                    }
                ],
            }
        )
        manifest.pop("covered_viewports", None)
        manifest.pop("covered_states", None)
        manifest["assets"][0]["occurrences"] = [
            {"occurrence_id": "images:img#hero:content"}
        ]
        navigation_fingerprint = "1" * 64
        reference_fingerprint = "2" * 64
        environment = self.artifact(
            "evidence/environment.json",
            json.dumps({
                "schemaVersion": "web-capture-environment/1.0",
                "probeViewport": {"innerWidth": 1440, "innerHeight": 900, "devicePixelRatio": 1},
                "navigationFingerprint": navigation_fingerprint,
                "referenceFingerprint": reference_fingerprint,
            }, sort_keys=True).encode("utf-8"),
        )
        dom_snapshot = self.artifact(
            "evidence/dom-snapshot.json",
            json.dumps({"schemaVersion": "web-dom-render-tree/1.0", "normalizedObservableValuesPersisted": True, "documents": []}, sort_keys=True).encode("utf-8"),
        )
        ax_tree = self.artifact(
            "evidence/ax-tree.json",
            json.dumps({"schemaVersion": "web-ax-tree-public/1.0", "normalizedObservableValuesPersisted": True, "nodes": []}, sort_keys=True).encode("utf-8"),
        )
        state_contract = self.artifact(
            "evidence/state-contract.json",
            json.dumps({
                "schemaVersion": "web-capture-state-contract/1.0",
                "expectedPublicLocation": "https://target.example.test/home",
                "document": {"minScrollWidth": 1, "minScrollHeight": 1},
                "selectors": [{"selector": "img#hero", "minCount": 1, "minVisibleCount": 1, "maxCount": None, "maxVisibleCount": None}],
            }, sort_keys=True).encode("utf-8"),
        )
        state_witness = self.artifact(
            "evidence/state-witness.json",
            json.dumps({
                "schemaVersion": "web-capture-state-witness/1.0", "pass": True,
                "phase": "pre", "observedAt": "2026-01-01T00:00:00Z",
                "checks": {"publicLocation": True, "minScrollWidth": True, "minScrollHeight": True, "selectors": True},
                "publicLocation": "https://target.example.test/home", "documentMetrics": {"scrollWidth": 1440, "scrollHeight": 900},
                "selectorResults": [{"selector": "img#hero", "invalidSelector": False, "count": 1, "visibleCount": 1, "pass": True}],
            }, sort_keys=True).encode("utf-8"),
        )
        state_witness_post = self.artifact(
            "evidence/state-witness-post.json",
            json.dumps({
                "schemaVersion": "web-capture-state-witness/1.0", "pass": True,
                "phase": "post", "observedAt": "2026-01-01T00:00:01Z",
                "checks": {"publicLocation": True, "minScrollWidth": True, "minScrollHeight": True, "selectors": True},
                "publicLocation": "https://target.example.test/home", "documentMetrics": {"scrollWidth": 1440, "scrollHeight": 900},
                "selectorResults": [{"selector": "img#hero", "invalidSelector": False, "count": 1, "visibleCount": 1, "pass": True}],
            }, sort_keys=True).encode("utf-8"),
        )
        font_usage_payload = {
            "schemaVersion": "web-platform-font-usage/1.0",
            "candidateNodeCount": 1,
            "queriedNodeCount": 1,
            "failedNodeCount": 0,
            "unmappedNodeCount": 0,
            "scanTruncated": False,
            "expectedLocators": ["img#hero"],
            "expectedRecords": [{"locator": "img#hero", "pseudo": None}],
            "records": [{
                "documentIndex": 0,
                "nodeIndex": 1,
                "locator": "img#hero",
                "ancestorLocators": [],
                "paintedVisible": True,
                "fonts": [{"familyName": "Arial", "postScriptName": "Arial", "isCustomFont": False, "glyphCount": 4}],
            }],
            "families": [{"familyName": "Arial", "postScriptName": "Arial", "isCustomFont": False, "glyphCount": 4, "nodeCount": 1}],
            "pseudoDeclarations": [],
            "scopeRoots": ["img#hero"],
            "budgetExhausted": False,
            "timedOutNodeCount": 0,
            "scopeMissing": False,
        }
        reference_font_usage = self.artifact(
            "evidence/reference-font-usage.json", json.dumps(font_usage_payload, sort_keys=True).encode("utf-8")
        )
        replica_font_usage = self.artifact(
            "evidence/replica-font-usage.json", json.dumps(font_usage_payload, sort_keys=True).encode("utf-8")
        )
        replica_probe = self.artifact(
            "evidence/replica-inventory.json", (self.root / probe["path"]).read_bytes()
        )
        context = {
            "projectId": "project-1", "pageId": "home", "scenarioId": "SCN-home",
            "baselineId": "BL-home", "viewportId": "desktop-1440x900",
            "stateId": "default", "side": "reference",
        }
        bundle = {
            "schemaVersion": "web-capture-bundle/2.0",
            "capturedAt": "2026-01-01T00:00:02Z",
            "contentPolicy": "public-observable",
            "context": context,
            "navigationFingerprint": navigation_fingerprint,
            "referenceFingerprint": reference_fingerprint,
            "stateContractSha256": state_contract["sha256"],
            "stateWitnessSha256": state_witness["sha256"],
            "stateWitnessPostSha256": state_witness_post["sha256"],
            "viewport": {"innerWidth": 1440, "innerHeight": 900, "devicePixelRatio": 1},
            "artifacts": {
                "inventory": dict(probe), "environment": environment, "domSnapshot": dom_snapshot,
                "axTree": ax_tree, "fontUsage": reference_font_usage, "stateContract": state_contract, "stateWitness": state_witness, "stateWitnessPost": state_witness_post, "screenshot": dict(screenshot),
            },
        }
        bundle_ref = self.artifact("evidence/capture-bundle.json", json.dumps(bundle, sort_keys=True).encode("utf-8"))
        manifest["capture_bundle"] = bundle_ref
        def side_bundle(relative_path, screenshot_ref, side, navigation_fingerprint):
            side_context = dict(context)
            side_context["side"] = side
            payload = {
                "schemaVersion": "web-capture-bundle/2.0",
                "capturedAt": "2026-01-01T00:00:02Z",
                "contentPolicy": "public-observable",
                "context": side_context,
                "navigationFingerprint": navigation_fingerprint,
                "referenceFingerprint": reference_fingerprint if side == "reference" else "3" * 64,
                "stateContractSha256": state_contract["sha256"],
                "stateWitnessSha256": state_witness["sha256"],
                "stateWitnessPostSha256": state_witness_post["sha256"],
                "viewport": {"innerWidth": 1440, "innerHeight": 900, "devicePixelRatio": 1},
                "artifacts": {
                    "inventory": dict(probe) if side == "reference" else dict(replica_probe), "environment": environment, "domSnapshot": dom_snapshot,
                    "axTree": ax_tree,
                    "stateContract": state_contract, "stateWitness": state_witness, "stateWitnessPost": state_witness_post,
                    "fontUsage": reference_font_usage if side == "reference" else replica_font_usage,
                    "screenshot": dict(screenshot_ref),
                },
            }
            return self.artifact(relative_path, json.dumps(payload, sort_keys=True).encode("utf-8"))

        reference_sample_bundle = side_bundle(
            "evidence/reference-stability-sample-bundle.json", reference_stability_sample, "reference", "4" * 64
        )
        replica_sample_bundle = side_bundle(
            "evidence/replica-stability-sample-bundle.json", replica_stability_sample, "replica", "5" * 64
        )
        replica_bundle = side_bundle(
            "evidence/replica-capture-bundle.json", replica, "replica", "6" * 64
        )
        for report_ref, capture_refs in (
            (reference_stability, [reference_sample_bundle, bundle_ref]),
            (replica_stability, [replica_sample_bundle, replica_bundle]),
        ):
            report_path = self.root / report_ref["path"]
            stability_payload = json.loads(report_path.read_text(encoding="utf-8"))
            stability_payload["capture_bundles"] = capture_refs
            report_path.write_text(json.dumps(stability_payload, sort_keys=True), encoding="utf-8")
            report_ref["sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        manifest["critical_diffs"][0].update({
            "viewport_id": "desktop-1440x900",
            "state_id": "default",
            "reference_capture_bundle": bundle_ref,
            "replica_capture_bundle": replica_bundle,
        })
        font_report = self.artifact(
            "evidence/font-report.json",
            json.dumps({
                "schema_version": 1,
                "gate": "web_font_fallback",
                "status": "pass",
                "ok": True,
                "scope_id": "CMP-home",
                "root_locator": "img#hero",
                "reference": reference_font_usage,
                "replica": replica_font_usage,
                "reference_summary": {"queriedNodeCount": 1, "familyCount": 1},
                "replica_summary": {"queriedNodeCount": 1, "familyCount": 1},
                "unexpected_fallbacks": [],
            }, sort_keys=True).encode("utf-8"),
        )
        manifest["critical_diffs"][0]["font_report"] = font_report
        structure_report = self.artifact(
            "evidence/structure-report.json",
            json.dumps({
                "schema_version": 1,
                "gate": "web_structure_diff",
                "status": "pass",
                "ok": True,
                "scope": {"root_locator": "img#hero"},
                "reference": dict(probe),
                "replica": dict(replica_probe),
                "thresholds": {"geometry_tolerance_css_px": 0.5},
                "summary": {"mismatch_count": 0},
                "mismatches": [],
            }, sort_keys=True).encode("utf-8"),
        )
        manifest["critical_diffs"][0]["structure_report"] = structure_report
        manifest["reference_fingerprint"] = reference_fingerprint
        for collection in ("required_viewports", "required_states"):
            manifest[collection][0]["reference_capture"]["artifacts"].insert(0, dict(bundle_ref, kind="capture-bundle"))
        return manifest

    def capture_bundle_manifest(self):
        manifest = self.strong_manifest()
        return manifest

    def refresh_bundle(self, manifest, bundle=None) -> None:
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        if bundle is None:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            bundle["artifacts"]["inventory"] = dict(manifest["probe_inventory"])
        bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        manifest["capture_bundle"]["sha256"] = digest
        for collection in ("required_viewports", "required_states"):
            for entry in manifest[collection]:
                for artifact in entry["reference_capture"]["artifacts"]:
                    if artifact["path"] == manifest["capture_bundle"]["path"]:
                        artifact["sha256"] = digest

    def browser_capture_bundle(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        context_fingerprint = hashlib.sha256(
            json.dumps(bundle["context"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        receipt = {
            "schemaVersion": "web-capture-source-receipt/1.0",
            "receiptId": "receipt-1",
            "adapter": "browser-control-in-app",
            "sessionAliasHash": "a" * 64,
            "tabIdentityHash": "b" * 64,
            "expectedPublicLocation": "https://target.example.test/home",
            "contextFingerprint": context_fingerprint,
            "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2026-01-01T00:30:00Z",
            "preStateWitnessSha256": bundle["stateWitnessSha256"],
            "postStateWitnessSha256": bundle["stateWitnessPostSha256"],
        }
        receipt_ref = self.artifact(
            "evidence/source-receipt.json",
            json.dumps(receipt, sort_keys=True).encode("utf-8"),
        )
        bundle["captureMode"] = "read-only-supported-browser-tab"
        bundle["sourceReceiptSha256"] = receipt_ref["sha256"]
        bundle["artifacts"]["sourceReceipt"] = receipt_ref
        self.refresh_bundle(manifest, bundle)
        return manifest, bundle, receipt

    def test_capture_bundle_rejects_fake_json_and_non_png_artifacts(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        fake_environment = self.artifact("evidence/fake-environment.json", b"{}")
        fake_screenshot = self.artifact("evidence/fake-reference.png", b"not a png")
        bundle["artifacts"]["environment"] = fake_environment
        bundle["artifacts"]["screenshot"] = fake_screenshot
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("capture_artifact_schema_invalid", codes)
        self.assertIn("capture_screenshot_invalid", codes)

    def test_capture_bundle_rejects_failed_page_state_witness(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        witness_path = self.root / bundle["artifacts"]["stateWitness"]["path"]
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        witness["pass"] = False
        witness["checks"]["selectors"] = False
        witness_path.write_text(json.dumps(witness, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(witness_path.read_bytes()).hexdigest()
        bundle["artifacts"]["stateWitness"]["sha256"] = digest
        bundle["stateWitnessSha256"] = digest
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_state_witness_failed", self.error_codes(report))

    def test_capture_bundle_recomputes_self_reported_state_witness(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        witness_path = self.root / bundle["artifacts"]["stateWitness"]["path"]
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        witness["selectorResults"][0].update({"count": 0, "visibleCount": 0, "pass": True})
        witness["pass"] = True
        witness_path.write_text(json.dumps(witness, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(witness_path.read_bytes()).hexdigest()
        bundle["artifacts"]["stateWitness"]["sha256"] = digest
        bundle["stateWitnessSha256"] = digest
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_state_witness_selector_mismatch", self.error_codes(report))

    def test_capture_bundle_recomputes_post_state_witness(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        witness_path = self.root / bundle["artifacts"]["stateWitnessPost"]["path"]
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        witness["selectorResults"][0].update({"count": 0, "visibleCount": 0, "pass": True})
        witness_path.write_text(json.dumps(witness, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(witness_path.read_bytes()).hexdigest()
        bundle["artifacts"]["stateWitnessPost"]["sha256"] = digest
        bundle["stateWitnessPostSha256"] = digest
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_state_witness_selector_mismatch", self.error_codes(report))

    def test_browser_receipt_rejects_expiry_and_invalid_identity_hashes(self):
        cases = (
            ("expiresAt", "2025-12-31T23:59:59Z", "capture_source_receipt_time_invalid"),
            ("sessionAliasHash", "not-a-hash", "capture_source_receipt_invalid"),
            ("tabIdentityHash", "not-a-hash", "capture_source_receipt_invalid"),
        )
        for field, value, expected_code in cases:
            with self.subTest(field=field):
                manifest, bundle, receipt = self.browser_capture_bundle()
                receipt[field] = value
                receipt_path = self.root / bundle["artifacts"]["sourceReceipt"]["path"]
                receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
                digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                bundle["artifacts"]["sourceReceipt"]["sha256"] = digest
                bundle["sourceReceiptSha256"] = digest
                self.refresh_bundle(manifest, bundle)
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn(expected_code, self.error_codes(report))

    def test_capture_bundle_rejects_missing_font_scope(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        usage_path = self.root / bundle["artifacts"]["fontUsage"]["path"]
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        usage["scopeMissing"] = True
        usage_path.write_text(json.dumps(usage, sort_keys=True), encoding="utf-8")
        bundle["artifacts"]["fontUsage"]["sha256"] = hashlib.sha256(usage_path.read_bytes()).hexdigest()
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_font_usage_incomplete", self.error_codes(report))

    def test_capture_bundle_requires_independent_post_witness(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        del bundle["artifacts"]["stateWitnessPost"]
        del bundle["stateWitnessPostSha256"]
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_bundle_artifact_missing", self.error_codes(report))

    def test_capture_bundle_rejects_font_scope_and_budget_bypass(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        usage_path = self.root / bundle["artifacts"]["fontUsage"]["path"]
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        usage.update({"scopeRoots": ["#wrong"], "budgetExhausted": True, "timedOutNodeCount": 1})
        usage_path.write_text(json.dumps(usage, sort_keys=True), encoding="utf-8")
        bundle["artifacts"]["fontUsage"]["sha256"] = hashlib.sha256(usage_path.read_bytes()).hexdigest()
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("capture_font_scope_mismatch", codes)
        self.assertIn("capture_font_usage_incomplete", codes)

    def test_supported_browser_receipt_is_recomputed_against_bundle(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["captureMode"] = "read-only-supported-browser-tab"
        context_fingerprint = hashlib.sha256(json.dumps(bundle["context"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        receipt = self.artifact("evidence/source-receipt.json", json.dumps({
            "schemaVersion": "web-capture-source-receipt/1.0", "receiptId": "r", "adapter": "browser-control-in-app",
            "sessionAliasHash": "a" * 64, "tabIdentityHash": "b" * 64,
            "expectedPublicLocation": "https://wrong.example.test/home", "contextFingerprint": context_fingerprint,
            "preStateWitnessSha256": "c" * 64, "postStateWitnessSha256": "d" * 64,
            "issuedAt": "2025-12-31T23:59:59Z", "expiresAt": "2026-01-01T00:00:59Z",
        }, sort_keys=True).encode("utf-8"))
        bundle["artifacts"]["sourceReceipt"] = receipt
        bundle["sourceReceiptSha256"] = receipt["sha256"]
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("capture_source_receipt_location_mismatch", codes)
        self.assertIn("capture_source_receipt_witness_mismatch", codes)

    def test_pixel_capture_rejects_redacted_or_mismatched_context(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["contentPolicy"] = "redacted"
        bundle["context"]["scenarioId"] = "SCN-other"
        self.refresh_bundle(manifest, bundle)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("capture_bundle_content_policy_insufficient", codes)
        self.assertIn("capture_bundle_context_mismatch", codes)

    def test_component_spec_cannot_invent_or_modify_inventory_elements(self):
        manifest = self.capture_bundle_manifest()
        spec_path = self.root / manifest["component_specs"]["path"]
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        spec["elements"][0]["geometry"]["width"] = 999
        spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")
        manifest["component_specs"]["sha256"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("component_spec_element_mismatch", self.error_codes(report))

    def write_manifest(self, manifest) -> None:
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def run_direct(self, manifest):
        self.write_manifest(manifest)
        return web_fidelity_gate.run_gate(self.manifest_path, self.root)

    def error_codes(self, report):
        return {entry["code"] for entry in report["errors"]}

    def test_passing_manifest_and_cli_json_contract(self):
        self.write_manifest(self.good_manifest())
        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--manifest",
                str(self.manifest_path),
                "--project-root",
                str(self.root),
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["assets_checked"], 1)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(self.manifest_path.read_bytes()).hexdigest())

    def test_complete_strong_manifest_passes(self):
        manifest = self.strong_manifest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 0, report["errors"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(self.manifest_path.read_bytes()).hexdigest())

    def test_pixel_qa_requires_both_side_stability_reports(self):
        manifest = self.strong_manifest()
        del manifest["critical_diffs"][0]["reference_stability"]
        del manifest["critical_diffs"][0]["replica_stability"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("stability_evidence_missing", self.error_codes(report))

    def test_pixel_qa_requires_replica_capture_bundle(self):
        manifest = self.strong_manifest()
        del manifest["critical_diffs"][0]["replica_capture_bundle"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("replica_capture_bundle_missing", self.error_codes(report))

    def test_pixel_qa_requires_actual_font_report(self):
        manifest = self.strong_manifest()
        del manifest["critical_diffs"][0]["font_report"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("font_report_missing", self.error_codes(report))

    def test_pixel_qa_requires_structure_report(self):
        manifest = self.strong_manifest()
        del manifest["critical_diffs"][0]["structure_report"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("structure_report_missing", self.error_codes(report))

    def test_pixel_qa_recomputes_structure_report(self):
        manifest = self.strong_manifest()
        diff = manifest["critical_diffs"][0]
        structure_ref = diff["structure_report"]
        structure_path = self.root / structure_ref["path"]
        structure = json.loads(structure_path.read_text(encoding="utf-8"))
        replica_inventory_ref = structure["replica"]
        replica_inventory_path = self.root / replica_inventory_ref["path"]
        replica_inventory = json.loads(replica_inventory_path.read_text(encoding="utf-8"))
        replica_inventory["visibleElements"][0]["geometry"]["x"] += 2
        replica_inventory_path.write_text(json.dumps(replica_inventory, sort_keys=True), encoding="utf-8")
        replica_inventory_ref["sha256"] = hashlib.sha256(replica_inventory_path.read_bytes()).hexdigest()
        structure_path.write_text(json.dumps(structure, sort_keys=True), encoding="utf-8")
        structure_ref["sha256"] = hashlib.sha256(structure_path.read_bytes()).hexdigest()

        replica_bundle_ref = diff["replica_capture_bundle"]
        replica_bundle_path = self.root / replica_bundle_ref["path"]
        replica_bundle = json.loads(replica_bundle_path.read_text(encoding="utf-8"))
        replica_bundle["artifacts"]["inventory"] = replica_inventory_ref
        replica_bundle_path.write_text(json.dumps(replica_bundle, sort_keys=True), encoding="utf-8")
        replica_bundle_ref["sha256"] = hashlib.sha256(replica_bundle_path.read_bytes()).hexdigest()

        stability_ref = diff["replica_stability"]
        stability_path = self.root / stability_ref["path"]
        stability = json.loads(stability_path.read_text(encoding="utf-8"))
        stability["capture_bundles"][1] = replica_bundle_ref
        stability_path.write_text(json.dumps(stability, sort_keys=True), encoding="utf-8")
        stability_ref["sha256"] = hashlib.sha256(stability_path.read_bytes()).hexdigest()

        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("structure_report_metrics_forged", self.error_codes(report))

    def test_pixel_qa_recomputes_font_usage_instead_of_trusting_pass(self):
        manifest = self.strong_manifest()
        diff = manifest["critical_diffs"][0]
        font_report_ref = diff["font_report"]
        font_report_path = self.root / font_report_ref["path"]
        font_report = json.loads(font_report_path.read_text(encoding="utf-8"))
        replica_usage_ref = font_report["replica"]
        replica_usage_path = self.root / replica_usage_ref["path"]
        replica_usage = json.loads(replica_usage_path.read_text(encoding="utf-8"))
        replica_usage["records"][0]["fonts"][0]["familyName"] = "Fallback Sans"
        replica_usage["records"][0]["fonts"][0]["postScriptName"] = "FallbackSans-Regular"
        replica_usage_path.write_text(json.dumps(replica_usage, sort_keys=True), encoding="utf-8")
        replica_usage_ref["sha256"] = hashlib.sha256(replica_usage_path.read_bytes()).hexdigest()
        font_report_path.write_text(json.dumps(font_report, sort_keys=True), encoding="utf-8")
        font_report_ref["sha256"] = hashlib.sha256(font_report_path.read_bytes()).hexdigest()

        replica_bundle_ref = diff["replica_capture_bundle"]
        replica_bundle_path = self.root / replica_bundle_ref["path"]
        replica_bundle = json.loads(replica_bundle_path.read_text(encoding="utf-8"))
        replica_bundle["artifacts"]["fontUsage"] = replica_usage_ref
        replica_bundle_path.write_text(json.dumps(replica_bundle, sort_keys=True), encoding="utf-8")
        replica_bundle_ref["sha256"] = hashlib.sha256(replica_bundle_path.read_bytes()).hexdigest()

        stability_ref = diff["replica_stability"]
        stability_path = self.root / stability_ref["path"]
        stability = json.loads(stability_path.read_text(encoding="utf-8"))
        stability["capture_bundles"][1] = replica_bundle_ref
        stability_path.write_text(json.dumps(stability, sort_keys=True), encoding="utf-8")
        stability_ref["sha256"] = hashlib.sha256(stability_path.read_bytes()).hexdigest()

        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("font_report_metrics_forged", self.error_codes(report))

    def test_pixel_qa_recomputes_declared_stable_pair(self):
        manifest = self.strong_manifest()
        report_ref = manifest["critical_diffs"][0]["reference_stability"]
        report_path = self.root / report_ref["path"]
        stability = json.loads(report_path.read_text(encoding="utf-8"))
        noisy_path = self.root / "evidence/reference-noisy.png"
        canonical_path = self.root / manifest["critical_diffs"][0]["reference_screenshot"]["path"]
        canonical_pixel = Image.open(canonical_path).convert("RGB").getpixel((0, 0))
        changed_pixel = tuple(255 - channel for channel in canonical_pixel)
        Image.new("RGB", (1, 1), changed_pixel).save(noisy_path, format="PNG")
        noisy_sample = {
            "path": "evidence/reference-noisy.png",
            "sha256": hashlib.sha256(noisy_path.read_bytes()).hexdigest(),
        }
        stability["samples"][0] = noisy_sample
        noisy_bundle_ref = stability["capture_bundles"][0]
        noisy_bundle_path = self.root / noisy_bundle_ref["path"]
        noisy_bundle = json.loads(noisy_bundle_path.read_text(encoding="utf-8"))
        noisy_bundle["artifacts"]["screenshot"] = noisy_sample
        noisy_bundle_path.write_text(json.dumps(noisy_bundle, sort_keys=True), encoding="utf-8")
        noisy_bundle_ref["sha256"] = hashlib.sha256(noisy_bundle_path.read_bytes()).hexdigest()
        report_path.write_text(json.dumps(stability, sort_keys=True), encoding="utf-8")
        report_ref["sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("stability_recompute_failed", self.error_codes(report))

    def test_pixel_qa_canonical_must_be_second_stable_sample(self):
        manifest = self.strong_manifest()
        report_ref = manifest["critical_diffs"][0]["reference_stability"]
        report_path = self.root / report_ref["path"]
        stability = json.loads(report_path.read_text(encoding="utf-8"))
        stability["canonical"] = stability["samples"][0]
        report_path.write_text(json.dumps(stability, sort_keys=True), encoding="utf-8")
        report_ref["sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("stability_canonical_not_from_pair", self.error_codes(report))

    def test_pixel_qa_rejects_resolved_path_alias_for_stability_samples(self):
        manifest = self.strong_manifest()
        report_ref = manifest["critical_diffs"][0]["reference_stability"]
        report_path = self.root / report_ref["path"]
        stability = json.loads(report_path.read_text(encoding="utf-8"))
        canonical = stability["samples"][1]
        aliased = dict(canonical)
        aliased["path"] = "evidence/../evidence/reference.png"
        stability["samples"][0] = aliased
        first_bundle_ref = stability["capture_bundles"][0]
        first_bundle_path = self.root / first_bundle_ref["path"]
        first_bundle = json.loads(first_bundle_path.read_text(encoding="utf-8"))
        first_bundle["artifacts"]["screenshot"] = aliased
        first_bundle_path.write_text(json.dumps(first_bundle, sort_keys=True), encoding="utf-8")
        first_bundle_ref["sha256"] = hashlib.sha256(first_bundle_path.read_bytes()).hexdigest()
        report_path.write_text(json.dumps(stability, sort_keys=True), encoding="utf-8")
        report_ref["sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("stability_sample_reused", self.error_codes(report))

    def test_empty_component_spec_cannot_satisfy_strong_gate(self):
        manifest = self.strong_manifest()
        spec_path = self.root / manifest["component_specs"]["path"]
        spec_path.write_text("{}", encoding="utf-8")
        manifest["component_specs"]["sha256"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("component_spec_schema_invalid", self.error_codes(report))

    def test_builder_stage_does_not_require_post_build_diff_or_font_result(self):
        manifest = self.strong_manifest()
        manifest["scope"] = {"scope_id": "CMP-home", "kind": "component", "root_locator": "img#hero"}
        manifest.pop("critical_diffs")
        manifest.pop("font_fallback")

        self.write_manifest(manifest)
        builder_report, builder_code = web_fidelity_gate.run_gate(
            self.manifest_path,
            self.root,
            "builder",
        )
        qa_report, qa_code = web_fidelity_gate.run_gate(
            self.manifest_path,
            self.root,
            "qa",
        )

        self.assertEqual(builder_code, 0, builder_report["errors"])
        self.assertEqual(builder_report["stage"], "builder")
        self.assertEqual(qa_code, 2)
        self.assertIn("critical_diffs_missing", self.error_codes(qa_report))
        self.assertIn("font_fallback_missing", self.error_codes(qa_report))

    def test_capture_bundle_v2_triggers_strong_mode_and_inventory_shape_checks(self):
        manifest = self.capture_bundle_manifest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 0, report["errors"])

        inventory_path = self.root / manifest["probe_inventory"]["path"]
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory["schemaVersion"] = "web-asset-inventory/0.9"
        inventory["dom"]["scanTruncated"] = True
        inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
        manifest["probe_inventory"]["sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["artifacts"]["inventory"] = dict(manifest["probe_inventory"])
        bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
        manifest["capture_bundle"]["sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("probe_inventory_schema_invalid", codes)
        self.assertIn("probe_inventory_truncated", codes)

    def test_one_capture_bundle_cannot_cover_renamed_viewport_or_state(self):
        manifest = self.strong_manifest()
        mobile = json.loads(json.dumps(manifest["required_viewports"][0]))
        mobile["id"] = "mobile-390x844"
        hover = json.loads(json.dumps(manifest["required_states"][0]))
        hover["id"] = "hover"
        manifest["required_viewports"].append(mobile)
        manifest["required_states"].append(hover)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("reference_capture_bundle_reused", codes)
        self.assertIn("reference_capture_bundle_context_mismatch", codes)
        self.assertIn("critical_diff_matrix_missing", codes)

    def test_discovered_font_faces_require_explicit_resolution_evidence(self):
        manifest = self.strong_manifest()
        inventory_path = self.root / manifest["probe_inventory"]["path"]
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory["fonts"] = {
            "status": "loaded",
            "faces": [{"family": "Replica Sans", "weight": "400"}],
            "visibleFamilyDeclarations": [{"family": "Replica Sans", "visibleElementCount": 1}],
        }
        inventory_path.write_text(json.dumps(inventory, sort_keys=True), encoding="utf-8")
        manifest["probe_inventory"]["sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
        for collection_name in ("required_viewports", "required_states"):
            for entry in manifest[collection_name]:
                for artifact in entry["reference_capture"]["artifacts"]:
                    if artifact["path"] == manifest["probe_inventory"]["path"]:
                        artifact["sha256"] = manifest["probe_inventory"]["sha256"]
        spec_path = self.root / manifest["component_specs"]["path"]
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        spec["source_inventory"] = dict(manifest["probe_inventory"])
        spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")
        manifest["component_specs"]["sha256"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
        self.refresh_bundle(manifest)

        self.write_manifest(manifest)
        report, code = web_fidelity_gate.run_gate(self.manifest_path, self.root, "builder")
        self.assertEqual(code, 2)
        self.assertIn("global_font_resolution_required", self.error_codes(report))

        font_evidence = self.artifact("evidence/font-resolution.json", b"{}")
        manifest["metadata"] = {
            "global_fonts": {
                "status": "BLOCKED_RIGHTS",
                "rights": "reference_only",
                "evidence": [font_evidence],
                "scope_exclusion": {
                    "reason": "blocked_rights",
                    "evidence_ids": ["EVD-FONT-RIGHTS"],
                },
            }
        }
        self.write_manifest(manifest)
        report, code = web_fidelity_gate.run_gate(self.manifest_path, self.root, "builder")
        self.assertEqual(code, 0, report["errors"])
        self.assertEqual(report["equivalence_scope"], "partial_excludes_visible_assets")
        report, code = web_fidelity_gate.run_gate(self.manifest_path, self.root, "qa")
        self.assertEqual(code, 2)
        self.assertIn("global_font_resolution_required", self.error_codes(report))

        manifest["metadata"] = {
            "global_fonts": {"status": "RESOLVED", "evidence": [font_evidence]}
        }
        self.write_manifest(manifest)
        report, code = web_fidelity_gate.run_gate(self.manifest_path, self.root, "builder")
        self.assertEqual(code, 0, report["errors"])

    def test_visual_capture_bundle_rejects_forged_threshold_metrics(self):
        manifest = self.capture_bundle_manifest()
        manifest["fidelity"] = "visual"
        report_path = self.root / manifest["critical_diffs"][0]["diff_report"]["path"]
        diff_report = json.loads(report_path.read_text(encoding="utf-8"))
        diff_report["whole_page_pixel_equivalent"] = False
        diff_report["metrics"]["exact_diff_pixels"] = 1
        diff_report["visual_equivalent_within_threshold"] = True
        report_path.write_text(json.dumps(diff_report, sort_keys=True), encoding="utf-8")
        manifest["critical_diffs"][0]["diff_report"]["sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()

        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("visual_diff_metrics_forged", self.error_codes(report))

    def test_capture_bundle_v2_requires_bundle_artifact(self):
        manifest = self.capture_bundle_manifest()
        del manifest["capture_bundle"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_bundle_missing", self.error_codes(report))

    def test_capture_bundle_v2_rejects_inventory_link_mismatch(self):
        manifest = self.capture_bundle_manifest()
        bundle_path = self.root / manifest["capture_bundle"]["path"]
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["artifacts"]["inventory"] = dict(manifest["component_specs"])
        bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
        manifest["capture_bundle"]["sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("capture_bundle_inventory_mismatch", self.error_codes(report))

    def test_capture_bundle_v2_rejects_missing_or_mismatched_required_artifacts(self):
        for case in ("missing", "hash-mismatch"):
            with self.subTest(case=case):
                manifest = self.capture_bundle_manifest()
                bundle_path = self.root / manifest["capture_bundle"]["path"]
                bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
                if case == "missing":
                    del bundle["artifacts"]["axTree"]
                    expected_code = "capture_bundle_artifact_missing"
                else:
                    bundle["artifacts"]["environment"]["sha256"] = "0" * 64
                    expected_code = "strong_artifact_hash_mismatch"
                bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
                manifest["capture_bundle"]["sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn(expected_code, self.error_codes(report))

    def test_strong_manifest_fails_when_inventory_has_asset_but_assets_are_empty(self):
        manifest = self.strong_manifest()
        manifest["assets"] = []
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("asset_occurrence_coverage_incomplete", self.error_codes(report))

    def test_legacy_discovery_summary_cannot_hide_an_empty_asset_manifest(self):
        manifest = self.good_manifest()
        manifest["assets"] = []
        manifest["reference_summary"] = {
            "total": 236,
            "image": 158,
            "inlineSvg": 11,
        }
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("asset_manifest_empty_after_discovery", self.error_codes(report))
        self.assertEqual(report["summary"]["discovered_asset_candidates"], 169)

    def test_builder_stage_rejects_legacy_non_strong_manifest(self):
        manifest = self.good_manifest()
        self.write_manifest(manifest)
        report, code = web_fidelity_gate.run_gate(self.manifest_path, self.root, "builder")
        self.assertEqual(code, 2)
        self.assertIn("builder_strong_mode_required", self.error_codes(report))
        self.assertFalse(report["strong_mode"])

    def test_strong_manifest_rejects_self_reported_critical_diff(self):
        manifest = self.strong_manifest()
        manifest["critical_diffs"] = [{"component_id": "home-default-desktop", "pass": True}]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("critical_diff_evidence_missing", self.error_codes(report))

    def test_strong_manifest_rejects_bare_coverage_and_self_reported_lists(self):
        manifest = self.strong_manifest()
        manifest["required_viewports"] = ["desktop-1440x900", "mobile-390x844"]
        manifest["covered_viewports"] = list(manifest["required_viewports"])
        manifest["required_states"] = ["default", "hover"]
        manifest["covered_states"] = list(manifest["required_states"])
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("bare_coverage_forbidden", self.error_codes(report))

    def test_strong_manifest_rejects_probe_hash_mismatch(self):
        manifest = self.strong_manifest()
        manifest["probe_inventory"]["sha256"] = "0" * 64
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("strong_artifact_hash_mismatch", self.error_codes(report))

    def test_cli_output_writes_report_atomically_inside_project_root(self):
        self.write_manifest(self.strong_manifest())
        output_path = self.root / "reports" / "gate.json"
        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--manifest",
                str(self.manifest_path),
                "--project-root",
                str(self.root),
                "--output",
                "reports/gate.json",
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), json.loads(process.stdout))

    def test_cli_output_rejects_project_root_escape(self):
        self.write_manifest(self.strong_manifest())
        outside = self.root.parent / "outside-report.json"
        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--manifest",
                str(self.manifest_path),
                "--project-root",
                str(self.root),
                "--output",
                "../outside-report.json",
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(process.returncode, 3, process.stdout + process.stderr)
        self.assertFalse(outside.exists())
        self.assertIn("output_path_invalid", self.error_codes(json.loads(process.stdout)))

    def test_hash_mismatch_fails_gate_with_exit_2(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["sha256"] = "0" * 64
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "fail")
        self.assertIn("sha256_mismatch", self.error_codes(report))

    def test_missing_local_asset_fails(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["local_path"] = "assets/missing.png"
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("asset_file_missing", self.error_codes(report))

    def test_unknown_rights_and_missing_evidence_fail(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["rights"] = "unknown"
        manifest["assets"][0]["evidence_ids"] = []
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("rights_unapproved", codes)
        self.assertIn("evidence_ids_missing", codes)

    def test_ai_generated_guessed_and_lookalike_provenance_are_rejected(self):
        for provenance in (
            "ai_generated",
            "generated_lookalike",
            "guessed",
            "approximate_icon_library",
        ):
            with self.subTest(provenance=provenance):
                manifest = self.good_manifest()
                manifest["assets"][0]["provenance"] = provenance
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn("forbidden_asset_provenance", self.error_codes(report))

    def test_unapproved_placeholder_and_unresolved_assets_are_rejected(self):
        for provenance in ("unapproved_placeholder", "unresolved"):
            with self.subTest(provenance=provenance):
                manifest = self.good_manifest()
                manifest["assets"][0]["provenance"] = provenance
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn("forbidden_asset_provenance", self.error_codes(report))

    def test_accepted_deviation_cannot_approve_forbidden_provenance(self):
        for provenance in (
            "ai_generated",
            "generated_lookalike",
            "guessed",
            "approximate_icon_library",
            "unapproved_placeholder",
            "unresolved",
        ):
            with self.subTest(provenance=provenance):
                manifest = self.good_manifest()
                asset = manifest["assets"][0]
                asset["resolution"] = "accepted_deviation"
                asset["provenance"] = provenance
                asset["accepted_deviation"] = {
                    "deviation_id": "DEV-FORBIDDEN",
                    "approved_by": "product-owner",
                    "reason": "A deviation cannot legalize an approximate asset",
                    "decision": provenance,
                }
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                codes = self.error_codes(report)
                self.assertIn("forbidden_asset_provenance", codes)
                self.assertIn("accepted_deviation_provenance_invalid", codes)

    def test_visible_in_scope_assets_require_provenance_even_with_deviation(self):
        for resolution in ("exact_captured", "accepted_deviation"):
            with self.subTest(resolution=resolution):
                manifest = self.good_manifest()
                manifest["assets"][0]["resolution"] = resolution
                del manifest["assets"][0]["provenance"]
                if resolution == "accepted_deviation":
                    manifest["assets"][0]["accepted_deviation"] = {
                        "deviation_id": "DEV-NO-PROVENANCE",
                        "approved_by": "product-owner",
                        "reason": "Explicit test case",
                        "decision": "approved_omission",
                    }
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn("provenance_missing", self.error_codes(report))

    def test_visible_out_of_scope_asset_requires_evidence_and_never_claims_full_scope(self):
        manifest = self.strong_manifest()
        asset = manifest["assets"][0]
        asset.update(
            {
                "in_scope": False,
                "rights": "reference_only",
                "resolution": "unresolved",
                "provenance": "unresolved",
                "status": "UNRESOLVED",
            }
        )
        asset.pop("scope_exclusion", None)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("scope_exclusion_missing", self.error_codes(report))

        asset["scope_exclusion"] = {"reason": "blocked_rights", "evidence_ids": ["EVD-rights"]}
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 0, report["errors"])
        self.assertEqual(report["equivalence_scope"], "partial_excludes_visible_assets")

    def test_each_exact_resolution_requires_its_matching_provenance(self):
        exact_cases = (
            ("exact_captured", "captured_original"),
            ("exact_provided", "provided_original"),
            ("exact_reconstructed", "spec_reconstructed"),
        )
        spec = self.root / "assets" / "logo-spec.json"
        spec.write_text("{}", encoding="utf-8")
        for resolution, provenance in exact_cases:
            with self.subTest(resolution=resolution, provenance=provenance):
                manifest = self.good_manifest()
                manifest["assets"][0]["resolution"] = resolution
                manifest["assets"][0]["provenance"] = provenance
                if resolution == "exact_reconstructed":
                    manifest["assets"][0]["spec_path"] = "assets/logo-spec.json"
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 0, report["errors"])

                manifest["assets"][0]["provenance"] = "captured_original" if provenance != "captured_original" else "provided_original"
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn("provenance_resolution_mismatch", self.error_codes(report))

    def test_missing_state_coverage_and_mobile_viewport_fail(self):
        manifest = self.good_manifest()
        manifest["required_viewports"] = [
            {"id": "desktop-1440x900", "kind": "desktop", "covered": True}
        ]
        manifest["required_states"][1]["covered"] = False
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("required_mobile_viewport_missing", codes)
        self.assertIn("required_states_uncovered", codes)

    def test_external_coverage_lists_detect_missing_mobile_and_state(self):
        manifest = self.good_manifest()
        manifest["required_viewports"] = ["desktop", "mobile"]
        manifest["captured_viewports"] = ["desktop"]
        manifest["required_states"] = ["default", "focus"]
        manifest["captured_states"] = ["default"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("required_viewports_uncovered", codes)
        self.assertIn("required_states_uncovered", codes)

    def test_font_fallback_failure_is_blocking(self):
        manifest = self.good_manifest()
        manifest["font_fallback"] = {"checked": True, "pass": False, "fallback_used": True}
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        codes = self.error_codes(report)
        self.assertIn("font_fallback_failed", codes)
        self.assertIn("unexpected_font_fallback", codes)

    def test_critical_diff_requires_explicit_pass(self):
        manifest = self.good_manifest()
        del manifest["critical_diffs"][0]["pass"]
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("critical_diff_failed", self.error_codes(report))

    def test_sensitive_url_userinfo_and_query_are_rejected_without_echoing_secret(self):
        for source_ref in (
            "https://user:super-secret@public.example.test/logo.png",
            "https://public.example.test/logo.png?access_token=super-secret",
            "/assets/logo.png?token=super-secret",
        ):
            with self.subTest(source_ref=source_ref):
                manifest = self.good_manifest()
                manifest["assets"][0]["source_ref"] = source_ref
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn("sensitive_source_ref", self.error_codes(report))
                self.assertNotIn("super-secret", json.dumps(report))

    def test_private_remote_hotlink_is_rejected(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["source_ref"] = "https://127.0.0.1/private/logo.png"
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("private_remote_hotlink", self.error_codes(report))

    def test_explicit_remote_hotlink_marker_is_rejected(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["remote_hotlink"] = True
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("private_remote_hotlink", self.error_codes(report))

    def test_path_traversal_and_symlink_escape_are_rejected(self):
        outside = self.root.parent / "outside.bin"
        outside.write_bytes(b"outside")
        for local_path in ("../outside.bin", "assets/escape.bin"):
            with self.subTest(local_path=local_path):
                escape = self.root / "assets" / "escape.bin"
                if local_path.endswith("escape.bin") and not escape.exists():
                    try:
                        escape.symlink_to(outside)
                    except (OSError, NotImplementedError):
                        self.skipTest("symlinks are unavailable")
                manifest = self.good_manifest()
                manifest["assets"][0]["local_path"] = local_path
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 2)
                self.assertIn("local_path_invalid", self.error_codes(report))

    def test_approved_deviation_with_all_approval_fields_passes(self):
        for provenance in (
            "user_provided_licensed_replacement",
            "authorized_neutral_replacement",
            "approved_static_rasterization",
        ):
            with self.subTest(provenance=provenance):
                manifest = self.good_manifest()
                manifest["assets"][0]["resolution"] = "accepted_deviation"
                manifest["assets"][0]["provenance"] = provenance
                manifest["assets"][0]["accepted_deviation"] = {
                    "deviation_id": "DEV-7",
                    "approved_by": "product-owner",
                    "reason": "Original licensed campaign art is no longer distributed",
                    "decision": provenance,
                }
                report, code = self.run_direct(manifest)
                self.assertEqual(code, 0, report["errors"])
                self.assertTrue(report["ok"])

    def test_incomplete_deviation_is_rejected(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["resolution"] = "accepted_deviation"
        manifest["assets"][0]["provenance"] = "authorized_neutral_replacement"
        manifest["assets"][0]["accepted_deviation"] = {"deviation_id": "DEV-8"}
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("accepted_deviation_incomplete", self.error_codes(report))

    def test_deviation_decision_must_match_allowed_provenance(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["resolution"] = "accepted_deviation"
        manifest["assets"][0]["provenance"] = "authorized_neutral_replacement"
        manifest["assets"][0]["accepted_deviation"] = {
            "deviation_id": "DEV-9",
            "approved_by": "product-owner",
            "reason": "Authorized neutral replacement",
            "decision": "approved_static_rasterization",
        }
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("accepted_deviation_decision_mismatch", self.error_codes(report))

    def test_approved_omission_may_have_no_local_file_or_hash(self):
        manifest = self.good_manifest()
        asset = manifest["assets"][0]
        asset["resolution"] = "accepted_deviation"
        asset["provenance"] = "approved_omission"
        del asset["local_path"]
        del asset["sha256"]
        asset["accepted_deviation"] = {
            "deviation_id": "DEV-OMIT-1",
            "approved_by": "product-owner",
            "reason": "The decorative occurrence is explicitly omitted",
            "decision": "approved_omission",
        }
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 0, report["errors"])

    def test_non_omission_deviation_still_requires_local_file_and_hash(self):
        manifest = self.good_manifest()
        asset = manifest["assets"][0]
        asset["resolution"] = "accepted_deviation"
        asset["provenance"] = "approved_static_rasterization"
        del asset["local_path"]
        del asset["sha256"]
        asset["accepted_deviation"] = {
            "deviation_id": "DEV-RASTER-1",
            "approved_by": "product-owner",
            "reason": "A fixed-state rasterization was explicitly approved",
            "decision": "approved_static_rasterization",
        }
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("local_path_invalid", self.error_codes(report))

    def test_exact_reconstruction_requires_existing_spec(self):
        manifest = self.good_manifest()
        manifest["assets"][0]["resolution"] = "exact_reconstructed"
        manifest["assets"][0]["provenance"] = "spec_reconstructed"
        manifest["assets"][0]["spec_path"] = "evidence/missing-spec.json"
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 2)
        self.assertIn("reconstruction_spec_missing", self.error_codes(report))

    def test_duplicate_content_hashes_are_reported_but_do_not_fail(self):
        second = self.root / "assets" / "logo-copy.bin"
        second.write_bytes(self.asset_path.read_bytes())
        manifest = self.good_manifest()
        copied_asset = dict(manifest["assets"][0])
        copied_asset.update({"asset_id": "logo-copy", "local_path": "assets/logo-copy.bin"})
        manifest["assets"].append(copied_asset)
        report, code = self.run_direct(manifest)
        self.assertEqual(code, 0, report["errors"])
        self.assertEqual(report["summary"]["duplicate_hash_groups"], 1)
        self.assertEqual(report["duplicate_hashes"][0]["asset_ids"], ["logo", "logo-copy"])

    def test_invalid_json_uses_exit_3_and_json_report(self):
        self.manifest_path.write_text("{not-json", encoding="utf-8")
        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--manifest",
                str(self.manifest_path),
                "--project-root",
                str(self.root),
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(process.returncode, 3)
        report = json.loads(process.stdout)
        self.assertEqual(report["status"], "invalid_manifest")
        self.assertIn("invalid_json", self.error_codes(report))


if __name__ == "__main__":
    unittest.main()
