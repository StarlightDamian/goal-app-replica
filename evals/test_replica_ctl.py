"""Behavioral tests for the dependency-free replica state controller."""

from __future__ import annotations

import datetime
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "replica_ctl.py"
SPEC = importlib.util.spec_from_file_location("replica_ctl", SCRIPT)
assert SPEC and SPEC.loader
replica_ctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replica_ctl)


UTC = datetime.timezone.utc


class ReplicaControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace_root = self.root / ".replica"
        self.code_root = self.root / "code"
        self.code_root.mkdir()
        self.controller, self.start_result = replica_ctl.ReplicaController.start_project(
            project_id="sample-project",
            workspace_root=self.workspace_root,
            code_root=str(self.code_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def load_state(self):
        return json.loads(self.controller.store.state_path.read_text(encoding="utf-8"))

    def add_gap(self, gap_id="GAP-1"):
        return self.controller.add_gap(
            gap_id=gap_id,
            title="Reference and replica differ",
            priority="P0",
            scenario_ids=["SCN-1"],
            reference_evidence=["EVD-REF-1"],
            replica_evidence=["EVD-REP-1"],
            acceptance=["Paired replay passes"],
        )

    def add_task(self, task_id="TASK-1", gap_id="GAP-1", resources=None, dependencies=None):
        return self.controller.add_task(
            task_id=task_id,
            goal="Make the observable flow equivalent",
            gap_ids=[gap_id] if gap_id else [],
            priority="P0",
            inputs=["EVD-REF-1", "EVD-REP-1"],
            dependencies=dependencies or [],
            resource_keys=resources or ["code:src/feature"],
            editable_paths=["src/feature"],
            forbidden_paths=["src/unrelated"],
            base_revision="abc123",
            acceptance=["Focused test passes"],
            expected_outputs=["code diff", "validation result"],
        )

    def write_preflight(self, *, ok=True, status="pass", scope_id="CMP-home", scope_kind="component", partial_font=False):
        def artifact(relative_path, content):
            path = self.code_root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            return {"path": relative_path, "sha256": hashlib.sha256(content).hexdigest()}

        root_element = {
            "locator": "#root",
            "geometry": {"x": 0, "y": 0, "width": 1, "height": 1},
            "layout": {"display": "block"},
        }
        inventory = {
            "schemaVersion": "web-asset-inventory/1.0",
            "dom": {"scanTruncated": False},
            "images": [],
            "imageInputs": [],
            "videos": [],
            "inlineSvgs": [],
            "svgUses": [],
            "svgExternalReferences": [],
            "cssImages": [],
            "pseudoElements": [],
            "visibleElements": [root_element],
            "canvases": [],
            "iframes": [],
            "fonts": {
                "faces": [{"family": "Reference Display", "weight": "400"}] if partial_font else [],
                "visibleFamilyDeclarations": [{"family": "Reference Display", "visibleElementCount": 1}] if partial_font else [],
            },
        }
        inventory_ref = artifact(
            "reports/inventory.json",
            json.dumps(inventory, sort_keys=True).encode("utf-8"),
        )
        font_evidence_ref = artifact("reports/font-rights.json", b"{}") if partial_font else None
        png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
        screenshot_ref = artifact("reports/reference.png", png)
        navigation_fingerprint = "1" * 64
        reference_fingerprint = hashlib.sha256(b"https://reference.example.test/").hexdigest()
        environment_ref = artifact("reports/environment.json", json.dumps({
            "schemaVersion": "web-capture-environment/1.0",
            "probeViewport": {"innerWidth": 1280, "innerHeight": 720, "devicePixelRatio": 1},
            "navigationFingerprint": navigation_fingerprint,
            "referenceFingerprint": reference_fingerprint,
        }, sort_keys=True).encode("utf-8"))
        dom_ref = artifact("reports/dom-snapshot.json", json.dumps({
            "schemaVersion": "web-dom-render-tree/1.0", "normalizedObservableValuesPersisted": True, "documents": []
        }, sort_keys=True).encode("utf-8"))
        ax_ref = artifact("reports/ax-tree.json", json.dumps({
            "schemaVersion": "web-ax-tree-public/1.0", "normalizedObservableValuesPersisted": True, "nodes": []
        }, sort_keys=True).encode("utf-8"))
        capture_context = {
            "projectId": "sample-project", "pageId": "home", "scenarioId": "SCN-1",
            "baselineId": "BL-1", "viewportId": "desktop-1280x720", "stateId": "default", "side": "reference",
        }
        component_spec = {
            "schemaVersion": "web-component-spec/1.0",
            "component_id": scope_id,
            "scope": {"scope_id": scope_id, "kind": scope_kind, "root_locator": "#root" if scope_kind == "component" else "*"},
            "source_inventory": inventory_ref,
            "viewport": "desktop-1280x720",
            "states": ["default"],
            "capture_context": capture_context,
            "elements": [root_element],
        }
        component_ref = artifact(
            "reports/component-spec.json",
            json.dumps(component_spec, sort_keys=True).encode("utf-8"),
        )
        state_contract_ref = artifact(
            "reports/state-contract.json",
            json.dumps({
                "schemaVersion": "web-capture-state-contract/1.0",
                "expectedPublicLocation": "https://target.example.test/home",
                "document": {"minScrollWidth": 1, "minScrollHeight": 1},
                "selectors": [{"selector": "#root", "minCount": 1, "minVisibleCount": 1, "maxCount": None, "maxVisibleCount": None}],
            }, sort_keys=True).encode("utf-8"),
        )
        state_witness_ref = artifact(
            "reports/state-witness.json",
            json.dumps({
                "schemaVersion": "web-capture-state-witness/1.0", "pass": True,
                "phase": "pre", "observedAt": "2026-01-01T00:00:00Z",
                "checks": {"publicLocation": True, "minScrollWidth": True, "minScrollHeight": True, "selectors": True},
                "publicLocation": "https://target.example.test/home",
                "documentMetrics": {"scrollWidth": 1280, "scrollHeight": 720},
                "selectorResults": [{"selector": "#root", "invalidSelector": False, "count": 1, "visibleCount": 1, "pass": True}],
            }, sort_keys=True).encode("utf-8"),
        )
        state_witness_post_ref = artifact(
            "reports/state-witness-post.json",
            json.dumps({
                "schemaVersion": "web-capture-state-witness/1.0", "pass": True,
                "phase": "post", "observedAt": "2026-01-01T00:00:01Z",
                "checks": {"publicLocation": True, "minScrollWidth": True, "minScrollHeight": True, "selectors": True},
                "publicLocation": "https://target.example.test/home",
                "documentMetrics": {"scrollWidth": 1280, "scrollHeight": 720},
                "selectorResults": [{"selector": "#root", "invalidSelector": False, "count": 1, "visibleCount": 1, "pass": True}],
            }, sort_keys=True).encode("utf-8"),
        )
        font_usage_ref = artifact(
            "reports/font-usage.json",
            json.dumps({
                "schemaVersion": "web-platform-font-usage/1.0", "candidateNodeCount": 0,
                "queriedNodeCount": 0, "failedNodeCount": 0, "unmappedNodeCount": 0,
                "scanTruncated": False, "scopeRoots": ["#root" if scope_kind == "component" else "*"], "expectedLocators": [],
                "expectedRecords": [], "records": [], "families": [], "pseudoDeclarations": [],
                "budgetExhausted": False, "timedOutNodeCount": 0, "scopeMissing": False,
            }, sort_keys=True).encode("utf-8"),
        )
        bundle = {
            "schemaVersion": "web-capture-bundle/2.0",
            "capturedAt": "2026-01-01T00:00:02Z",
            "contentPolicy": "public-observable",
            "context": capture_context,
            "navigationFingerprint": navigation_fingerprint,
            "referenceFingerprint": reference_fingerprint,
            "stateContractSha256": state_contract_ref["sha256"],
            "stateWitnessSha256": state_witness_ref["sha256"],
            "stateWitnessPostSha256": state_witness_post_ref["sha256"],
            "viewport": {"innerWidth": 1280, "innerHeight": 720, "devicePixelRatio": 1},
            "artifacts": {
                "inventory": inventory_ref,
                "environment": environment_ref,
                "domSnapshot": dom_ref,
                "axTree": ax_ref,
                "fontUsage": font_usage_ref,
                "stateContract": state_contract_ref,
                "stateWitness": state_witness_ref,
                "stateWitnessPost": state_witness_post_ref,
                "screenshot": screenshot_ref,
            },
        }
        bundle_ref = artifact(
            "reports/capture-bundle.json",
            json.dumps(bundle, sort_keys=True).encode("utf-8"),
        )
        manifest_relative_path = "reports/web-fidelity-manifest.json"
        manifest_path = self.code_root / manifest_relative_path
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": 1,
            "enforcement_mode": "capture_bundle_v2",
            "project_id": "sample-project",
            "page_id": "home",
            "scenario_id": "SCN-1",
            "baseline_id": "BL-1",
            "reference_fingerprint": reference_fingerprint,
            "scope": {"scope_id": scope_id, "kind": scope_kind, "root_locator": "#root" if scope_kind == "component" else "*"},
            "capture_bundle": bundle_ref,
            "probe_inventory": inventory_ref,
            "component_specs": component_ref,
            "required_viewports": [
                {
                    "id": "desktop-1280x720",
                    "kind": "desktop",
                    "reference_capture": {"artifacts": [dict(bundle_ref, kind="capture-bundle"), dict(screenshot_ref, kind="screenshot"), dict(inventory_ref, kind="probe")]},
                }
            ],
            "required_states": [
                {
                    "id": "default",
                    "reference_capture": {"artifacts": [dict(bundle_ref, kind="capture-bundle"), dict(screenshot_ref, kind="screenshot"), dict(inventory_ref, kind="probe")]},
                }
            ],
            "assets": [],
        }
        if partial_font:
            manifest["metadata"] = {
                "global_fonts": {
                    "status": "BLOCKED_RIGHTS",
                    "rights": "reference_only",
                    "evidence": [font_evidence_ref],
                    "scope_exclusion": {
                        "reason": "blocked_rights",
                        "evidence_ids": ["EVD-FONT-RIGHTS"],
                    },
                }
            }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        relative_path = "reports/web-fidelity-gate.json"
        report_path = self.code_root / relative_path
        report_path.parent.mkdir(parents=True, exist_ok=True)
        gate_script = SCRIPT.with_name("web_fidelity_gate.py")
        process = subprocess.run(
            [
                sys.executable,
                str(gate_script),
                "--manifest",
                str(manifest_path),
                "--project-root",
                str(self.code_root),
                "--stage",
                "builder",
                "--output",
                str(report_path),
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["ok"] = ok
        report["status"] = status
        content = json.dumps(report, sort_keys=True).encode("utf-8")
        report_path.write_bytes(content)
        return relative_path, hashlib.sha256(content).hexdigest(), report_path

    def test_update_gap_appends_unique_audited_evidence(self):
        self.add_gap()
        result = self.controller.update_gap(
            gap_id="GAP-1",
            scenario_ids=["SCN-1", "SCN-2"],
            reference_evidence=["EVD-REF-1", "EVD-REF-2"],
            replica_evidence=["EVD-REP-2"],
            acceptance=["Paired replay passes", "Independent QA passes"],
        )
        self.assertTrue(result["changed"])
        gap = self.load_state()["gaps"]["GAP-1"]
        self.assertEqual(gap["scenario_ids"], ["SCN-1", "SCN-2"])
        self.assertEqual(gap["reference_evidence"], ["EVD-REF-1", "EVD-REF-2"])
        self.assertEqual(gap["replica_evidence"], ["EVD-REP-1", "EVD-REP-2"])
        second = self.controller.update_gap(gap_id="GAP-1", scenario_ids=["SCN-2"])
        self.assertFalse(second["changed"])
        with self.assertRaises(replica_ctl.ReplicaCtlError) as missing:
            self.controller.update_gap(gap_id="GAP-missing", scenario_ids=["SCN-3"])
        self.assertEqual(missing.exception.code, "not_found")
        self.assertTrue(self.controller.validate()["ok"])

    def test_update_gap_replaces_stale_title_and_description_with_audit(self):
        self.add_gap()

        updated = self.controller.update_gap(
            gap_id="GAP-1",
            title="Seller surface pairing remains open",
            description="The core contract is closed; seller UI pairing is still missing.",
            actor="coordinator",
        )

        self.assertTrue(updated["changed"])
        self.assertEqual(updated["gap"]["title"], "Seller surface pairing remains open")
        self.assertEqual(
            updated["gap"]["description"],
            "The core contract is closed; seller UI pairing is still missing.",
        )
        self.assertEqual(
            updated["replaced"]["title"]["from"],
            "Reference and replica differ",
        )
        self.assertEqual(updated["replaced"]["description"]["from"], "")
        event = self.load_state()["events"][-1]
        self.assertEqual(event["type"], "gap_updated")
        self.assertEqual(event["replaced"], updated["replaced"])

        unchanged = self.controller.update_gap(
            gap_id="GAP-1",
            title="Seller surface pairing remains open",
            description="The core contract is closed; seller UI pairing is still missing.",
        )
        self.assertFalse(unchanged["changed"])

        with self.assertRaisesRegex(replica_ctl.ReplicaCtlError, "title"):
            self.controller.update_gap(gap_id="GAP-1", title="   ")

    def test_update_gap_removes_exact_acceptance_with_audit(self):
        self.add_gap()
        result = self.controller.update_gap(
            gap_id="GAP-1",
            remove_acceptance=["Paired replay passes"],
        )
        self.assertTrue(result["changed"])
        self.assertEqual(result["removed"], {"acceptance": ["Paired replay passes"]})
        state = self.load_state()
        self.assertEqual(state["gaps"]["GAP-1"]["acceptance"], [])
        self.assertEqual(state["events"][-1]["type"], "gap_updated")
        self.assertEqual(state["events"][-1]["removed"], {"acceptance": ["Paired replay passes"]})
        self.assertTrue(self.controller.validate()["ok"])

    def test_update_gap_remove_acceptance_cli_is_exact_and_fail_closed(self):
        self.add_gap()
        command = [
            sys.executable,
            str(SCRIPT),
            "--workspace",
            str(self.controller.workspace),
            "update-gap",
            "--gap-id",
            "GAP-1",
            "--remove-acceptance",
            "Paired replay passes",
        ]
        removed = subprocess.run(command, text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(removed.stdout)["removed"], {"acceptance": ["Paired replay passes"]})
        repeated = subprocess.run(command, text=True, capture_output=True)
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(json.loads(repeated.stderr)["code"], "not_found")
        self.assertTrue(self.controller.validate()["ok"])

    def test_web_builder_weak_or_legacy_preflight_is_rejected(self):
        self.add_gap()
        relative_path, digest, report_path = self.write_preflight()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["strong_mode"] = False
        report["enforcement_mode"] = None
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(report_path.read_bytes()).hexdigest()

        with self.assertRaisesRegex(replica_ctl.ReplicaCtlError, "capture_bundle_v2"):
            self.controller.add_task(
                task_id="TASK-WEB-WEAK",
                goal="Build Web UI from a weak report",
                gap_ids=["GAP-1"],
                task_kind="web_builder",
                preflight_report=relative_path,
                preflight_sha256=digest,
                preflight_scope_id="CMP-home",
            )

    def test_web_builder_partial_scope_preflight_is_rejected(self):
        self.add_gap()
        relative_path, _digest, report_path = self.write_preflight()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["equivalence_scope"] = "partial_excludes_visible_assets"
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(report_path.read_bytes()).hexdigest()

        with self.assertRaisesRegex(replica_ctl.ReplicaCtlError, "capture_bundle_v2"):
            self.controller.add_task(
                task_id="TASK-WEB-PARTIAL",
                goal="Build Web UI from a partial report",
                gap_ids=["GAP-1"],
                task_kind="web_builder",
                preflight_report=relative_path,
                preflight_sha256=digest,
                preflight_scope_id="CMP-home",
            )

    def test_visual_web_project_rejects_writable_generic_task(self):
        visual_root = self.root / "visual-code"
        visual_root.mkdir()
        controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="visual-project",
            workspace_root=self.workspace_root,
            code_root=str(visual_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="pixel",
            asset_rights="explicit_authorized",
        )
        controller.add_gap(
            gap_id="GAP-WEB",
            title="Visual mismatch",
            priority="P0",
            scenario_ids=["SCN-WEB"],
            reference_evidence=["EVD-REF"],
            replica_evidence=["EVD-REP"],
            acceptance=["Pixel gate passes"],
        )

        with self.assertRaisesRegex(replica_ctl.ReplicaCtlError, "typed"):
            controller.add_task(
                task_id="TASK-GENERIC-WEB",
                goal="Edit the page",
                gap_ids=["GAP-WEB"],
                task_kind="generic",
            )

    def test_visual_web_project_accepts_scoped_core_contract_builder_without_web_preflight(self):
        visual_root = self.root / "visual-core-code"
        visual_root.mkdir()
        controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="visual-core-project",
            workspace_root=self.workspace_root / "visual-core",
            code_root=str(visual_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="pixel",
            asset_rights="explicit_authorized",
        )
        controller.add_gap(
            gap_id="GAP-CORE",
            title="Store and user principals are conflated",
            priority="P0",
            scenario_ids=["SCN-STORE"],
            acceptance=["Store principal contract tests pass"],
        )

        added = controller.add_task(
            task_id="TASK-CORE",
            goal="Separate store and user principals",
            gap_ids=["GAP-CORE"],
            task_kind="core_contract_builder",
            editable_paths=["src/core/context.ts", "test/core/store-principal.test.ts"],
        )
        self.assertEqual(added["task"]["task_kind"], "core_contract_builder")
        claimed = controller.claim(task_id="TASK-CORE", owner="core-builder")
        self.assertEqual(claimed["task"]["editable_paths"], [
            "src/core/context.ts",
            "test/core/store-principal.test.ts",
        ])

    def test_core_contract_builder_rejects_empty_or_out_of_scope_editable_paths(self):
        invalid_paths = [
            [],
            ["src/corex/context.ts"],
            ["test/corex/context.test.ts"],
            ["src/apps/storefront/page.tsx"],
            ["../src/core/context.ts"],
            [r"C:\code\src\core\context.ts"],
            ["/src/core/context.ts"],
            [r"\\server\share\src\core\context.ts"],
            [r"C:src\core\context.ts"],
            ["src/core/../apps/context.ts"],
            [r"test\core\..\apps\context.test.ts"],
            ["src/core/context.ts", "src/apps/storefront/page.tsx"],
        ]
        for index, editable_paths in enumerate(invalid_paths):
            with self.subTest(editable_paths=editable_paths):
                with self.assertRaisesRegex(replica_ctl.ReplicaCtlError, "src/core|test/core"):
                    self.controller.add_task(
                        task_id="TASK-CORE-BAD-%s" % index,
                        goal="Escape the core contract scope",
                        task_kind="core_contract_builder",
                        editable_paths=editable_paths,
                    )

    def test_persisted_core_contract_builder_scope_cannot_be_bypassed_before_claim(self):
        self.controller.add_task(
            task_id="TASK-CORE",
            goal="Edit the core contract",
            task_kind="core_contract_builder",
            editable_paths=["src/core/context.ts"],
        )
        state = self.load_state()
        state["tasks"]["TASK-CORE"]["editable_paths"] = ["src/apps/storefront/page.tsx"]
        self.controller.store.atomic_write(state)

        validation = self.controller.validate()
        self.assertFalse(validation["valid"])
        self.assertTrue(
            any("core_contract_builder" in error for error in validation["errors"]),
            validation["errors"],
        )
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.claim(task_id="TASK-CORE", owner="core-builder")

    def test_core_contract_builder_rejects_invalid_or_tampered_forbidden_paths_before_claim(self):
        for index, forbidden_path in enumerate(
            [r"C:\outside", "/outside", r"\\server\share", "../outside"]
        ):
            with self.subTest(forbidden_path=forbidden_path):
                with self.assertRaisesRegex(replica_ctl.ReplicaCtlError, "project-root-relative"):
                    self.controller.add_task(
                        task_id="TASK-CORE-BAD-FORBIDDEN-%s" % index,
                        goal="Reject an invalid forbidden path",
                        task_kind="core_contract_builder",
                        editable_paths=["src/core/context.ts"],
                        forbidden_paths=[forbidden_path],
                    )

        self.controller.add_task(
            task_id="TASK-CORE-TAMPERED-FORBIDDEN",
            goal="Reject a persisted forbidden path escape",
            task_kind="core_contract_builder",
            editable_paths=["src/core/context.ts"],
            forbidden_paths=["src/core/protected"],
        )
        state = self.load_state()
        state["tasks"]["TASK-CORE-TAMPERED-FORBIDDEN"]["forbidden_paths"] = [r"C:\outside"]
        self.controller.store.atomic_write(state)

        validation = self.controller.validate()
        self.assertFalse(validation["valid"])
        self.assertTrue(
            any("forbidden paths" in error for error in validation["errors"]),
            validation["errors"],
        )
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.claim(
                task_id="TASK-CORE-TAMPERED-FORBIDDEN",
                owner="core-builder",
            )

    def test_core_contract_handoff_rejects_out_of_scope_changed_files_and_keeps_lease(self):
        self.controller.add_task(
            task_id="TASK-CORE",
            goal="Edit the core contract",
            task_kind="core_contract_builder",
            editable_paths=["src/core/context.ts", "test/core"],
            forbidden_paths=["src/core/protected/**"],
        )
        claim = self.controller.claim(task_id="TASK-CORE", owner="core-builder")

        for changed_files in (
            ["src/apps/storefront/page.tsx"],
            ["src/core/undeclared.ts"],
            ["src/core/context.ts", "src/apps/storefront/page.tsx"],
            ["src/core/protected/secret.ts"],
            ["src/core/PROTECTED/secret.ts"],
            [],
        ):
            with self.subTest(changed_files=changed_files):
                with self.assertRaisesRegex(
                    replica_ctl.ReplicaCtlError,
                    "src/core|test/core|editable paths|forbidden paths|at least one changed file",
                ):
                    self.controller.handoff(
                        task_id="TASK-CORE",
                        owner="core-builder",
                        lease_id=claim["lease"]["lease_id"],
                        lease_epoch=claim["lease"]["epoch"],
                        summary="Attempted out-of-scope handoff",
                        changed_files=changed_files,
                    )
                state = self.load_state()
                self.assertEqual(state["tasks"]["TASK-CORE"]["status"], "claimed")
                self.assertEqual(state["tasks"]["TASK-CORE"]["lease"]["lease_id"], claim["lease"]["lease_id"])

        completed = self.controller.handoff(
            task_id="TASK-CORE",
            owner="core-builder",
            lease_id=claim["lease"]["lease_id"],
            lease_epoch=claim["lease"]["epoch"],
            summary="Core contract ready",
            changed_files=["src/core/context.ts", "test/core/store-principal.test.ts"],
        )
        self.assertEqual(completed["task_status"], "review")

    def test_tampered_core_contract_handoff_cannot_validate_or_be_accepted(self):
        self.controller.add_task(
            task_id="TASK-CORE",
            goal="Edit the core contract",
            task_kind="core_contract_builder",
            editable_paths=["src/core/context.ts"],
        )
        claim = self.controller.claim(task_id="TASK-CORE", owner="core-builder")
        completed = self.controller.handoff(
            task_id="TASK-CORE",
            owner="core-builder",
            lease_id=claim["lease"]["lease_id"],
            lease_epoch=claim["lease"]["epoch"],
            summary="Core contract ready",
            changed_files=["src/core/context.ts"],
        )
        state = self.load_state()
        state["handoffs"][completed["handoff"]["handoff_id"]]["changed_files"] = [
            "src/apps/storefront/page.tsx"
        ]
        self.controller.store.atomic_write(state)

        validation = self.controller.validate()
        self.assertFalse(validation["valid"])
        self.assertTrue(any("changed files" in error for error in validation["errors"]), validation["errors"])
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.accept_handoff(
                handoff_id=completed["handoff"]["handoff_id"],
                accepted_by="coordinator",
                result="merged",
            )

    def test_tampered_core_contract_handoff_cannot_enter_forbidden_path(self):
        self.controller.add_task(
            task_id="TASK-CORE",
            goal="Edit the core contract",
            task_kind="core_contract_builder",
            editable_paths=["src/core"],
            forbidden_paths=["src/core/protected"],
        )
        claim = self.controller.claim(task_id="TASK-CORE", owner="core-builder")
        completed = self.controller.handoff(
            task_id="TASK-CORE",
            owner="core-builder",
            lease_id=claim["lease"]["lease_id"],
            lease_epoch=claim["lease"]["epoch"],
            summary="Core contract ready",
            changed_files=["src/core/context.ts"],
        )
        state = self.load_state()
        state["handoffs"][completed["handoff"]["handoff_id"]]["changed_files"] = [
            "src/core/PROTECTED/secret.ts"
        ]
        self.controller.store.atomic_write(state)

        validation = self.controller.validate()
        self.assertFalse(validation["valid"])
        self.assertTrue(any("forbidden paths" in error for error in validation["errors"]), validation["errors"])
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.accept_handoff(
                handoff_id=completed["handoff"]["handoff_id"],
                accepted_by="coordinator",
                result="merged",
            )

    def test_persisted_generic_task_cannot_bypass_visual_web_policy(self):
        self.add_gap()
        self.add_task()
        state = self.load_state()
        state["project"]["web"] = {
            "fidelity": "pixel",
            "asset_rights": "explicit_authorized",
        }
        state["project"]["fingerprint"] = replica_ctl._fingerprint(state["project"])
        self.controller.store.atomic_write(state)

        validation = self.controller.validate()
        self.assertFalse(validation["valid"])
        self.assertTrue(
            any("task_kind" in error and "visual/pixel" in error for error in validation["errors"]),
            validation["errors"],
        )
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.claim(task_id="TASK-1", owner="legacy-agent")

    def test_pixel_web_gap_cannot_close_with_an_arbitrary_evidence_label(self):
        pixel_root = self.root / "pixel-code"
        pixel_root.mkdir()
        controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="pixel-project",
            workspace_root=self.workspace_root,
            code_root=str(pixel_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="pixel",
            asset_rights="explicit_authorized",
        )
        controller.add_gap(
            gap_id="GAP-WEB-QA",
            title="Pixel mismatch",
            priority="P0",
            scenario_ids=["SCN-WEB"],
            reference_evidence=["EVD-REF"],
            replica_evidence=["EVD-REP"],
            acceptance=["Pixel gate passes"],
        )

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            controller.close_gap(
                gap_id="GAP-WEB-QA",
                qa_evidence=["EVD-INDEPENDENT-QA"],
            )
        self.assertEqual(caught.exception.code, "qa_evidence_required")

    def test_strict_visual_workflow_requires_declared_scope_qa(self):
        visual_root = self.root / "strict-visual-code"
        visual_root.mkdir()
        controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="strict-visual-project",
            workspace_root=self.workspace_root / "strict-visual",
            code_root=str(visual_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="visual",
            asset_rights="reference_only",
        )
        controller.add_gap(
            gap_id="GAP-VISUAL-QA",
            title="Visual mismatch",
            priority="P1",
            scenario_ids=["SCN-VISUAL"],
            reference_evidence=["EVD-REF"],
            replica_evidence=["EVD-REP"],
            acceptance=["Declared-scope QA passes"],
        )
        with mock.patch.object(
            replica_ctl,
            "_verify_web_qa_report",
            return_value={"path": "reports/qa.json", "sha256": "0" * 64},
        ) as verifier:
            controller.close_gap(
                gap_id="GAP-VISUAL-QA",
                qa_evidence=["EVD-INDEPENDENT-QA"],
                qa_report="reports/qa.json",
                qa_report_sha256="0" * 64,
            )
        self.assertIs(verifier.call_args.args[3], True)

    def test_start_uses_expected_layout_and_never_overwrites(self):
        self.assertTrue(self.start_result["created"])
        self.assertEqual(self.controller.workspace, self.workspace_root.resolve() / "sample-project")
        for directory_name in ("scenarios", "evidence", "handoffs", "reports"):
            self.assertTrue((self.controller.workspace / directory_name).is_dir())
        before = self.controller.store.state_path.read_bytes()
        before_stat = self.controller.store.state_path.stat()

        _, second = replica_ctl.ReplicaController.start_project(
            project_id="sample-project",
            workspace_root=self.workspace_root,
            code_root=str(self.root / "different-code"),
            reference_id="https://different.example.test",
            reference_platform="web",
            replica_id="different-replica",
            replica_platform="android",
        )

        after = self.controller.store.state_path.read_bytes()
        after_stat = self.controller.store.state_path.stat()
        self.assertFalse(second["created"])
        self.assertFalse(second["ok"])
        self.assertTrue(second["unchanged"])
        self.assertEqual(second["action_required"], "resume")
        self.assertTrue(second["identity_mismatches"])
        self.assertEqual(before, after)
        self.assertEqual(before_stat.st_mtime_ns, after_stat.st_mtime_ns)

    def test_empty_project_cannot_be_marked_complete(self):
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.checkpoint(
                summary="No work was performed",
                run_state="complete",
                evidence_ids=["EVD-self-reported"],
            )
        self.assertEqual(self.controller.status()["run"]["state"], "active")

    def test_project_component_is_windows_safe_and_allows_chinese(self):
        invalid_components = (
            "CON",
            "con.txt",
            "PRN",
            "AUX.json",
            "NUL",
            "COM1",
            "lpt9.log",
            "bad:name",
            "bad<name",
            "bad>name",
            'bad"name',
            "bad|name",
            "bad?name",
            "bad*name",
            "bad/name",
            "bad\\name",
            "trailing.",
            "trailing ",
            "control\x1f",
            "delete\x7f",
        )
        for value in invalid_components:
            with self.subTest(value=repr(value)):
                with self.assertRaises(replica_ctl.ReplicaCtlError):
                    replica_ctl._safe_component(value, "project_id")

        self.assertEqual(replica_ctl._safe_component("复刻项目-一号", "project_id"), "复刻项目-一号")
        chinese_controller, result = replica_ctl.ReplicaController.start_project(
            project_id="复刻项目-一号",
            workspace_root=self.root / "chinese-root",
            code_root=str(self.code_root),
            reference_id="reference-app",
            reference_platform="web",
            replica_id="replica-app",
            replica_platform="android",
        )
        self.assertTrue(result["created"])
        self.assertEqual(chinese_controller.workspace.name, "复刻项目-一号")

    def test_cli_start_contract_and_json_status(self):
        another_root = self.root / "cli-root"
        start_command = [
            sys.executable,
            str(SCRIPT),
            "start",
            "--project-id",
            "cli-project",
            "--workspace-root",
            str(another_root),
            "--code-root",
            str(self.code_root),
            "--reference-id",
            "reference-app",
            "--reference-platform",
            "windows",
            "--replica-id",
            "replica-app",
            "--replica-platform",
            "macos",
            "--scope-id",
            "checkout-flow-v1",
            "--reference-write-policy",
            "read_only",
        ]
        start = subprocess.run(
            start_command,
            text=True,
            capture_output=True,
            check=True,
        )
        created = json.loads(start.stdout)
        self.assertTrue(created["ok"])
        self.assertTrue(created["created"])

        repeated = subprocess.run(start_command, text=True, capture_output=True)
        self.assertEqual(repeated.returncode, 4)
        repeated_result = json.loads(repeated.stdout)
        self.assertFalse(repeated_result["ok"])
        self.assertTrue(repeated_result["unchanged"])
        self.assertEqual(repeated_result["action_required"], "resume")

        status = subprocess.run(
            [sys.executable, str(SCRIPT), "status", "--workspace", created["workspace"]],
            text=True,
            capture_output=True,
            check=True,
        )
        summary = json.loads(status.stdout)
        self.assertEqual(summary["project_id"], "cli-project")
        self.assertEqual(summary["counts"]["active_leases"], 0)

    def test_checkpoint_and_status_do_not_store_secret_material(self):
        result = self.controller.checkpoint(
            summary="Baseline captured",
            phase="diff",
            next_actions=["Create the highest severity Gap"],
            evidence_ids=["EVD-1"],
        )
        self.assertEqual(result["checkpoint"]["phase"], "diff")
        status = self.controller.status()
        self.assertEqual(status["run"]["phase"], "diff")
        revision = status["revision"]
        self.controller.status()
        self.assertEqual(self.controller.status()["revision"], revision)

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.checkpoint(summary="authorization: Bearer definitely-a-secret")
        self.assertEqual(caught.exception.code, "sensitive_input_rejected")
        raw = self.controller.store.state_path.read_text(encoding="utf-8")
        self.assertNotIn("definitely-a-secret", raw)

    def test_add_commands_are_non_overwriting_and_validate_dependencies(self):
        self.add_gap()
        self.add_task()
        original = self.load_state()["tasks"]["TASK-1"]
        with self.assertRaises(replica_ctl.ReplicaCtlError):
            self.controller.add_task(task_id="TASK-1", goal="Replace existing", gap_ids=["GAP-1"])
        self.assertEqual(self.load_state()["tasks"]["TASK-1"], original)

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.add_task(task_id="TASK-2", goal="Bad dependency", dependencies=["MISSING"])
        self.assertEqual(caught.exception.code, "missing_dependency")

    def test_web_builder_without_preflight_report_is_rejected(self):
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.add_task(task_id="TASK-WEB", goal="Build Web UI", task_kind="web_builder")
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_web_builder_self_reported_missing_file_is_rejected(self):
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.add_task(
                task_id="TASK-WEB",
                goal="Build Web UI",
                task_kind="web_builder",
                preflight_report="reports/does-not-exist.json",
                preflight_sha256="0" * 64,
                preflight_scope_id="CMP-home",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_web_builder_failed_preflight_report_is_rejected(self):
        report, digest, _ = self.write_preflight(ok=False, status="fail")
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.add_task(
                task_id="TASK-WEB",
                goal="Build Web UI",
                task_kind="web_builder",
                preflight_report=report,
                preflight_sha256=digest,
                preflight_scope_id="CMP-home",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_web_builder_preflight_hash_mismatch_is_rejected(self):
        report, _, _ = self.write_preflight()
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.add_task(
                task_id="TASK-WEB",
                goal="Build Web UI",
                task_kind="web_builder",
                preflight_report=report,
                preflight_sha256="0" * 64,
                preflight_scope_id="CMP-home",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_web_builder_with_valid_preflight_can_be_added_and_claimed(self):
        report, digest, _ = self.write_preflight()
        added = self.controller.add_task(
            task_id="TASK-WEB",
            goal="Build Web UI",
            task_kind="web_builder",
            preflight_report=report,
            preflight_sha256=digest,
            preflight_scope_id="CMP-home",
        )
        self.assertEqual(added["task"]["task_kind"], "web_builder")
        self.assertEqual(added["task"]["preflight_report"], report)
        self.assertEqual(added["task"]["preflight_sha256"], digest)

        claimed = self.controller.claim(task_id="TASK-WEB", owner="web-builder")
        self.assertEqual(claimed["task"]["task_kind"], "web_builder")
        self.assertEqual(claimed["task"]["preflight_report"], report)
        self.assertEqual(claimed["task"]["preflight_sha256"], digest)

    def test_strict_web_workflow_requires_page_foundation_before_builder_and_qa_is_read_only(self):
        strict_controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="sample-project",
            workspace_root=self.workspace_root / "strict",
            code_root=str(self.code_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="pixel",
            asset_rights="explicit_authorized",
        )
        foundation_report, foundation_digest, _ = self.write_preflight(
            scope_id="PAGE-home", scope_kind="page"
        )
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            strict_controller.add_task(
                task_id="TASK-FOUNDATION-BAD",
                goal="Prepare page foundation",
                task_kind="web_foundation",
                preflight_report=foundation_report,
                preflight_sha256=foundation_digest,
                preflight_scope_id="PAGE-home",
                editable_paths=["src/styles.css"],
            )
        self.assertEqual(caught.exception.code, "gate_blocked")
        strict_controller.add_task(
            task_id="TASK-FOUNDATION",
            goal="Verify page foundation evidence",
            task_kind="web_foundation",
            preflight_report=foundation_report,
            preflight_sha256=foundation_digest,
            preflight_scope_id="PAGE-home",
        )
        claim = strict_controller.claim(task_id="TASK-FOUNDATION", owner="foundation-owner")
        submitted = strict_controller.handoff(
            task_id="TASK-FOUNDATION", owner="foundation-owner",
            lease_id=claim["lease"]["lease_id"], lease_epoch=claim["lease"]["epoch"],
            summary="Page capture and foundation specification verified", result="ready",
            changed_files=[], commit_or_patch="none", validation=["builder gate: pass"],
            evidence_ids=["EVD-PAGE-FOUNDATION"], remaining_uncertainty=[], next_action="Build page scope",
        )
        strict_controller.accept_handoff(
            handoff_id=submitted["handoff"]["handoff_id"], accepted_by="coordinator",
            result="merged", validation=["foundation reviewed"], evidence_ids=["EVD-PAGE-FOUNDATION-QA"],
        )

        builder_report, builder_digest, _ = self.write_preflight(scope_id="CMP-home", scope_kind="component")
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            strict_controller.add_task(
                task_id="TASK-BUILDER-NO-FOUNDATION", goal="Build component", task_kind="web_builder",
                preflight_report=builder_report, preflight_sha256=builder_digest, preflight_scope_id="CMP-home",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

        strict_controller.add_task(
            task_id="TASK-BUILDER", goal="Build component", task_kind="web_builder",
            dependencies=["TASK-FOUNDATION"],
            preflight_report=builder_report, preflight_sha256=builder_digest, preflight_scope_id="CMP-home",
        )
        claimed = strict_controller.claim(task_id="TASK-BUILDER", owner="web-builder")
        self.assertEqual(claimed["task"]["task_kind"], "web_builder")

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            strict_controller.add_task(
                task_id="TASK-QA-BAD", goal="Review component", task_kind="web_qa",
                editable_paths=["src/component.tsx"],
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_reference_only_structure_builder_accepts_partial_but_web_builder_does_not(self):
        controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="sample-project",
            workspace_root=self.workspace_root / "structure-only",
            code_root=str(self.code_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="pixel",
            asset_rights="reference_only",
        )
        controller.add_gap(
            gap_id="GAP-STRUCTURE",
            title="Protected assets block pixel work",
            priority="P1",
            scenario_ids=["SCN-1"],
            reference_evidence=["EVD-REF"],
            replica_evidence=[],
            acceptance=["Structure converges without pixel claim"],
        )
        foundation_report, foundation_digest, _ = self.write_preflight(
            scope_id="PAGE-home", scope_kind="page", partial_font=True
        )
        controller.add_task(
            task_id="TASK-FOUNDATION",
            goal="Verify page structure evidence",
            gap_ids=["GAP-STRUCTURE"],
            task_kind="web_foundation",
            preflight_report=foundation_report,
            preflight_sha256=foundation_digest,
            preflight_scope_id="PAGE-home",
        )
        claim = controller.claim(task_id="TASK-FOUNDATION", owner="foundation-owner")
        handoff = controller.handoff(
            task_id="TASK-FOUNDATION",
            owner="foundation-owner",
            lease_id=claim["lease"]["lease_id"],
            lease_epoch=claim["lease"]["epoch"],
            summary="Partial page foundation verified",
            result="ready",
        )
        controller.accept_handoff(
            handoff_id=handoff["handoff"]["handoff_id"],
            accepted_by="coordinator",
            result="merged",
        )

        component_report, component_digest, component_path = self.write_preflight(
            scope_id="CMP-structure", scope_kind="component", partial_font=True
        )
        self.assertEqual(
            json.loads(component_path.read_text(encoding="utf-8"))["equivalence_scope"],
            "partial_excludes_visible_assets",
        )
        controller.add_task(
            task_id="TASK-STRUCTURE",
            goal="Implement observed text and geometry without protected assets",
            gap_ids=["GAP-STRUCTURE"],
            dependencies=["TASK-FOUNDATION"],
            task_kind="web_structure_builder",
            preflight_report=component_report,
            preflight_sha256=component_digest,
            preflight_scope_id="CMP-structure",
            editable_paths=["src/component.tsx"],
        )
        claimed = controller.claim(task_id="TASK-STRUCTURE", owner="structure-builder")
        self.assertEqual(claimed["task"]["task_kind"], "web_structure_builder")

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            controller.add_task(
                task_id="TASK-PIXEL",
                goal="Incorrectly use partial evidence for pixel work",
                gap_ids=["GAP-STRUCTURE"],
                dependencies=["TASK-FOUNDATION"],
                task_kind="web_builder",
                preflight_report=component_report,
                preflight_sha256=component_digest,
                preflight_scope_id="CMP-structure",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_authorized_project_rejects_partial_page_foundation(self):
        controller, _ = replica_ctl.ReplicaController.start_project(
            project_id="sample-project",
            workspace_root=self.workspace_root / "authorized-partial",
            code_root=str(self.code_root),
            reference_id="https://reference.example.test",
            reference_platform="web",
            replica_id="local-replica",
            replica_platform="web",
            web_fidelity="pixel",
            asset_rights="explicit_authorized",
        )
        report, digest, _ = self.write_preflight(
            scope_id="PAGE-home", scope_kind="page", partial_font=True
        )
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            controller.add_task(
                task_id="TASK-FOUNDATION",
                goal="Incorrect partial foundation",
                task_kind="web_foundation",
                preflight_report=report,
                preflight_sha256=digest,
                preflight_scope_id="PAGE-home",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_web_builder_tampered_preflight_is_rejected_before_claim(self):
        report, digest, report_path = self.write_preflight()
        self.controller.add_task(
            task_id="TASK-WEB",
            goal="Build Web UI",
            task_kind="web_builder",
            preflight_report=report,
            preflight_sha256=digest,
            preflight_scope_id="CMP-home",
        )
        report_path.write_text('{"gate":"web_fidelity_gate","ok":true,"status":"pass"}', encoding="utf-8")

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.claim(task_id="TASK-WEB", owner="web-builder")
        self.assertEqual(caught.exception.code, "gate_blocked")
        task = self.load_state()["tasks"]["TASK-WEB"]
        self.assertEqual(task["status"], "ready")
        self.assertIsNone(task["lease"])

    def test_web_builder_tampered_manifest_is_rejected_before_claim(self):
        report, digest, _ = self.write_preflight()
        self.controller.add_task(
            task_id="TASK-WEB",
            goal="Build Web UI",
            task_kind="web_builder",
            preflight_report=report,
            preflight_sha256=digest,
            preflight_scope_id="CMP-home",
        )
        (self.code_root / "reports" / "web-fidelity-manifest.json").write_text(
            '{"schema_version":1,"scope":{"scope_id":"CMP-other"},"assets":[]}',
            encoding="utf-8",
        )

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.claim(task_id="TASK-WEB", owner="web-builder")
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_web_builder_tampered_referenced_artifact_is_rejected_before_claim(self):
        report, digest, _ = self.write_preflight()
        self.controller.add_task(
            task_id="TASK-WEB",
            goal="Build Web UI",
            task_kind="web_builder",
            preflight_report=report,
            preflight_sha256=digest,
            preflight_scope_id="CMP-home",
        )
        component_spec = self.code_root / "reports" / "component-spec.json"
        component_spec.write_text("{}", encoding="utf-8")

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.claim(task_id="TASK-WEB", owner="web-builder")
        self.assertEqual(caught.exception.code, "gate_blocked")
        self.assertIn("artifacts no longer pass", str(caught.exception))

    def test_web_builder_scope_mismatch_is_rejected(self):
        report, digest, _ = self.write_preflight()
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.add_task(
                task_id="TASK-WEB",
                goal="Build Web UI",
                task_kind="web_builder",
                preflight_report=report,
                preflight_sha256=digest,
                preflight_scope_id="CMP-other",
            )
        self.assertEqual(caught.exception.code, "gate_blocked")

    def test_legacy_generic_task_without_new_fields_remains_claimable(self):
        self.add_gap()
        self.add_task()
        state = self.load_state()
        task = state["tasks"]["TASK-1"]
        task.pop("task_kind")
        task.pop("preflight_report")
        task.pop("preflight_sha256")
        task.pop("preflight_scope_id")
        self.controller.store.atomic_write(state)

        self.assertTrue(self.controller.validate()["valid"])
        claimed = self.controller.claim(task_id="TASK-1", owner="legacy-agent")
        self.assertEqual(claimed["task"]["task_kind"], "generic")
        self.assertEqual(claimed["task"]["preflight_report"], "")
        self.assertEqual(claimed["task"]["preflight_sha256"], "")

    def test_claim_is_atomic_across_task_and_resources(self):
        self.add_gap()
        self.add_task(task_id="TASK-1", resources=["code:shared", "surface:replica"])
        self.add_task(task_id="TASK-2", resources=["code:shared"])

        claim = self.controller.claim(task_id="TASK-1", owner="agent-a", ttl_seconds=30)
        self.assertEqual(claim["lease"]["epoch"], 1)
        state = self.load_state()
        self.assertEqual(state["resource_leases"]["code:shared"]["task_id"], "TASK-1")
        self.assertEqual(state["resource_leases"]["surface:replica"]["task_id"], "TASK-1")

        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.claim(task_id="TASK-2", owner="agent-b")
        self.assertEqual(caught.exception.code, "resource_conflict")
        state = self.load_state()
        self.assertEqual(state["tasks"]["TASK-2"]["status"], "ready")
        self.assertIsNone(state["tasks"]["TASK-2"]["lease"])

    def test_parallel_cli_claim_has_exactly_one_winner(self):
        self.add_gap()
        self.add_task()
        command = [
            sys.executable,
            str(SCRIPT),
            "--workspace",
            str(self.controller.workspace),
            "claim",
            "--task-id",
            "TASK-1",
        ]
        processes = [
            subprocess.Popen(command + ["--owner", "agent-%d" % index], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for index in range(8)
        ]
        results = [process.communicate(timeout=10) + (process.returncode,) for process in processes]
        winners = [result for result in results if result[2] == 0]
        losers = [result for result in results if result[2] != 0]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(len(losers), 7, results)
        self.assertTrue(json.loads(winners[0][0])["lease"]["lease_id"])
        self.assertTrue(all(json.loads(item[1])["ok"] is False for item in losers))
        self.assertEqual(self.controller.validate()["errors"], [])

    def test_heartbeat_requires_lease_identity_and_preserves_epoch(self):
        self.add_gap()
        self.add_task()
        start = datetime.datetime(2026, 1, 1, tzinfo=UTC)
        claim = self.controller.claim(task_id="TASK-1", owner="agent-a", ttl_seconds=10, now=start)
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.heartbeat(task_id="TASK-1", owner="agent-a", now=start)
        self.assertEqual(caught.exception.code, "lease_identity_required")

        heartbeat = self.controller.heartbeat(
            task_id="TASK-1",
            owner="agent-a",
            lease_id=claim["lease"]["lease_id"],
            lease_epoch=1,
            ttl_seconds=60,
            now=start + datetime.timedelta(seconds=8),
        )
        self.assertEqual(heartbeat["lease_epoch"], 1)
        self.assertEqual(replica_ctl.parse_time(heartbeat["expires_at"]), start + datetime.timedelta(seconds=68))

    def test_handoff_is_self_contained_and_releases_all_resources(self):
        self.add_gap()
        self.add_task(resources=["code:src/feature", "surface:replica-web"])
        claim = self.controller.claim(task_id="TASK-1", owner="agent-a")
        handoff_result = self.controller.handoff(
            task_id="TASK-1",
            owner="agent-a",
            lease_id=claim["lease"]["lease_id"],
            lease_epoch=claim["lease"]["epoch"],
            summary="Implemented and focused tests passed",
            result="ready",
            changed_files=["src/feature/view.ts"],
            commit_or_patch="commit:abc",
            validation=["unit: pass", "replay: pass"],
            evidence_ids=["EVD-QA-INPUT"],
            remaining_uncertainty=["Independent QA still required"],
            next_action="Coordinator reviews, merges, and assigns QA.",
        )
        handoff = handoff_result["handoff"]
        self.assertEqual(handoff_result["task_status"], "review")
        for key in ("task", "gaps", "lease", "summary", "changed_files", "validation", "next_action"):
            self.assertIn(key, handoff)
        self.assertEqual(handoff["task"]["inputs"], ["EVD-REF-1", "EVD-REP-1"])
        state = self.load_state()
        self.assertEqual(state["resource_leases"], {})
        self.assertIsNone(state["tasks"]["TASK-1"]["lease"])
        self.assertIn(handoff["handoff_id"], state["handoffs"])
        self.assertEqual(self.controller.status()["counts"]["pending_handoffs"], 1)

        accepted = self.controller.accept_handoff(
            handoff_id=handoff["handoff_id"],
            accepted_by="coordinator",
            result="merged",
            validation=["handoff scope reviewed"],
            evidence_ids=["EVD-MERGE-1"],
        )
        self.assertEqual(accepted["task_status"], "done")
        self.assertEqual(self.controller.status()["counts"]["pending_handoffs"], 0)

        with self.assertRaises(replica_ctl.ReplicaCtlError):
            self.controller.heartbeat(
                task_id="TASK-1",
                owner="agent-a",
                lease_id=claim["lease"]["lease_id"],
            )

    def test_partial_handoff_requeues_with_incremented_next_epoch(self):
        self.add_gap()
        self.add_task()
        first = self.controller.claim(task_id="TASK-1", owner="agent-a")
        self.controller.handoff(
            task_id="TASK-1",
            owner="agent-a",
            lease_id=first["lease"]["lease_id"],
            summary="Partially implemented",
            result="partial",
        )
        second = self.controller.claim(task_id="TASK-1", owner="agent-b")
        self.assertEqual(second["lease"]["epoch"], 2)
        with self.assertRaises(replica_ctl.ReplicaCtlError):
            self.controller.handoff(
                task_id="TASK-1",
                owner="agent-a",
                lease_id=first["lease"]["lease_id"],
                summary="Late stale handoff",
            )

    def test_rejected_handoff_requeues_and_stale_decision_cannot_repeat(self):
        self.add_gap()
        self.add_task()
        claim = self.controller.claim(task_id="TASK-1", owner="agent-a")
        completed = self.controller.handoff(
            task_id="TASK-1",
            owner="agent-a",
            lease_id=claim["lease"]["lease_id"],
            summary="Ready for review",
        )
        handoff_id = completed["handoff"]["handoff_id"]
        decision = self.controller.accept_handoff(
            handoff_id=handoff_id,
            accepted_by="coordinator",
            result="rejected",
            note="Validation evidence is incomplete.",
        )
        self.assertEqual(decision["task_status"], "ready")
        next_claim = self.controller.claim(task_id="TASK-1", owner="agent-b")
        self.assertEqual(next_claim["lease"]["epoch"], 2)
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.accept_handoff(
                handoff_id=handoff_id,
                accepted_by="coordinator",
                result="merged",
            )
        self.assertEqual(caught.exception.code, "already_decided")

    def test_complete_checkpoint_is_gated_by_merge_gap_and_lease_state(self):
        self.add_gap()
        self.add_task()
        claim = self.controller.claim(task_id="TASK-1", owner="agent-a")
        submitted = self.controller.handoff(
            task_id="TASK-1",
            owner="agent-a",
            lease_id=claim["lease"]["lease_id"],
            summary="Implementation ready for Coordinator review",
        )
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.checkpoint(summary="Premature completion", run_state="complete")
        self.assertEqual(self.controller.status()["run"]["state"], "active")

        self.controller.accept_handoff(
            handoff_id=submitted["handoff"]["handoff_id"],
            accepted_by="coordinator",
            result="merged",
        )
        self.controller.close_gap(gap_id="GAP-1", qa_evidence=["EVD-INDEPENDENT-QA"])
        complete = self.controller.checkpoint(
            summary="Acceptance gates passed",
            run_state="complete",
            evidence_ids=["EVD-INDEPENDENT-QA"],
        )
        self.assertEqual(complete["checkpoint"]["run_state"], "complete")
        self.assertTrue(self.controller.validate()["valid"])

    def test_reap_requires_confirmation_and_never_touches_unexpired_lease(self):
        self.add_gap()
        self.add_task()
        start = datetime.datetime(2026, 1, 1, tzinfo=UTC)
        self.controller.claim(task_id="TASK-1", owner="agent-a", ttl_seconds=10, now=start)
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.reap(confirm_inactive=False, now=start + datetime.timedelta(seconds=20))
        self.assertEqual(caught.exception.code, "confirmation_required")

        early = self.controller.reap(confirm_inactive=True, now=start + datetime.timedelta(seconds=5))
        self.assertEqual(early["reaped_count"], 0)
        self.assertEqual(self.load_state()["tasks"]["TASK-1"]["status"], "claimed")

        reaped = self.controller.reap(
            confirm_inactive=True,
            task_id="TASK-1",
            confirmed_by="coordinator",
            reason="Checked agent process and worktree; both are inactive.",
            now=start + datetime.timedelta(seconds=11),
        )
        self.assertEqual(reaped["reaped_count"], 1)
        state = self.load_state()
        self.assertEqual(state["tasks"]["TASK-1"]["status"], "ready")
        self.assertEqual(state["resource_leases"], {})
        self.assertTrue(state["abandoned_leases"][0]["confirmed_inactive"])

    def test_close_gap_refuses_missing_qa_evidence(self):
        self.add_gap()
        with self.assertRaises(replica_ctl.ReplicaCtlError) as caught:
            self.controller.close_gap(gap_id="GAP-1", qa_evidence=[])
        self.assertEqual(caught.exception.code, "qa_evidence_required")
        self.assertEqual(self.load_state()["gaps"]["GAP-1"]["status"], "open")

        result = self.controller.close_gap(
            gap_id="GAP-1",
            qa_evidence=["EVD-QA-1", "EVD-QA-2"],
            qa_by="independent-qa",
        )
        self.assertEqual(result["gap"]["status"], "closed")
        self.assertEqual(result["gap"]["closure"]["qa_evidence"], ["EVD-QA-1", "EVD-QA-2"])

    def test_validate_detects_credentials_without_echoing_values(self):
        state = self.load_state()
        state["runtime"] = {"access_token": "never-print-this-value"}
        self.controller.store.atomic_write(state)
        result = self.controller.validate()
        self.assertFalse(result["valid"])
        rendered = json.dumps(result)
        self.assertIn("forbidden credential field", rendered)
        self.assertNotIn("never-print-this-value", rendered)
        with self.assertRaises(replica_ctl.StateValidationError):
            self.controller.add_gap(gap_id="GAP-X", title="Must refuse mutation")

    def test_validate_detects_resource_lease_inconsistency(self):
        self.add_gap()
        self.add_task()
        self.controller.claim(task_id="TASK-1", owner="agent-a")
        state = self.load_state()
        state["resource_leases"]["code:src/feature"]["task_id"] = "TASK-OTHER"
        self.controller.store.atomic_write(state)
        result = self.controller.validate()
        self.assertFalse(result["valid"])
        self.assertTrue(any("belongs to another lease" in item or "without an active lease" in item for item in result["errors"]))

    def test_validate_reports_malformed_reference_lists_without_crashing(self):
        self.add_gap()
        self.add_task()
        state = self.load_state()
        state["tasks"]["TASK-1"]["gap_ids"] = [{}]
        state["tasks"]["TASK-1"]["dependencies"] = [{}]
        state["tasks"]["TASK-1"]["handoff_ids"] = [{}]
        self.controller.store.atomic_write(state)
        result = self.controller.validate()
        self.assertFalse(result["valid"])
        self.assertTrue(any("must contain non-empty strings" in item for item in result["errors"]))

    def test_init_alias_and_workspace_auto_discovery(self):
        alias_root = self.root / "alias-root"
        command = [
            sys.executable,
            str(SCRIPT),
            "init",
            "--project-id",
            "alias-project",
            "--workspace-root",
            str(alias_root / ".replica"),
            "--code-root",
            str(self.code_root),
            "--reference-id",
            "ref",
            "--reference-platform",
            "android",
            "--replica-id",
            "rep",
            "--replica-platform",
            "ios",
        ]
        created = json.loads(subprocess.run(command, text=True, capture_output=True, check=True).stdout)
        discovered = subprocess.run(
            [sys.executable, str(SCRIPT), "status"],
            cwd=alias_root,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(json.loads(discovered.stdout)["workspace"], created["workspace"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
