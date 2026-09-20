"""Real Chromium proof: capture -> stability -> paired analysis.

This is deliberately separate from the fast contract tests.  It launches an
isolated headless Chrome/Edge profile, captures actual DOM/layout/AX/PNG
artifacts through the production CDP runner, and proves that the runtime can
both accept an exact pair and localize a visible mismatch.
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "scripts" / "web_capture_cdp.js"
STABILITY = ROOT / "scripts" / "web_stability_gate.py"
ANALYZER = ROOT / "scripts" / "web_pair_analyzer.py"
VISUAL_DIFF = ROOT / "scripts" / "web_visual_diff.py"
PIPELINE = ROOT / "scripts" / "web_pipeline.py"
FIDELITY_GATE = ROOT / "scripts" / "web_fidelity_gate.py"
FONT_DIFF = ROOT / "scripts" / "web_font_diff.py"
STRUCTURE_DIFF = ROOT / "scripts" / "web_structure_diff.py"


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


def _free_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _browser_path() -> Path | None:
    candidates = [
        os.environ.get("CHROME_PATH"),
        shutil.which("chrome"),
        shutil.which("msedge"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


@unittest.skipIf(Image is None, "Pillow is unavailable")
class WebFidelityChromiumE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.browser = _browser_path()
        if cls.browser is None:
            raise unittest.SkipTest("Chrome/Edge is unavailable")
        node = subprocess.run(["node", "--version"], text=True, capture_output=True)
        if node.returncode != 0 or int(node.stdout.strip().lstrip("v").split(".", 1)[0]) < 24:
            raise unittest.SkipTest("Node.js 24+ is required")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project = Path(self.temporary.name)
        self.web = self.project / "web"
        self.web.mkdir()
        self.state_contract = self.project / "state-contract.json"
        self.state_contract.write_text(json.dumps({
            "schemaVersion": "web-capture-state-contract/1.0",
            "document": {"minScrollWidth": 360, "minScrollHeight": 180},
            "selectors": [
                {"selector": "main.card", "minCount": 1, "minVisibleCount": 1, "maxCount": 1, "maxVisibleCount": 1},
                {"selector": "main.card h1", "minCount": 1, "minVisibleCount": 1},
            ],
        }), encoding="utf-8")
        Image.new("RGB", (24, 24), (225, 0, 0)).save(self.web / "asset.png", format="PNG")
        Image.new("RGB", (48, 48), (0, 80, 210)).save(self.web / "asset-2x.png", format="PNG")
        shared = """
<meta charset="utf-8"><style>
*{box-sizing:border-box}html,body{margin:0;background:#f5f5f5;font-family:Arial,sans-serif}
.card{position:relative;width:360px;height:180px;margin:24px;padding:20px;background:white;border:1px solid #ddd;border-radius:8px}
.card::before{content:"";position:absolute;right:16px;top:16px;width:24px;height:24px;background:url('/asset.png') center/24px 24px no-repeat}
button{width:120px;height:36px;border:0;border-radius:4px;background:#e2231a;color:white;font-size:14px}
button::before{content:"\u25cf";font-family:Arial,sans-serif;margin-right:4px}
button:focus{outline:2px solid #111;outline-offset:2px}
</style>
<main class="card"><h1>Replica fixture</h1><picture><source srcset="/asset-2x.png 2x"><img id="hero" src="/asset.png" srcset="/asset.png 1x, /asset-2x.png 2x" width="24" height="24" alt="fixture"></picture><svg width="20" height="20" viewBox="0 0 20 20"><circle cx="10" cy="10" r="8" fill="#e2231a"/></svg><button autofocus>购买</button><div id="shadow"></div></main>
<section style="position:fixed;top:1000px;left:0">Offscreen rendered text must not enter the current viewport font scope.</section>
<script>document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML='<span>shadow text</span>'</script>
"""
        self.shared_html = "<!doctype html>" + shared
        (self.web / "reference.html").write_text(self.shared_html, encoding="utf-8")
        (self.web / "replica.html").write_text(self.shared_html, encoding="utf-8")
        (self.web / "mismatch.html").write_text(
            "<!doctype html><style>.card{transform:translateX(12px)}</style>" + shared,
            encoding="utf-8",
        )

        handler = functools.partial(_QuietHandler, directory=str(self.web))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

        self.cdp_port = _free_port()
        self.profile = self.project / "chrome-profile"
        self.browser_process = subprocess.Popen(
            [
                str(self.browser),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--remote-debugging-port={self.cdp_port}",
                f"--user-data-dir={self.profile}",
                "--window-size=800,600",
                "--force-device-scale-factor=1",
                self.origin + "/reference.html",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.endpoint = f"http://127.0.0.1:{self.cdp_port}"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(self.endpoint + "/json/list", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail("isolated Chromium CDP endpoint did not start")

    def tearDown(self) -> None:
        if hasattr(self, "browser_process"):
            self.browser_process.terminate()
            try:
                self.browser_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.browser_process.kill()
                self.browser_process.wait(timeout=5)
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join(timeout=5)
        self.temporary.cleanup()

    def _targets(self) -> list[dict]:
        with urllib.request.urlopen(self.endpoint + "/json/list", timeout=2) as response:
            return json.load(response)

    def _open(self, url: str) -> str:
        request = urllib.request.Request(
            self.endpoint + "/json/new?" + urllib.parse.quote(url, safe=""),
            method="PUT",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            target = json.load(response)
        return str(target["id"])

    def _capture(self, target_id: str, output: str, side: str) -> Path:
        command = [
            "node", str(CAPTURE), "--endpoint", self.endpoint,
            "--project-root", str(self.project), "--target-id", target_id,
            "--output-dir", output, "--content-policy", "public-observable",
            "--project-id", "e2e-project", "--page-id", "fixture",
            "--scenario-id", "SCN-default", "--baseline-id", "BL-e2e",
            "--viewport-id", "800x600@1", "--state-id", "default", "--side", side,
            "--state-contract", str(self.state_contract),
            "--font-scope-root", "*",
        ]
        process = subprocess.run(command, text=True, capture_output=True, timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr)
        return self.project / output / "reference.png"

    def _python(self, script: Path, *arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        process = subprocess.run(
            [sys.executable, str(script), *arguments], text=True, capture_output=True, timeout=45
        )
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        return process

    def _artifact(self, path: Path) -> dict[str, str]:
        import hashlib
        return {
            "path": path.relative_to(self.project).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def test_real_capture_is_stable_exact_and_detects_mismatch(self) -> None:
        reference_target = next(
            target["id"] for target in self._targets() if target.get("url") == self.origin + "/reference.html"
        )
        reference_first = self._capture(reference_target, "evidence/reference-1", "reference")
        reference_second = self._capture(reference_target, "evidence/reference-2", "reference")
        reference_stability = self.project / "evidence/reference-stability.json"
        self._python(
            STABILITY,
            "--project-root", str(self.project), "--sample", str(reference_first), "--sample", str(reference_second),
            "--capture-bundle", str(reference_first.parent / "capture-bundle.json"),
            "--capture-bundle", str(reference_second.parent / "capture-bundle.json"),
            "--side", "reference", "--scope-id", "CMP-button", "--mode", "pixel",
            "--output", str(reference_stability),
        )
        stability = json.loads(reference_stability.read_text(encoding="utf-8"))
        self.assertTrue(stability["ok"])

        inventory = json.loads((self.project / "evidence/reference-1/inventory.json").read_text(encoding="utf-8"))
        button_locator = next(
            element["locator"] for element in inventory["visibleElements"]
            if isinstance(element, dict) and "button" in str(element.get("locator", "")).lower()
        )
        environment = json.loads((self.project / "evidence/reference-1/environment.json").read_text(encoding="utf-8"))
        font_usage = json.loads((self.project / "evidence/reference-1/font-usage.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(inventory.get("inlineSvgs", [])), 1)
        self.assertGreaterEqual(len(inventory.get("pseudoElements", [])), 1)
        self.assertGreaterEqual(len(inventory.get("images", [])), 1)
        self.assertTrue(environment["renderingEnvironment"]["locale"])
        self.assertIsNotNone(environment["renderingEnvironment"]["timezone"])
        self.assertEqual(environment["screenshotPolicy"]["scale"], "device")
        self.assertEqual(font_usage["schemaVersion"], "web-platform-font-usage/1.0")
        self.assertFalse(font_usage["scanTruncated"])
        self.assertEqual(font_usage["failedNodeCount"], 0)
        self.assertEqual(font_usage["unmappedNodeCount"], 0, font_usage)

        replica_target = self._open(self.origin + "/replica.html")
        replica = self._capture(replica_target, "evidence/replica", "replica")
        exact_path = self.project / "evidence/exact-analysis.json"
        self._python(
            ANALYZER, "--project-root", str(self.project), "--reference", str(reference_second),
            "--replica", str(replica), "--output", str(exact_path),
        )
        exact = json.loads(exact_path.read_text(encoding="utf-8"))
        self.assertEqual(exact["metrics"]["exact_diff_pixels"], 0)

        mismatch_target = self._open(self.origin + "/mismatch.html")
        mismatch = self._capture(mismatch_target, "evidence/mismatch", "replica")
        mismatch_structure_path = self.project / "evidence/mismatch-structure.json"
        self._python(
            STRUCTURE_DIFF,
            "--project-root", str(self.project),
            "--reference", str(reference_second.parent / "inventory.json"),
            "--replica", str(mismatch.parent / "inventory.json"),
            "--root-locator", button_locator,
            "--output", str(mismatch_structure_path), expected=2,
        )
        mismatch_structure = json.loads(mismatch_structure_path.read_text(encoding="utf-8"))
        self.assertGreater(mismatch_structure["summary"]["mismatch_count"], 0)
        mismatch_path = self.project / "evidence/mismatch-analysis.json"
        self._python(
            ANALYZER, "--project-root", str(self.project), "--reference", str(reference_second),
            "--replica", str(mismatch), "--structure-report", str(mismatch_structure_path),
            "--tile-size", "32", "--output", str(mismatch_path), expected=2,
        )
        report = json.loads(mismatch_path.read_text(encoding="utf-8"))
        self.assertGreater(report["metrics"]["exact_diff_pixels"], 0)
        self.assertTrue(report["work_queue"])
        self.assertTrue(any(item["phase"] == "geometry" for item in report["work_queue"]))

        # Apply the smallest fixture implementation fix, then re-capture instead
        # of accepting the earlier exact page as proof of convergence.
        (self.web / "mismatch.html").write_text(self.shared_html, encoding="utf-8")
        repaired_target = self._open(self.origin + "/mismatch.html?repaired=1")
        repaired_first = self._capture(repaired_target, "evidence/repaired-1", "replica")
        repaired_second = self._capture(repaired_target, "evidence/repaired-2", "replica")
        repaired_stability = self.project / "evidence/replica-stability.json"
        self._python(
            STABILITY,
            "--project-root", str(self.project), "--sample", str(repaired_first), "--sample", str(repaired_second),
            "--capture-bundle", str(repaired_first.parent / "capture-bundle.json"),
            "--capture-bundle", str(repaired_second.parent / "capture-bundle.json"),
            "--side", "replica", "--scope-id", "CMP-button", "--mode", "pixel",
            "--output", str(repaired_stability),
        )
        repaired_structure_path = self.project / "evidence/repaired-structure.json"
        self._python(
            STRUCTURE_DIFF,
            "--project-root", str(self.project),
            "--reference", str(reference_second.parent / "inventory.json"),
            "--replica", str(repaired_second.parent / "inventory.json"),
            "--root-locator", button_locator,
            "--output", str(repaired_structure_path),
        )
        repaired_structure = json.loads(repaired_structure_path.read_text(encoding="utf-8"))
        self.assertTrue(repaired_structure["ok"])
        repaired_analysis_path = self.project / "evidence/repaired-analysis.json"
        self._python(
            ANALYZER, "--project-root", str(self.project), "--reference", str(reference_second),
            "--replica", str(repaired_second), "--structure-report", str(repaired_structure_path),
            "--previous-report", str(mismatch_path),
            "--output", str(repaired_analysis_path),
        )
        repaired_analysis = json.loads(repaired_analysis_path.read_text(encoding="utf-8"))
        self.assertEqual(repaired_analysis["metrics"]["exact_diff_pixels"], 0)
        self.assertEqual(repaired_analysis["trend"], "improved")

        visual_dir = self.project / "evidence/repaired-visual-diff"
        self._python(
            VISUAL_DIFF, "--project-root", str(self.project), "--reference", str(reference_second),
            "--replica", str(repaired_second), "--output-dir", str(visual_dir),
        )
        visual_report = json.loads((visual_dir / "report.json").read_text(encoding="utf-8"))
        self.assertTrue(visual_report["whole_page_pixel_equivalent"])
        font_report_path = self.project / "evidence/font-report.json"
        self._python(
            FONT_DIFF, "--project-root", str(self.project),
            "--reference", str(reference_second.parent / "font-usage.json"),
            "--replica", str(repaired_second.parent / "font-usage.json"),
            "--scope-id", "CMP-button", "--root-locator", button_locator,
            "--output", str(font_report_path),
        )
        font_report = json.loads(font_report_path.read_text(encoding="utf-8"))
        self.assertGreater(font_report["reference_summary"]["scopedNodeCount"], 0)
        self.assertGreater(font_report["reference_summary"]["scopedPseudoCount"], 0)
        self.assertEqual(
            font_report["reference_summary"]["scopedNodeCount"],
            font_report["replica_summary"]["scopedNodeCount"],
        )

        # Compile a real component-scoped manifest from the captured inventory,
        # pass the production builder gate, then attach the real paired runtime
        # evidence and pass the production QA gate.
        manifest_path = self.project / "evidence/button-manifest.json"
        self._python(
            PIPELINE, "compile-builder", "--project-root", str(self.project),
            "--bundle", str(reference_second.parent / "capture-bundle.json"),
            "--scope-id", "CMP-button", "--root-locator", button_locator,
            "--viewport", "800x600@1", "--state", "default", "--rights", "explicit_authorized",
            "--project-id", "e2e-project", "--page-id", "fixture",
            "--scenario-id", "SCN-default", "--baseline-id", "BL-e2e",
            "--output", str(manifest_path),
        )
        builder_gate = self.project / "evidence/button-builder-gate.json"
        self._python(
            FIDELITY_GATE, "--manifest", str(manifest_path), "--project-root", str(self.project),
            "--stage", "builder", "--output", str(builder_gate),
        )

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["font_fallback"] = {"checked": True, "pass": True, "unexpected_fallbacks": []}
        manifest["critical_diffs"] = [{
            "component_id": "CMP-button",
            "viewport_id": "800x600@1",
            "state_id": "default",
            "pass": True,
            "reference_capture_bundle": self._artifact(reference_second.parent / "capture-bundle.json"),
            "replica_capture_bundle": self._artifact(repaired_second.parent / "capture-bundle.json"),
            "reference_screenshot": self._artifact(reference_second),
            "replica_screenshot": self._artifact(repaired_second),
            "reference_stability": self._artifact(reference_stability),
            "replica_stability": self._artifact(repaired_stability),
            "font_report": self._artifact(font_report_path),
            "structure_report": self._artifact(repaired_structure_path),
            "diff_report": self._artifact(visual_dir / "report.json"),
            "overlay": self._artifact(visual_dir / "overlay.png"),
        }]
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        qa_gate = self.project / "evidence/button-qa-gate.json"
        self._python(
            FIDELITY_GATE, "--manifest", str(manifest_path), "--project-root", str(self.project),
            "--stage", "qa", "--output", str(qa_gate),
        )
        qa_report = json.loads(qa_gate.read_text(encoding="utf-8"))
        self.assertTrue(qa_report["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
