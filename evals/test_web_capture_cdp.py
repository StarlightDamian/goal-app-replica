"""Safety-boundary tests for the zero-dependency CDP capture runner."""

from __future__ import annotations

import http.server
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_capture_cdp.js"


class _TargetListHandler(http.server.BaseHTTPRequestHandler):
    request_paths: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        type(self).request_paths.append(self.path)
        if self.path != "/json/list":
            self.send_error(404)
            return
        payload = json.dumps(
            [
                {
                    "id": "page-1",
                    "type": "page",
                    "url": "https://target.example.test/private?token=target-secret",
                    "webSocketDebuggerUrl": (
                        "ws://127.0.0.1:9/devtools/page/page-1?token=websocket-secret"
                    ),
                }
            ]
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class WebCaptureCdpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        version = subprocess.run(["node", "--version"], text=True, capture_output=True)
        if version.returncode != 0:
            raise unittest.SkipTest("Node.js is unavailable")
        major = int(version.stdout.strip().lstrip("v").split(".", 1)[0])
        if major < 24:
            raise unittest.SkipTest("Node.js 24+ is required")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        self.state_contract = self.project_root / "state-contract.json"
        self.state_contract.write_text(json.dumps({
            "schemaVersion": "web-capture-state-contract/1.0",
            "expectedPublicLocation": "https://target.example.test/private",
            "document": {"minScrollHeight": 1},
            "selectors": [{"selector": "main", "minCount": 1, "minVisibleCount": 1}],
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_capture(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        context_arguments = (
            "--project-id", "project-1", "--page-id", "home", "--scenario-id", "SCN-home",
            "--baseline-id", "BL-home", "--viewport-id", "1280x720@1", "--state-id", "default",
            "--side", "reference",
            "--state-contract", str(self.state_contract),
            "--font-scope-root", "main",
        )
        return subprocess.run(
            ["node", str(SCRIPT), *arguments, *context_arguments],
            text=True,
            capture_output=True,
            timeout=15,
        )

    def test_source_declares_only_read_only_capture_methods_and_bundle_contract(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"web-capture-bundle/2.0"',
            'client.call("Browser.getVersion"',
            'client.call("Page.getLayoutMetrics"',
            'client.call("Runtime.evaluate"',
            'client.call("DOMSnapshot.captureSnapshot"',
            'client.call("Accessibility.getFullAXTree"',
            '"CSS.getPlatformFontsForNode"',
            'client.call("Page.captureScreenshot"',
            "navigationFingerprint",
            "document.fonts.ready",
            "renderingEnvironment",
            "screenshotPolicy",
            '"environment.json"',
            '"inventory.json"',
            '"dom-snapshot.json"',
            '"ax-tree.json"',
            '"font-usage.json"',
            '"state-contract.json"',
            '"state-witness.json"',
            '"state-witness-post.json"',
            '"reference.png"',
            '"capture-bundle.json"',
            'path.join(__dirname, "web_asset_probe.js")',
            "rawPersisted: false",
            '"public-observable"',
            'normalizedPublicDomSnapshot',
            'normalizedPublicAxTree',
            'normalizedObservableValuesPersisted: true',
            "async function atomicWrite",
            "captureStateWitness",
        ):
            self.assertIn(required, source)
        for forbidden in (
            'client.call("Page.reload"',
            'client.call("Page.navigate"',
            'client.call("Input.dispatchMouseEvent"',
            'client.call("DOM.setAttributeValue"',
            'client.call("Network.enable"',
            'client.call("Browser.setDownloadBehavior"',
        ):
            self.assertNotIn(forbidden, source)

    def test_non_loopback_endpoint_is_rejected_without_network_access(self) -> None:
        result = self.run_capture(
            "--endpoint",
            "http://example.com:9222",
            "--project-root",
            str(self.project_root),
            "--target-id",
            "page-1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback", result.stderr)

    def test_explicit_target_selector_is_required(self) -> None:
        result = self.run_capture(
            "--endpoint",
            "http://127.0.0.1:9222",
            "--project-root",
            str(self.project_root),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one explicit", result.stderr)

    def test_target_id_and_target_url_are_mutually_exclusive(self) -> None:
        result = self.run_capture(
            "--endpoint",
            "http://127.0.0.1:9222",
            "--project-root",
            str(self.project_root),
            "--target-id",
            "page-1",
            "--target-url",
            "https://target.example.test",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one explicit", result.stderr)

    def test_output_path_escape_is_rejected_before_endpoint_access(self) -> None:
        result = self.run_capture(
            "--endpoint",
            "http://127.0.0.1:9222",
            "--project-root",
            str(self.project_root),
            "--target-id",
            "page-1",
            "--output-dir",
            "../outside",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("project-root-relative", result.stderr)
        self.assertFalse((self.project_root.parent / "outside").exists())

    def test_loopback_mock_endpoint_is_queried_without_leaking_target_or_websocket_secrets(self) -> None:
        _TargetListHandler.request_paths = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetListHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = self.run_capture(
                "--endpoint",
                f"http://127.0.0.1:{server.server_port}",
                "--project-root",
                str(self.project_root),
                "--target-id",
                "page-1",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertNotEqual(result.returncode, 0)  # mock has no WebSocket server
        self.assertEqual(_TargetListHandler.request_paths, ["/json/list"])
        rendered = result.stdout + result.stderr
        self.assertNotIn("target-secret", rendered)
        self.assertNotIn("websocket-secret", rendered)
        self.assertNotIn("devtools/page/page-1", rendered)
        self.assertIn("could not connect", result.stderr)

    def test_public_observable_normalization_excludes_script_text_and_path_tokens(self) -> None:
        program = f"""
const capture = require({json.dumps(str(SCRIPT))});
const strings = [
  '#document', 'HTML', 'BODY', 'SCRIPT', '#text',
  'window.__BOOTSTRAP__={{access_token:\"TOP_SECRET\"}}',
  'DIV', 'hello public', 'IMG', 'src',
  'https://cdn.example.test/path-token-TOP_SECRET/logo.png?session=TOP_SECRET'
];
const raw = {{ strings, documents: [{{
  documentURL: 0,
  nodes: {{
    nodeType: [9,1,1,1,3,1,3,1],
    nodeName: [0,1,2,3,4,6,4,8],
    nodeValue: [0,0,0,0,5,0,7,0],
    parentIndex: [-1,0,1,2,3,2,5,2],
    attributes: [[],[],[],[],[],[],[],[9,10]]
  }},
  layout: {{ nodeIndex: [5,6,7], bounds: [[0,0,10,10],[0,0,10,10],[0,0,10,10]], text: [0,7,0], styles: [[],[],[]], paintOrders: [1,2,3] }}
}}] }};
console.log(JSON.stringify({{
  tree: capture.normalizedPublicDomSnapshot(raw),
  url: capture.publicUrl(strings[10]),
  opaqueUrl: capture.publicUrl('https://cdn.example.test/eyJhbGciOiJIUzI1NiJ9abcdefghijkl/asset.png')
}}));
"""
        result = subprocess.run(["node", "-e", program], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = result.stdout
        self.assertIn("hello public", rendered)
        self.assertIn("redacted", rendered)
        self.assertNotIn("TOP_SECRET", rendered)
        self.assertNotIn("path-token", rendered)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9abcdefghijkl", rendered)
        self.assertNotIn("__BOOTSTRAP__", rendered)

    def test_state_contract_rejects_empty_or_secret_bearing_expectations(self) -> None:
        program = f"""
const capture = require({json.dumps(str(SCRIPT))});
for (const value of [
  {{ schemaVersion: 'web-capture-state-contract/1.0' }},
  {{ schemaVersion: 'web-capture-state-contract/1.0', expectedPublicLocation: 'https://example.test/home' }},
  {{ schemaVersion: 'web-capture-state-contract/1.0', selectors: [{{selector:'main'}}] }},
  {{ schemaVersion: 'web-capture-state-contract/1.0', expectedPublicLocation: 'https://example.test/home?token=secret' }}
]) {{
  try {{ capture.stateContract(value); console.log('accepted'); }}
  catch (error) {{ console.log(error.message); }}
}}
"""
        result = subprocess.run(["node", "-e", program], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("accepted", result.stdout)
        self.assertIn("positive selector assertion", result.stdout)
        self.assertIn("observable count constraint", result.stdout)
        self.assertIn("without secrets", result.stdout)

    def test_platform_font_capture_has_a_total_timeout_signal(self) -> None:
        program = f"""
const capture = require({json.dumps(str(SCRIPT))});
const raw = {{ strings: ['#document','HTML','BODY','DIV','#text','hello'], documents: [{{
  nodes: {{ nodeType:[9,1,1,1,3], nodeName:[0,1,2,3,4], parentIndex:[-1,0,1,2,3], backendNodeId:[0,1,2,3,4], pseudoType:{{index:[],value:[]}} }},
  layout: {{ nodeIndex:[4], text:[5], bounds:[[0,0,10,10]] }}
}}] }};
const inventory = {{ visibleElements:[{{tag:'div',locator:'#target',ancestorLocators:['body','html'],geometry:{{documentX:0,documentY:0,width:10,height:10}},paintVisibility:{{paintedVisible:true}}}}], pseudoElements:[] }};
const client = {{ call(method) {{
  if (method === 'DOM.getDocument') return Promise.resolve({{}});
  if (method === 'DOM.pushNodesByBackendIdsToFrontend') return Promise.resolve({{nodeIds:[11]}});
  if (method === 'CSS.getPlatformFontsForNode') return new Promise(() => {{}});
  throw new Error(method);
}} }};
capture.capturePlatformFonts(client, raw, inventory, {{batchSize:1,perCallTimeoutMs:10,totalBudgetMs:20}})
  .then(result => console.log(JSON.stringify(result)));
"""
        result = subprocess.run(["node", "-e", program], text=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["failedNodeCount"], 1)
        self.assertEqual(payload["timedOutNodeCount"], 1)
        self.assertEqual(payload["queriedNodeCount"], 0)

    def test_font_scope_attribute_quotes_are_shell_stable(self) -> None:
        program = f"""
const capture = require({json.dumps(str(SCRIPT))});
console.log(JSON.stringify([
  capture.normalizedScopeLocator('nav[aria-label="频道导航"]'),
  capture.normalizedScopeLocator('nav[aria-label=频道导航]'),
  capture.normalizedScopeLocator("nav[aria-label='频道导航']")
]));
"""
        result = subprocess.run(["node", "-e", program], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout)
        self.assertEqual(len(set(values)), 1)
        self.assertNotIn('"', values[0])
        self.assertNotIn("'", values[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
