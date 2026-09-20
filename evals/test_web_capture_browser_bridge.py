"""Contract tests for supported Browser-tab capture adapter."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "web_capture_browser_bridge.mjs"


class WebCaptureBrowserBridgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        version = subprocess.run(["node", "--version"], text=True, capture_output=True)
        if version.returncode != 0:
            raise unittest.SkipTest("Node.js is unavailable")

    def test_source_is_fail_closed_and_component_scoped(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "a host-issued sourceReceipt is required",
            "fontScopeRoots must identify at least one captured component root",
            "totalBudgetMs: 45_000",
            "font capture was incomplete",
            "Browser tab screenshot was not a PNG",
            "selected Browser tab changed document or route during capture",
            '"state-contract.json"',
            '"state-witness.json"',
            '"source-receipt.json"',
            "fs.rm(paths.temporaryDir, { recursive: true, force: true })",
        ):
            self.assertIn(required, source)
        for forbidden in (
            'call("Page.navigate"',
            'call("Page.reload"',
            'call("Input.dispatchMouseEvent"',
            'call("Network.getCookies"',
            'call("Storage.getCookies"',
        ):
            self.assertNotIn(forbidden, source)

    def test_missing_source_receipt_fails_before_cdp_or_filesystem_access(self) -> None:
        program = f"""
import({json.dumps(SCRIPT.as_uri())}).then(async module => {{
  const tab = {{ capabilities: {{}}, screenshot() {{ throw new Error('should-not-run'); }} }};
  try {{
    await module.captureBrowserTab({{
      tab,
      projectRoot: 'Z:/must-not-be-read',
      outputDir: 'evidence/capture',
      context: {{
        projectId: 'p', pageId: 'home', scenarioId: 's', baselineId: 'b',
        viewportId: 'v', stateId: 'default', side: 'reference'
      }},
      stateContract: {{
        schemaVersion: 'web-capture-state-contract/1.0',
        expectedPublicLocation: 'https://example.test/home',
        selectors: [{{ selector: 'main', minCount: 1, minVisibleCount: 1 }}]
      }},
      fontScopeRoots: ['main']
    }});
    process.exitCode = 2;
  }} catch (error) {{
    console.log(error.message);
  }}
}});
"""
        result = subprocess.run(["node", "--input-type=module", "-e", program], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("host-issued sourceReceipt", result.stdout)

    def test_source_receipt_rejects_location_mismatch_before_capture(self) -> None:
        program = f"""
import crypto from 'node:crypto';
const module = await import({json.dumps(SCRIPT.as_uri())});
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const context = {{projectId:'p',pageId:'home',scenarioId:'s',baselineId:'b',viewportId:'v',stateId:'default',side:'reference'}};
const stateContract = {{
  schemaVersion:'web-capture-state-contract/1.0',
  expectedPublicLocation:'https://example.test/home',
  selectors:[{{selector:'main',minCount:1,minVisibleCount:1}}]
}};
const adapter = 'browser-control-in-app';
const tabId = 'tab-1';
const sessionAlias = 'test-session';
const now = Date.now();
const baseReceipt = {{
  schemaVersion:'web-capture-source-receipt/1.0',receiptId:'receipt-1',adapter,
  sessionAliasHash:sha(sessionAlias),
  tabIdentityHash:sha(JSON.stringify({{adapter,tabId,expectedPublicLocation:stateContract.expectedPublicLocation}})),
  expectedPublicLocation:stateContract.expectedPublicLocation,
  contextFingerprint:sha(JSON.stringify(context)),
  issuedAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString()
}};
const tab = {{
  id:tabId,
  capabilities:{{async get(){{throw new Error('should-not-reach-cdp');}}}},
  async screenshot(){{throw new Error('should-not-reach-screenshot');}}
}};
try {{
  await module.captureBrowserTab({{
    tab,projectRoot:'Z:/must-not-be-read',outputDir:'evidence/capture',context,stateContract,
    fontScopeRoots:['main'],sourceReceipt:{{...baseReceipt,expectedPublicLocation:'https://example.test/error'}},sessionAlias
  }});
  console.log('accepted');
}} catch (error) {{
  console.log(error.message);
}}
"""
        result = subprocess.run(["node", "--input-type=module", "-e", program], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sourceReceipt expectedPublicLocation does not match state contract", result.stdout)
        self.assertNotIn("accepted", result.stdout)
        self.assertNotIn("should-not-reach", result.stdout)

    def test_fake_supported_tab_produces_pre_post_receipt_bound_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            program = f"""
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
const module = await import({json.dumps(SCRIPT.as_uri())});
const context = {{projectId:'p',pageId:'home',scenarioId:'s',baselineId:'b',viewportId:'v',stateId:'default',side:'reference'}};
const stateContract = {{schemaVersion:'web-capture-state-contract/1.0',expectedPublicLocation:'https://example.test/home',document:{{minScrollWidth:1,minScrollHeight:1}},selectors:[{{selector:'main',minCount:1,minVisibleCount:1}}]}};
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const adapter = 'browser-control-in-app';
const tabId = 'tab-1';
const sessionAlias = 'test-session';
const now = Date.now();
const sourceReceipt = {{
  schemaVersion:'web-capture-source-receipt/1.0',receiptId:'receipt-1',adapter,
  sessionAliasHash:sha(sessionAlias),
  tabIdentityHash:sha(JSON.stringify({{adapter,tabId,expectedPublicLocation:stateContract.expectedPublicLocation}})),
  expectedPublicLocation:stateContract.expectedPublicLocation,
  contextFingerprint:sha(JSON.stringify(context)),
  issuedAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString()
}};
const ready = {{publicLocation:stateContract.expectedPublicLocation,navigationTimeOrigin:123,readyState:'complete',fontsStatus:'loaded',userAgent:'Fake Chromium',renderingEnvironment:{{}},viewport:{{innerWidth:800,innerHeight:600,devicePixelRatio:1,visualViewportScale:1,scrollX:0,scrollY:0}}}};
const witness = {{publicLocation:stateContract.expectedPublicLocation,documentMetrics:{{scrollWidth:800,scrollHeight:600}},selectorResults:[{{selector:'main',invalidSelector:false,count:1,visibleCount:1,pass:true}}],checks:{{publicLocation:true,minScrollWidth:true,minScrollHeight:true,selectors:true}},pass:true}};
const inventory = {{schemaVersion:'web-asset-inventory/1.0',viewport:ready.viewport,dom:{{scanTruncated:false}},visibleElements:[{{tag:'main',locator:'main',ancestorLocators:['body','html'],geometry:{{x:0,y:0,width:800,height:600}},paintVisibility:{{paintedVisible:true}}}}],images:[],cssImages:[],inlineSvgs:[],pseudoElements:[]}};
let runtimeCall = 0;
const cdp = {{async send(method) {{
  if (method === 'DOM.enable' || method === 'CSS.enable') return {{}};
  if (method === 'Page.getLayoutMetrics') return {{cssLayoutViewport:{{clientWidth:800,clientHeight:600}},cssVisualViewport:{{clientWidth:800,clientHeight:600}},cssContentSize:{{width:800,height:600}}}};
  if (method === 'Runtime.evaluate') {{ runtimeCall += 1; return {{result:{{value:runtimeCall===1?ready:runtimeCall===2?witness:runtimeCall===3?inventory:runtimeCall===4?witness:{{publicLocation:ready.publicLocation,navigationTimeOrigin:ready.navigationTimeOrigin}}}}}}; }}
  if (method === 'DOMSnapshot.captureSnapshot') return {{strings:[],documents:[]}};
  if (method === 'Accessibility.getFullAXTree') return {{nodes:[]}};
  throw new Error(method);
}}}};
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
const tab = {{id:tabId,capabilities:{{async get(){{return cdp;}}}},async screenshot(){{return png;}}}};
const result = await module.captureBrowserTab({{tab,projectRoot:{json.dumps(directory)},outputDir:'evidence/capture',context,stateContract,fontScopeRoots:['main'],sourceReceipt,sessionAlias}});
const bundle = JSON.parse(await fs.readFile({json.dumps(str(Path(directory) / 'evidence' / 'capture' / 'capture-bundle.json'))}, 'utf8'));
console.log(JSON.stringify({{ok:result.ok,artifactKeys:Object.keys(bundle.artifacts).sort(),pre:bundle.stateWitnessSha256,post:bundle.stateWitnessPostSha256,receipt:bundle.sourceReceiptSha256}}));
"""
            result = subprocess.run(["node", "--input-type=module", "-e", program], text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertIn("stateWitnessPost", payload["artifactKeys"])
            self.assertIn("sourceReceipt", payload["artifactKeys"])
            self.assertNotEqual(payload["pre"], payload["post"])

    def test_receipt_tab_session_and_time_mismatches_fail_before_capture(self) -> None:
        program = f"""
import crypto from 'node:crypto';
const module = await import({json.dumps(SCRIPT.as_uri())});
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const context = {{projectId:'p',pageId:'home',scenarioId:'s',baselineId:'b',viewportId:'v',stateId:'default',side:'reference'}};
const stateContract = {{schemaVersion:'web-capture-state-contract/1.0',expectedPublicLocation:'https://example.test/home',selectors:[{{selector:'main',minCount:1}}]}};
const tab = {{id:'tab-1',capabilities:{{}},screenshot(){{throw new Error('should-not-run');}}}};
const base = {{schemaVersion:'web-capture-source-receipt/1.0',receiptId:'r',adapter:'browser-control-in-app',expectedPublicLocation:stateContract.expectedPublicLocation,contextFingerprint:sha(JSON.stringify(context))}};
const now = Date.now();
const cases = [
  {{...base,sessionAliasHash:sha('wrong'),tabIdentityHash:sha(JSON.stringify({{adapter:base.adapter,tabId:tab.id,expectedPublicLocation:stateContract.expectedPublicLocation}})),issuedAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString()}},
  {{...base,sessionAliasHash:sha('session'),tabIdentityHash:sha('wrong-tab'),issuedAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString()}},
  {{...base,sessionAliasHash:sha('session'),tabIdentityHash:sha(JSON.stringify({{adapter:base.adapter,tabId:tab.id,expectedPublicLocation:stateContract.expectedPublicLocation}})),issuedAt:new Date(now-60000).toISOString(),expiresAt:new Date(now-1000).toISOString()}}
];
for (const sourceReceipt of cases) {{
  try {{ await module.captureBrowserTab({{tab,projectRoot:'Z:/must-not-be-read',outputDir:'evidence/x',context,stateContract,fontScopeRoots:['main'],sourceReceipt,sessionAlias:'session'}}); console.log('accepted'); }}
  catch (error) {{ console.log(error.message); }}
}}
"""
        result = subprocess.run(["node", "--input-type=module", "-e", program], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("accepted", result.stdout)
        self.assertGreaterEqual(result.stdout.count("not bound"), 2)
        self.assertIn("expired", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
