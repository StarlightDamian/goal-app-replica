#!/usr/bin/env node
/**
 * Assemble the production Capture Bundle contract from a supported Browser
 * tab whose raw-CDP capability is already authorized by the host product.
 *
 * This adapter is intentionally a library: authentication and browser
 * ownership remain with the supported Browser surface. It never reads
 * cookies/storage, navigates, reloads, clicks, or downloads assets.
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const core = require("./web_capture_cdp.js");
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROBE_PATH = path.join(SCRIPT_DIR, "web_asset_probe.js");
const BUNDLE_SCHEMA = "web-capture-bundle/2.0";
const SOURCE_RECEIPT_SCHEMA = "web-capture-source-receipt/1.0";

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative));
}

function relativeArtifactPath(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join("/");
}

function artifact(root, filePath, bytes, mediaType) {
  return {
    path: relativeArtifactPath(root, filePath),
    sha256: core.sha256(bytes),
    mediaType,
  };
}

async function ensureNewOutput(projectRootValue, outputDirValue) {
  const projectRoot = await fs.realpath(path.resolve(projectRootValue));
  const outputDir = path.resolve(projectRoot, outputDirValue);
  if (!within(projectRoot, outputDir)) throw new Error("outputDir escapes projectRoot");
  try {
    await fs.access(outputDir);
    throw new Error("outputDir already exists; capture evidence is immutable");
  } catch (error) {
    if (error && error.code !== "ENOENT") throw error;
  }
  await fs.mkdir(path.dirname(outputDir), { recursive: true });
  const temporaryDir = outputDir + ".tmp-" + crypto.randomUUID();
  await fs.mkdir(temporaryDir);
  return { projectRoot, outputDir, temporaryDir };
}

function contextRecord(context) {
  const required = ["projectId", "pageId", "scenarioId", "baselineId", "viewportId", "stateId", "side"];
  for (const key of required) {
    if (typeof context?.[key] !== "string" || !context[key]) throw new Error("capture context is incomplete: " + key);
  }
  if (!new Set(["reference", "replica"]).has(context.side)) throw new Error("capture context side is invalid");
  return Object.fromEntries(required.map(key => [key, context[key]]));
}

function sourceReceiptRecord(value, context, expectedPublicLocation, tab, sessionAlias) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.schemaVersion !== SOURCE_RECEIPT_SCHEMA) {
    throw new Error("a host-issued sourceReceipt is required");
  }
  const safeId = field => {
    const candidate = value[field];
    if (typeof candidate !== "string" || !candidate || candidate.length > 200 || /[\u0000-\u001f\u007f]/.test(candidate)) throw new Error("sourceReceipt " + field + " is invalid");
    return candidate;
  };
  const safeHash = field => {
    const candidate = value[field];
    if (typeof candidate !== "string" || !/^[0-9a-f]{64}$/i.test(candidate)) throw new Error("sourceReceipt " + field + " must be a SHA-256 digest");
    return candidate.toLowerCase();
  };
  const issuedAt = Date.parse(value.issuedAt);
  const expiresAt = Date.parse(value.expiresAt);
  const now = Date.now();
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt > now + 60_000 || expiresAt <= now || expiresAt - issuedAt > 3_600_000) {
    throw new Error("sourceReceipt time window is invalid or expired");
  }
  if (value.contextFingerprint !== core.sha256(Buffer.from(JSON.stringify(context), "utf8"))) throw new Error("sourceReceipt context does not match capture context");
  if (value.expectedPublicLocation !== expectedPublicLocation) throw new Error("sourceReceipt expectedPublicLocation does not match state contract");
  if (typeof sessionAlias !== "string" || !sessionAlias.trim() || sessionAlias.length > 200) throw new Error("a non-secret Browser sessionAlias is required");
  if (tab.id == null || !String(tab.id)) throw new Error("supported Browser tab does not expose a bindable identity");
  const adapter = safeId("adapter");
  const expectedSessionAliasHash = core.sha256(Buffer.from(sessionAlias, "utf8"));
  const expectedTabIdentityHash = core.sha256(Buffer.from(JSON.stringify({ adapter, tabId: String(tab.id), expectedPublicLocation }), "utf8"));
  if (safeHash("sessionAliasHash") !== expectedSessionAliasHash || safeHash("tabIdentityHash") !== expectedTabIdentityHash) {
    throw new Error("sourceReceipt is not bound to the selected Browser session and tab");
  }
  return {
    schemaVersion: SOURCE_RECEIPT_SCHEMA,
    receiptId: safeId("receiptId"),
    adapter,
    sessionAliasHash: expectedSessionAliasHash,
    tabIdentityHash: expectedTabIdentityHash,
    hostBindingAlgorithm: "sha256(adapter,tab-id,public-location)+sha256(session-alias)",
    expectedPublicLocation,
    contextFingerprint: value.contextFingerprint,
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

export async function captureBrowserTab({ tab, projectRoot, outputDir, context, stateContract: stateContractValue, fontScopeRoots, sourceReceipt, sessionAlias }) {
  if (!tab?.capabilities || typeof tab.screenshot !== "function") throw new Error("a supported Browser tab is required");
  const safeContext = contextRecord(context);
  const safeStateContract = core.stateContract(stateContractValue);
  if (!safeStateContract.expectedPublicLocation) throw new Error("Browser bridge state contract requires expectedPublicLocation");
  const safeSourceReceipt = sourceReceiptRecord(sourceReceipt, safeContext, safeStateContract.expectedPublicLocation, tab, sessionAlias);
  if (!Array.isArray(fontScopeRoots) || !fontScopeRoots.length || fontScopeRoots.some(value => typeof value !== "string" || !value.trim())) {
    throw new Error("fontScopeRoots must identify at least one captured component root");
  }
  const safeFontScopeRoots = Array.from(new Set(fontScopeRoots.map(value => value.trim())));
  const paths = await ensureNewOutput(projectRoot, outputDir);
  let committed = false;
  try {
  const cdp = await tab.capabilities.get("cdp");
  const call = (method, params = {}) => cdp.send(method, params, { timeoutMs: 60_000 });

  await call("DOM.enable");
  await call("CSS.enable");
  const layoutMetrics = await call("Page.getLayoutMetrics");
  const readiness = await call("Runtime.evaluate", {
    expression: `(async () => {
      await document.fonts.ready;
      await Promise.all(Array.from(document.images).map(image => image.decode().catch(() => undefined)));
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      return {
        publicLocation: location.origin + location.pathname,
        navigationTimeOrigin: performance.timeOrigin,
        readyState: document.readyState,
        fontsStatus: document.fonts.status,
        userAgent: navigator.userAgent,
        renderingEnvironment: {
          locale: navigator.language,
          languages: Array.from(navigator.languages || []),
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
          colorSchemeDark: matchMedia('(prefers-color-scheme: dark)').matches,
          reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
          forcedColors: matchMedia('(forced-colors: active)').matches,
          prefersContrastMore: matchMedia('(prefers-contrast: more)').matches,
          documentClientWidth: document.documentElement.clientWidth,
          documentClientHeight: document.documentElement.clientHeight,
          scrollbarWidth: innerWidth - document.documentElement.clientWidth,
          screenWidth: screen.width,
          screenHeight: screen.height,
          colorDepth: screen.colorDepth,
          pixelDepth: screen.pixelDepth
        },
        viewport: {
          innerWidth,
          innerHeight,
          devicePixelRatio,
          visualViewportScale: visualViewport ? visualViewport.scale : 1,
          scrollX,
          scrollY
        }
      };
    })()`,
    returnByValue: true,
    awaitPromise: true,
    silent: true,
  });
  const ready = readiness?.result?.value;
  if (!ready || ready.readyState !== "complete") throw new Error("selected Browser tab is not render-ready");
  const stateWitness = await core.captureStateWitness({ call }, safeStateContract, ready, "pre");

  const probeSource = await fs.readFile(PROBE_PATH, "utf8");
  const inventoryResult = await call("Runtime.evaluate", {
    expression: probeSource,
    returnByValue: true,
    awaitPromise: true,
    silent: true,
  });
  const inventory = inventoryResult?.result?.value;
  if (!inventory || typeof inventory !== "object" || Array.isArray(inventory)) throw new Error("asset probe did not return an inventory");

  const domRaw = await call("DOMSnapshot.captureSnapshot", {
    computedStyles: core.COMPUTED_STYLES,
    includePaintOrder: true,
    includeDOMRects: true,
    includeBlendedBackgroundColors: false,
    includeTextColorOpacities: false,
  });
  const axRaw = await call("Accessibility.getFullAXTree");
  const fontUsage = await core.capturePlatformFonts({ call }, domRaw, inventory, {
    scopeRoots: safeFontScopeRoots,
    batchSize: 12,
    perCallTimeoutMs: 8_000,
    totalBudgetMs: 45_000,
  });
  if (fontUsage.scanTruncated || fontUsage.failedNodeCount || fontUsage.unmappedNodeCount || fontUsage.budgetExhausted || fontUsage.scopeMissing) {
    throw new Error("font capture was incomplete; narrow fontScopeRoots before retrying");
  }
  const screenshot = Buffer.from(await tab.screenshot({ fullPage: true }));
  if (screenshot.length < 8 || screenshot.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") throw new Error("Browser tab screenshot was not a PNG");
  const postStateWitness = await core.captureStateWitness({ call }, safeStateContract, ready, "post");
  const postCaptureIdentity = await call("Runtime.evaluate", {
    expression: `({ publicLocation: location.origin + location.pathname, navigationTimeOrigin: performance.timeOrigin })`,
    returnByValue: true,
    silent: true,
  });
  const postCaptureValue = postCaptureIdentity?.result?.value;
  const beforeIdentity = { publicLocation: ready.publicLocation, navigationTimeOrigin: ready.navigationTimeOrigin };
  if (core.sha256(Buffer.from(JSON.stringify(postCaptureValue || {}), "utf8")) !== core.sha256(Buffer.from(JSON.stringify(beforeIdentity), "utf8"))) {
    throw new Error("selected Browser tab changed document or route during capture");
  }

  const navigationFingerprint = core.sha256(Buffer.from(JSON.stringify({
    publicLocation: ready.publicLocation,
    navigationTimeOrigin: ready.navigationTimeOrigin,
  }), "utf8"));
  const referenceFingerprint = core.sha256(Buffer.from(ready.publicLocation, "utf8"));
  const environment = {
    schemaVersion: "web-capture-environment/1.0",
    browser: {
      protocolVersion: null,
      product: ready.userAgent || null,
      revision: null,
      userAgent: ready.userAgent || null,
      jsVersion: null,
    },
    layout: {
      cssLayoutViewport: layoutMetrics.cssLayoutViewport || null,
      cssVisualViewport: layoutMetrics.cssVisualViewport || null,
      cssContentSize: layoutMetrics.cssContentSize || null,
    },
    probeViewport: inventory.viewport || null,
    readiness: { readyState: ready.readyState, fontsStatus: ready.fontsStatus },
    renderingEnvironment: ready.renderingEnvironment || null,
    screenshotPolicy: {
      format: "png",
      fromSurface: true,
      captureBeyondViewport: true,
      caret: "browser-current",
      animation: "browser-current",
      scale: "device",
    },
    navigationFingerprint,
    referenceFingerprint,
  };

  const content = {
    environment: core.jsonBuffer(environment),
    inventory: core.jsonBuffer(inventory),
    domSnapshot: core.jsonBuffer(core.normalizedPublicDomSnapshot(domRaw)),
    axTree: core.jsonBuffer(core.normalizedPublicAxTree(axRaw)),
    fontUsage: core.jsonBuffer(fontUsage),
    stateContract: core.jsonBuffer(safeStateContract),
    stateWitness: core.jsonBuffer(stateWitness),
    stateWitnessPost: core.jsonBuffer(postStateWitness),
    sourceReceipt: core.jsonBuffer({ ...safeSourceReceipt, preStateWitnessSha256: core.sha256(core.jsonBuffer(stateWitness)), postStateWitnessSha256: core.sha256(core.jsonBuffer(postStateWitness)) }),
    screenshot,
  };
  const names = {
    environment: "environment.json",
    inventory: "inventory.json",
    domSnapshot: "dom-snapshot.json",
    axTree: "ax-tree.json",
    fontUsage: "font-usage.json",
    stateContract: "state-contract.json",
    stateWitness: "state-witness.json",
    stateWitnessPost: "state-witness-post.json",
    sourceReceipt: "source-receipt.json",
    screenshot: "reference.png",
    bundle: "capture-bundle.json",
  };
  const finalFiles = Object.fromEntries(Object.entries(names).map(([key, name]) => [key, path.join(paths.outputDir, name)]));
  const temporaryFiles = Object.fromEntries(Object.entries(names).map(([key, name]) => [key, path.join(paths.temporaryDir, name)]));
  const artifacts = {
    environment: artifact(paths.projectRoot, finalFiles.environment, content.environment, "application/json"),
    inventory: artifact(paths.projectRoot, finalFiles.inventory, content.inventory, "application/json"),
    domSnapshot: artifact(paths.projectRoot, finalFiles.domSnapshot, content.domSnapshot, "application/json"),
    axTree: artifact(paths.projectRoot, finalFiles.axTree, content.axTree, "application/json"),
    fontUsage: artifact(paths.projectRoot, finalFiles.fontUsage, content.fontUsage, "application/json"),
    stateContract: artifact(paths.projectRoot, finalFiles.stateContract, content.stateContract, "application/json"),
    stateWitness: artifact(paths.projectRoot, finalFiles.stateWitness, content.stateWitness, "application/json"),
    stateWitnessPost: artifact(paths.projectRoot, finalFiles.stateWitnessPost, content.stateWitnessPost, "application/json"),
    sourceReceipt: artifact(paths.projectRoot, finalFiles.sourceReceipt, content.sourceReceipt, "application/json"),
    screenshot: artifact(paths.projectRoot, finalFiles.screenshot, content.screenshot, "image/png"),
  };
  const bundle = {
    schemaVersion: BUNDLE_SCHEMA,
    capturedAt: new Date().toISOString(),
    captureMode: "read-only-supported-browser-tab",
    contentPolicy: "public-observable",
    context: safeContext,
    navigationFingerprint,
    referenceFingerprint,
    stateContractSha256: core.sha256(content.stateContract),
    stateWitnessSha256: core.sha256(content.stateWitness),
    stateWitnessPostSha256: core.sha256(content.stateWitnessPost),
    sourceReceiptSha256: core.sha256(content.sourceReceipt),
    fontScopeRoots: safeFontScopeRoots,
    viewport: ready.viewport,
    targetSelection: { kind: "supported-browser-tab", valuePersisted: false },
    probe: { path: "scripts/web_asset_probe.js", sha256: core.sha256(Buffer.from(probeSource, "utf8")) },
    protocolMethods: [
      "Page.getLayoutMetrics",
      "Runtime.evaluate",
      "DOM.enable",
      "CSS.enable",
      "DOMSnapshot.captureSnapshot",
      "Accessibility.getFullAXTree",
      "CSS.getPlatformFontsForNode",
      "BrowserUse.tab.screenshot",
    ],
    sideEffects: { reload: false, navigation: false, clicks: false, domMutation: false, assetDownloads: false },
    privacy: {
      cdpEndpointPersisted: false,
      websocketUrlPersisted: false,
      targetSelectorValuePersisted: false,
      domSnapshotRawPersisted: false,
      axTreeRawPersisted: false,
      normalizedPublicObservableValuesPersisted: true,
    },
    artifacts,
    limitations: [
      "Public observable DOM/AX values are normalized and secret-bearing fields remain excluded.",
      "Browser and protocol revisions are not exposed by the supported-tab raw-CDP allow-list; the user agent is persisted instead.",
      "The screenshot may visibly contain information already rendered in the selected public target.",
      "capture-bundle.json is the manifest and therefore cannot contain a stable hash of itself.",
    ],
  };
  const bundleContent = core.jsonBuffer(bundle);

  await fs.writeFile(temporaryFiles.environment, content.environment, { flag: "wx" });
  await fs.writeFile(temporaryFiles.inventory, content.inventory, { flag: "wx" });
  await fs.writeFile(temporaryFiles.domSnapshot, content.domSnapshot, { flag: "wx" });
  await fs.writeFile(temporaryFiles.axTree, content.axTree, { flag: "wx" });
  await fs.writeFile(temporaryFiles.fontUsage, content.fontUsage, { flag: "wx" });
  await fs.writeFile(temporaryFiles.stateContract, content.stateContract, { flag: "wx" });
  await fs.writeFile(temporaryFiles.stateWitness, content.stateWitness, { flag: "wx" });
  await fs.writeFile(temporaryFiles.stateWitnessPost, content.stateWitnessPost, { flag: "wx" });
  await fs.writeFile(temporaryFiles.sourceReceipt, content.sourceReceipt, { flag: "wx" });
  await fs.writeFile(temporaryFiles.screenshot, content.screenshot, { flag: "wx" });
  await fs.writeFile(temporaryFiles.bundle, bundleContent, { flag: "wx" });
  await fs.rename(paths.temporaryDir, paths.outputDir);
  committed = true;

  return {
    ok: true,
    schemaVersion: BUNDLE_SCHEMA,
    bundle: artifact(paths.projectRoot, finalFiles.bundle, bundleContent, "application/json"),
    viewport: ready.viewport,
    inventory: {
      visibleElements: inventory.visibleElements?.length || 0,
      assets: (inventory.images?.length || 0) + (inventory.cssImages?.length || 0) + (inventory.inlineSvgs?.length || 0),
    },
    fonts: {
      queried: fontUsage.queriedNodeCount,
      failed: fontUsage.failedNodeCount,
      unmapped: fontUsage.unmappedNodeCount,
      pseudo: fontUsage.pseudoDeclarations?.length || 0,
    },
  };
  } finally {
    if (!committed) await fs.rm(paths.temporaryDir, { recursive: true, force: true }).catch(() => undefined);
  }
}
