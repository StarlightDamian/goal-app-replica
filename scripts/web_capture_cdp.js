#!/usr/bin/env node
"use strict";

/*
 * Read-only capture runner for an already-open Chromium target.
 *
 * This runner intentionally has no navigation, reload, input, click, DOM
 * mutation, storage, download, or Network-domain commands. It observes the
 * current target through CDP. Authenticated/private targets use redacted
 * summaries; explicitly authorized public targets may persist a normalized,
 * secret-filtered render tree with real computed-style values.
 */

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");

const BUNDLE_SCHEMA = "web-capture-bundle/2.0";
const STATE_CONTRACT_SCHEMA = "web-capture-state-contract/1.0";
const STATE_WITNESS_SCHEMA = "web-capture-state-witness/1.0";
const DEFAULT_OUTPUT_DIR = "nas/page";
const COMMAND_TIMEOUT_MS = 30_000;
const COMPUTED_STYLES = [
  "display", "visibility", "position", "z-index", "opacity",
  "width", "height", "min-width", "min-height", "max-width", "max-height",
  "margin-top", "margin-right", "margin-bottom", "margin-left",
  "padding-top", "padding-right", "padding-bottom", "padding-left",
  "color", "background-color", "background-image",
  "border-top-width", "border-right-width", "border-bottom-width", "border-left-width",
  "border-top-color", "border-right-color", "border-bottom-color", "border-left-color",
  "border-radius", "box-shadow",
  "font-family", "font-size", "font-weight", "font-style", "line-height", "letter-spacing",
  "text-align", "white-space", "overflow-x", "overflow-y",
  "transform", "transform-origin", "object-fit", "object-position",
];
const SAFE_AX_ROLES = new Set([
  "Abbr", "Alert", "AlertDialog", "Application", "Article", "Banner", "Blockquote",
  "Button", "Canvas", "Caption", "Cell", "CheckBox", "Code", "ColorWell",
  "ColumnHeader", "ComboBoxGrouping", "ComboBoxMenuButton", "Complementary",
  "ContentInfo", "Date", "DateTime", "Definition", "DescriptionList",
  "DescriptionListDetail", "DescriptionListTerm", "Dialog", "Directory", "DisclosureTriangle",
  "DocAbstract", "DocAcknowledgments", "DocAfterword", "DocAppendix", "DocBackLink",
  "DocBiblioEntry", "DocBibliography", "DocBiblioRef", "DocChapter", "DocColophon",
  "DocConclusion", "DocCover", "DocCredit", "DocCredits", "DocDedication", "DocEndnote",
  "DocEndnotes", "DocEpigraph", "DocEpilogue", "DocErrata", "DocExample", "DocFootnote",
  "DocForeword", "DocGlossary", "DocGlossRef", "DocIndex", "DocIntroduction", "DocNoteRef",
  "DocNotice", "DocPageBreak", "DocPageFooter", "DocPageHeader", "DocPageList", "DocPart",
  "DocPreface", "DocPrologue", "DocPullquote", "DocQna", "DocSubtitle", "DocTip",
  "DocToc", "EmbeddedObject", "Emphasis", "Feed", "Figcaption", "Figure", "Footer",
  "Form", "GenericContainer", "GraphicsDocument", "GraphicsObject", "GraphicsSymbol",
  "Grid", "GridCell", "Group", "Header", "Heading", "Iframe", "IframePresentational",
  "Image", "InputTime", "LabelText", "Legend", "LineBreak", "Link", "List", "ListBox",
  "ListBoxOption", "ListItem", "Log", "Main", "Mark", "Marquee", "Math", "Menu",
  "MenuBar", "MenuItem", "MenuItemCheckBox", "MenuItemRadio", "MenuListOption",
  "MenuListPopup", "Meter", "Navigation", "None", "Note", "Paragraph", "PluginObject",
  "PopUpButton", "Pre", "ProgressIndicator", "RadioButton", "RadioGroup", "Region",
  "RootWebArea", "Row", "RowGroup", "RowHeader", "Ruby", "RubyAnnotation", "ScrollBar",
  "Search", "SearchBox", "Section", "Slider", "SpinButton", "Splitter", "StaticText",
  "Status", "Strong", "Subscript", "Superscript", "SvgRoot", "Switch", "Tab", "TabList",
  "TabPanel", "Table", "Term", "TextField", "Time", "Timer", "ToggleButton", "Toolbar",
  "Tooltip", "Tree", "TreeGrid", "TreeItem", "Video", "WebArea", "Window",
]);
const SAFE_PUBLIC_ATTRIBUTES = new Set([
  "id", "class", "role", "alt", "title", "placeholder", "type", "name",
  "href", "src", "srcset", "sizes", "media", "width", "height", "tabindex",
  "disabled", "checked", "selected", "expanded", "hidden", "open",
]);
const SAFE_AX_PROPERTIES = new Set([
  "checked", "disabled", "expanded", "focusable", "focused", "hasPopup",
  "invalid", "level", "multiselectable", "orientation", "pressed", "readonly",
  "required", "selected",
]);

class CaptureError extends Error {}

function usage() {
  return [
    "Usage:",
    "  node web_capture_cdp.js --endpoint http://127.0.0.1:9222 --project-root PATH \\",
    "    (--target-id ID | --target-url URL) [--output-dir nas/page] \\",
    "    --project-id ID --page-id ID --scenario-id ID --baseline-id ID \\",
    "    --viewport-id ID --state-id ID --side reference|replica \\",
    "    --state-contract PROJECT_ROOT_RELATIVE_JSON --font-scope-root LOCATOR \\",
    "    [--content-policy redacted|public-observable]",
    "",
    "The endpoint must be loopback HTTP(S). Capture is read-only and never reloads the target.",
  ].join("\n");
}

function parseArgs(argv) {
  const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === "--help" || name === "-h") return { help: true };
    if (!["--endpoint", "--project-root", "--output-dir", "--target-id", "--target-url", "--content-policy", "--state-contract", "--font-scope-root", "--project-id", "--page-id", "--scenario-id", "--baseline-id", "--viewport-id", "--state-id", "--side"].includes(name)) {
      throw new CaptureError("unknown argument; use --help for the supported interface");
    }
    if (Object.prototype.hasOwnProperty.call(values, name)) {
      throw new CaptureError("each option may be supplied only once");
    }
    const value = argv[index + 1];
    if (value == null || value.startsWith("--")) throw new CaptureError("an option value is missing");
    values[name] = value;
    index += 1;
  }
  if (!values["--endpoint"]) throw new CaptureError("--endpoint is required");
  if (!values["--project-root"]) throw new CaptureError("--project-root is required");
  if (!values["--state-contract"]) throw new CaptureError("--state-contract is required");
  if (!values["--font-scope-root"] || values["--font-scope-root"].length > 500 || /[\u0000-\u001f\u007f]/.test(values["--font-scope-root"])) {
    throw new CaptureError("--font-scope-root is required and must be a safe locator");
  }
  const selectors = [values["--target-id"], values["--target-url"]].filter(Boolean);
  if (selectors.length !== 1) {
    throw new CaptureError("exactly one explicit --target-id or --target-url is required");
  }
  const contentPolicy = values["--content-policy"] || "redacted";
  if (!["redacted", "public-observable"].includes(contentPolicy)) {
    throw new CaptureError("--content-policy must be redacted or public-observable");
  }
  const context = {
    projectId: values["--project-id"],
    pageId: values["--page-id"],
    scenarioId: values["--scenario-id"],
    baselineId: values["--baseline-id"],
    viewportId: values["--viewport-id"],
    stateId: values["--state-id"],
    side: values["--side"],
  };
  for (const [field, value] of Object.entries(context)) {
    if (typeof value !== "string" || !value.trim() || value !== value.trim() || value.length > 200 || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new CaptureError(`--${field.replace(/[A-Z]/g, letter => "-" + letter.toLowerCase())} is required and must be a safe identifier`);
    }
  }
  if (!["reference", "replica"].includes(context.side)) {
    throw new CaptureError("--side must be reference or replica");
  }
  return {
    endpoint: values["--endpoint"],
    projectRoot: values["--project-root"],
    outputDir: values["--output-dir"] || DEFAULT_OUTPUT_DIR,
    targetId: values["--target-id"] || null,
    targetUrl: values["--target-url"] || null,
    contentPolicy,
    stateContractPath: values["--state-contract"],
    fontScopeRoot: values["--font-scope-root"],
    context,
  };
}

function stateContract(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || raw.schemaVersion !== STATE_CONTRACT_SCHEMA) {
    throw new CaptureError("state contract schemaVersion must be " + STATE_CONTRACT_SCHEMA);
  }
  const documentRule = raw.document == null ? {} : raw.document;
  if (!documentRule || typeof documentRule !== "object" || Array.isArray(documentRule)) {
    throw new CaptureError("state contract document must be an object");
  }
  const normalizeInteger = (value, field) => {
    if (value == null) return null;
    if (!Number.isInteger(value) || value < 0 || value > 1000000) {
      throw new CaptureError("state contract " + field + " must be a bounded non-negative integer");
    }
    return value;
  };
  const normalizeRules = (value, field) => {
    if (value == null) return [];
    if (!Array.isArray(value) || value.length > 100) throw new CaptureError("state contract " + field + " must be an array with at most 100 entries");
    return value.map((entry, index) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new CaptureError("state contract " + field + " entries must be objects");
      const selector = entry.selector;
      if (typeof selector !== "string" || !selector.trim() || selector !== selector.trim() || selector.length > 500 || /[\u0000-\u001f\u007f]/.test(selector)) {
        throw new CaptureError("state contract " + field + " selector is invalid at index " + index);
      }
      const minCount = normalizeInteger(entry.minCount, field + ".minCount") ?? 0;
      const minVisibleCount = normalizeInteger(entry.minVisibleCount, field + ".minVisibleCount") ?? 0;
      const maxCount = normalizeInteger(entry.maxCount, field + ".maxCount");
      const maxVisibleCount = normalizeInteger(entry.maxVisibleCount, field + ".maxVisibleCount");
      if (maxCount != null && minCount > maxCount) throw new CaptureError("state contract selector minCount exceeds maxCount");
      if (maxVisibleCount != null && minVisibleCount > maxVisibleCount) throw new CaptureError("state contract selector minVisibleCount exceeds maxVisibleCount");
      if (minCount === 0 && minVisibleCount === 0 && maxCount == null && maxVisibleCount == null) {
        throw new CaptureError("state contract selector must contain an observable count constraint");
      }
      return { selector, minCount, minVisibleCount, maxCount, maxVisibleCount };
    });
  };
  let expectedPublicLocation = null;
  if (raw.expectedPublicLocation != null) {
    if (typeof raw.expectedPublicLocation !== "string" || !raw.expectedPublicLocation.trim() || raw.expectedPublicLocation.length > 2048) {
      throw new CaptureError("state contract expectedPublicLocation must be a non-empty public URL");
    }
    try {
      const parsed = new URL(raw.expectedPublicLocation);
      if (!new Set(["http:", "https:"]).has(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error();
      expectedPublicLocation = parsed.origin + parsed.pathname;
    } catch (_error) {
      throw new CaptureError("state contract expectedPublicLocation must be an HTTP(S) origin+path without secrets");
    }
  }
  const normalized = {
    schemaVersion: STATE_CONTRACT_SCHEMA,
    expectedPublicLocation,
    document: {
      minScrollWidth: normalizeInteger(documentRule.minScrollWidth, "document.minScrollWidth") ?? 0,
      minScrollHeight: normalizeInteger(documentRule.minScrollHeight, "document.minScrollHeight") ?? 0,
    },
    selectors: normalizeRules(raw.selectors, "selectors"),
  };
  if (new Set(normalized.selectors.map(rule => rule.selector)).size !== normalized.selectors.length) {
    throw new CaptureError("state contract selectors must be unique");
  }
  if (!normalized.selectors.some(rule => rule.minCount > 0 || rule.minVisibleCount > 0)) {
    throw new CaptureError("state contract must contain at least one positive selector assertion");
  }
  return normalized;
}

async function loadStateContract(projectRootValue, contractPathValue) {
  const projectRoot = await fsp.realpath(path.resolve(projectRootValue));
  const contractPath = path.resolve(projectRoot, contractPathValue);
  const relative = path.relative(projectRoot, contractPath);
  if (relative.startsWith(".." + path.sep) || relative === ".." || path.isAbsolute(relative)) {
    throw new CaptureError("--state-contract must stay inside --project-root");
  }
  let bytes;
  try {
    bytes = await fsp.readFile(contractPath);
  } catch (_error) {
    throw new CaptureError("state contract could not be read");
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (_error) {
    throw new CaptureError("state contract must be valid UTF-8 JSON");
  }
  return { contract: stateContract(parsed), contractPath };
}

async function captureStateWitness(client, contract, readinessValue, phase = "pre") {
  if (!new Set(["pre", "post"]).has(phase)) throw new CaptureError("state witness phase is invalid");
  const expression = `(() => {
    const contract = ${JSON.stringify(null)};
    return contract;
  })()`;
  const source = expression.replace("const contract = null;", "const contract = " + JSON.stringify(contract) + ";").replace("return contract;", `
    const visible = node => {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
      const rect = node.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
    };
    const selectorResults = contract.selectors.map(rule => {
      let nodes;
      try { nodes = Array.from(document.querySelectorAll(rule.selector)); }
      catch (_error) { return { selector: rule.selector, invalidSelector: true, count: 0, visibleCount: 0, pass: false }; }
      const count = nodes.length;
      const visibleCount = nodes.filter(visible).length;
      const pass = count >= rule.minCount && visibleCount >= rule.minVisibleCount
        && (rule.maxCount == null || count <= rule.maxCount)
        && (rule.maxVisibleCount == null || visibleCount <= rule.maxVisibleCount);
      return { selector: rule.selector, invalidSelector: false, count, visibleCount, pass };
    });
    const publicLocation = location.origin + location.pathname;
    const documentMetrics = {
      scrollWidth: document.documentElement.scrollWidth,
      scrollHeight: document.documentElement.scrollHeight
    };
    const checks = {
      publicLocation: contract.expectedPublicLocation == null || publicLocation === contract.expectedPublicLocation,
      minScrollWidth: documentMetrics.scrollWidth >= contract.document.minScrollWidth,
      minScrollHeight: documentMetrics.scrollHeight >= contract.document.minScrollHeight,
      selectors: selectorResults.every(result => result.pass)
    };
    return { publicLocation, documentMetrics, selectorResults, checks, pass: Object.values(checks).every(Boolean) };
  `);
  const result = await client.call("Runtime.evaluate", { expression: source, returnByValue: true, awaitPromise: true, silent: true });
  const value = result && result.result && result.result.value;
  if (!value || typeof value !== "object" || value.pass !== true || value.publicLocation !== readinessValue.publicLocation) {
    throw new CaptureError("selected target does not satisfy the declared page-state contract");
  }
  return { schemaVersion: STATE_WITNESS_SCHEMA, phase, observedAt: new Date().toISOString(), ...value };
}

function normalizedHostname(url) {
  return url.hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
}

function isLoopbackHostname(hostname) {
  if (hostname === "localhost" || hostname === "::1" || hostname === "0:0:0:0:0:0:0:1") return true;
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!ipv4) return false;
  return ipv4.slice(1).every((part) => Number(part) <= 255) && Number(ipv4[1]) === 127;
}

function parseLoopbackEndpoint(raw) {
  let endpoint;
  try {
    endpoint = new URL(raw);
  } catch (_error) {
    throw new CaptureError("--endpoint must be a valid loopback HTTP(S) URL");
  }
  if (!["http:", "https:"].includes(endpoint.protocol) || !isLoopbackHostname(normalizedHostname(endpoint))) {
    throw new CaptureError("--endpoint must use HTTP(S) on a loopback host");
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new CaptureError("--endpoint cannot contain userinfo, query, or fragment data");
  }
  if (endpoint.pathname !== "/" && endpoint.pathname !== "") {
    throw new CaptureError("--endpoint must identify the loopback CDP origin, not a subpath");
  }
  return endpoint;
}

function validateWebSocketUrl(raw) {
  let websocketUrl;
  try {
    websocketUrl = new URL(raw);
  } catch (_error) {
    throw new CaptureError("the selected target did not provide a valid CDP WebSocket URL");
  }
  if (!["ws:", "wss:"].includes(websocketUrl.protocol) || !isLoopbackHostname(normalizedHostname(websocketUrl))) {
    throw new CaptureError("the selected target CDP WebSocket is not loopback");
  }
  if (websocketUrl.username || websocketUrl.password) {
    throw new CaptureError("the selected target CDP WebSocket cannot contain userinfo");
  }
  return websocketUrl.href;
}

function relativeParts(value) {
  if (typeof value !== "string" || !value.trim() || value !== value.trim()) return null;
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || path.win32.parse(value).root) return null;
  const parts = value.split(/[\\/]+/);
  if (!parts.length || parts.some((part) => !part || part === "." || part === "..")) return null;
  return parts;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative));
}

async function prepareOutputDirectory(projectRootValue, outputDirValue) {
  let projectRoot;
  try {
    projectRoot = await fsp.realpath(path.resolve(projectRootValue));
  } catch (_error) {
    throw new CaptureError("--project-root must identify an existing directory");
  }
  if (!(await fsp.stat(projectRoot)).isDirectory()) {
    throw new CaptureError("--project-root must identify an existing directory");
  }
  const parts = relativeParts(outputDirValue);
  if (!parts) throw new CaptureError("--output-dir must be a clean project-root-relative path");
  const candidate = path.resolve(projectRoot, ...parts);
  if (!isWithin(projectRoot, candidate)) throw new CaptureError("--output-dir escapes the project root");

  let cursor = projectRoot;
  for (const part of parts) {
    cursor = path.join(cursor, part);
    try {
      const stat = await fsp.lstat(cursor);
      if (stat.isSymbolicLink()) throw new CaptureError("--output-dir cannot traverse symbolic links");
      if (!stat.isDirectory()) throw new CaptureError("--output-dir conflicts with a non-directory path");
    } catch (error) {
      if (error instanceof CaptureError) throw error;
      if (error && error.code !== "ENOENT") throw new CaptureError("--output-dir could not be inspected safely");
      await fsp.mkdir(cursor);
    }
  }
  const outputDir = await fsp.realpath(candidate);
  if (!isWithin(projectRoot, outputDir)) throw new CaptureError("--output-dir resolves outside the project root");
  return { projectRoot, outputDir };
}

async function selectTarget(endpoint, targetId, targetUrl) {
  const listUrl = new URL("/json/list", endpoint);
  let response;
  try {
    response = await fetch(listUrl, { method: "GET", signal: AbortSignal.timeout(10_000) });
  } catch (_error) {
    throw new CaptureError("the loopback CDP target list could not be read");
  }
  if (!response.ok) throw new CaptureError("the loopback CDP target list returned a non-success status");
  let targets;
  try {
    targets = await response.json();
  } catch (_error) {
    throw new CaptureError("the loopback CDP target list was not valid JSON");
  }
  if (!Array.isArray(targets)) throw new CaptureError("the loopback CDP target list was not an array");
  const target = targets.find((item) => item && (
    targetId != null ? (item.id === targetId || item.targetId === targetId) : item.url === targetUrl
  ));
  if (!target) throw new CaptureError("the explicitly selected target was not found");
  if (typeof target.webSocketDebuggerUrl !== "string") {
    throw new CaptureError("the explicitly selected target has no CDP WebSocket URL");
  }
  return validateWebSocketUrl(target.webSocketDebuggerUrl);
}

function decodeMessageData(data) {
  if (typeof data === "string") return Promise.resolve(data);
  if (Buffer.isBuffer(data)) return Promise.resolve(data.toString("utf8"));
  if (data instanceof ArrayBuffer) return Promise.resolve(Buffer.from(data).toString("utf8"));
  if (data && typeof data.text === "function") return data.text();
  return Promise.reject(new CaptureError("CDP returned an unsupported message type"));
}

class CdpClient {
  constructor(websocketUrl) {
    this.websocketUrl = websocketUrl;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    if (typeof WebSocket !== "function") throw new CaptureError("Node.js with built-in WebSocket support is required");
    const socket = new WebSocket(this.websocketUrl);
    this.socket = socket;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new CaptureError("timed out connecting to the selected CDP target")), COMMAND_TIMEOUT_MS);
      socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener("error", () => { clearTimeout(timer); reject(new CaptureError("could not connect to the selected CDP target")); }, { once: true });
    });
    socket.addEventListener("message", (event) => {
      decodeMessageData(event.data).then((text) => this.handleMessage(text)).catch(() => this.failPending());
    });
    socket.addEventListener("close", () => this.failPending());
  }

  handleMessage(text) {
    let message;
    try {
      message = JSON.parse(text);
    } catch (_error) {
      return;
    }
    if (!message || !Number.isInteger(message.id)) return;
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) pending.reject(new CaptureError("CDP command failed: " + pending.method));
    else pending.resolve(message.result || {});
  }

  failPending() {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new CaptureError("the CDP connection closed before capture completed"));
    }
    this.pending.clear();
  }

  call(method, params = {}) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(new CaptureError("the CDP connection is not open"));
    }
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new CaptureError("CDP command timed out: " + method));
      }, COMMAND_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer, method });
      try {
        this.socket.send(JSON.stringify({ id, method, params }));
      } catch (_error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new CaptureError("CDP command could not be sent: " + method));
      }
    });
  }

  close() {
    if (this.socket) this.socket.close();
  }
}

function arrayLength(value) {
  return Array.isArray(value) ? value.length : 0;
}

function publicText(value, limit = 2000) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/\s+/g, " ").trim();
  if (!normalized) return null;
  return normalized.length <= limit ? normalized : normalized.slice(0, limit) + "…";
}

function publicUrl(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const trimmed = value.trim();
  if (/^(?:javascript|data|blob):/i.test(trimmed)) return null;
  try {
    const parsed = new URL(trimmed);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    parsed.pathname = parsed.pathname.split("/").map((segment) =>
      /(?:access[_-]?token|api[_-]?key|auth|bearer|credential|jwt|secret|session|signature|token)/i.test(segment)
        || /^eyJ[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]+){0,2}$/.test(segment)
        || (/^[A-Za-z0-9_-]{24,}$/.test(segment) && !/^\d+$/.test(segment))
        ? "[redacted]"
        : segment
    ).join("/");
    return parsed.href;
  } catch (_error) {
    return publicText(trimmed.split(/[?#]/, 1)[0].split("/").map((segment) =>
      /(?:access[_-]?token|api[_-]?key|auth|bearer|credential|jwt|secret|session|signature|token)/i.test(segment)
        || /^eyJ[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]+){0,2}$/.test(segment)
        || (/^[A-Za-z0-9_-]{24,}$/.test(segment) && !/^\d+$/.test(segment))
        ? "[redacted]"
        : segment
    ).join("/"), 2000);
  }
}

function stringAt(strings, index) {
  return Number.isInteger(index) && typeof strings[index] === "string" ? strings[index] : null;
}

function rareStringAt(rare, nodeIndex, strings) {
  if (!rare || !Array.isArray(rare.index) || !Array.isArray(rare.value)) return null;
  const offset = rare.index.indexOf(nodeIndex);
  return offset < 0 ? null : stringAt(strings, rare.value[offset]);
}

function normalizedPublicDomSnapshot(raw) {
  const strings = Array.isArray(raw.strings) ? raw.strings : [];
  const documents = Array.isArray(raw.documents) ? raw.documents : [];
  return {
    schemaVersion: "web-dom-render-tree/1.0",
    sourceProtocolMethod: "DOMSnapshot.captureSnapshot",
    rawPersisted: false,
    normalizedObservableValuesPersisted: true,
    documents: documents.map((document, documentIndex) => {
      const nodes = document.nodes || {};
      const layout = document.layout || {};
      const nodeCount = arrayLength(nodes.nodeType);
      const normalizedNodes = [];
      for (let index = 0; index < nodeCount; index += 1) {
        const attributeIndexes = Array.isArray(nodes.attributes && nodes.attributes[index])
          ? nodes.attributes[index]
          : [];
        const attributes = {};
        for (let cursor = 0; cursor + 1 < attributeIndexes.length; cursor += 2) {
          const name = stringAt(strings, attributeIndexes[cursor]);
          let value = stringAt(strings, attributeIndexes[cursor + 1]);
          if (!name || !(SAFE_PUBLIC_ATTRIBUTES.has(name) || name.startsWith("aria-") || name === "data-testid")) continue;
          if (["href", "src", "srcset"].includes(name)) value = publicUrl(value);
          else value = publicText(value);
          if (value != null) attributes[name] = value;
        }
        normalizedNodes.push({
          index,
          parentIndex: Array.isArray(nodes.parentIndex) ? nodes.parentIndex[index] : null,
          nodeType: Array.isArray(nodes.nodeType) ? nodes.nodeType[index] : null,
          nodeName: publicText(stringAt(strings, nodes.nodeName && nodes.nodeName[index]), 256),
          nodeValue: null,
          pseudoType: rareStringAt(nodes.pseudoType, index, strings),
          shadowRootType: rareStringAt(nodes.shadowRootType, index, strings),
          attributes,
        });
      }
      const normalizedLayout = [];
      const layoutCount = arrayLength(layout.nodeIndex);
      for (let index = 0; index < layoutCount; index += 1) {
        const styleIndexes = Array.isArray(layout.styles && layout.styles[index]) ? layout.styles[index] : [];
        const computedStyle = {};
        for (let styleIndex = 0; styleIndex < COMPUTED_STYLES.length; styleIndex += 1) {
          const value = publicText(stringAt(strings, styleIndexes[styleIndex]), 2000);
          if (value != null) computedStyle[COMPUTED_STYLES[styleIndex]] = value;
        }
        normalizedLayout.push({
          nodeIndex: layout.nodeIndex[index],
          bounds: Array.isArray(layout.bounds && layout.bounds[index]) ? layout.bounds[index] : null,
          text: publicText(stringAt(strings, layout.text && layout.text[index])),
          paintOrder: Array.isArray(layout.paintOrders) ? layout.paintOrders[index] : null,
          computedStyle,
        });
      }
      return {
        documentIndex,
        documentUrl: publicUrl(stringAt(strings, document.documentURL)),
        contentWidth: document.contentWidth || null,
        contentHeight: document.contentHeight || null,
        scrollOffsetX: document.scrollOffsetX || 0,
        scrollOffsetY: document.scrollOffsetY || 0,
        nodes: normalizedNodes,
        layout: normalizedLayout,
      };
    }),
    redaction: {
      excluded: ["raw DOM text nodes", "input values", "textarea values", "cookies", "tokens", "query strings", "URL fragments", "backend node ids"],
      attributeAllowlist: Array.from(SAFE_PUBLIC_ATTRIBUTES).sort(),
    },
  };
}

function normalizedPublicAxTree(raw) {
  const nodes = Array.isArray(raw.nodes) ? raw.nodes : [];
  return {
    schemaVersion: "web-ax-tree-public/1.0",
    sourceProtocolMethod: "Accessibility.getFullAXTree",
    rawPersisted: false,
    normalizedObservableValuesPersisted: true,
    nodes: nodes.map((node, index) => {
      const properties = {};
      for (const property of Array.isArray(node && node.properties) ? node.properties : []) {
        if (!property || !SAFE_AX_PROPERTIES.has(property.name)) continue;
        properties[property.name] = property.value && property.value.value;
      }
      return {
        index,
        ignored: Boolean(node && node.ignored),
        role: node && node.role ? publicText(node.role.value, 256) : null,
        name: node && node.name ? publicText(node.name.value) : null,
        properties,
        childCount: arrayLength(node && node.childIds),
      };
    }),
    redaction: { excluded: ["values", "descriptions", "node ids", "relationships"] },
  };
}

function summarizeDomSnapshot(raw) {
  const documents = Array.isArray(raw.documents) ? raw.documents : [];
  const summary = {
    schemaVersion: "web-dom-snapshot-summary/1.0",
    sourceProtocolMethod: "DOMSnapshot.captureSnapshot",
    rawPersisted: false,
    summary: {
      documentCount: documents.length,
      totalNodeCount: 0,
      totalLayoutNodeCount: 0,
      totalTextBoxCount: 0,
      computedStylePropertyCount: COMPUTED_STYLES.length,
    },
    documents: [],
    redaction: {
      policy: "No DOMSnapshot string table, text, attribute names/values, input values, URLs, or backend node identifiers are persisted.",
      sensitiveClassesExcluded: ["input-value", "password", "token", "cookie", "free-text", "attribute-value"],
    },
    limitations: [
      "Raw DOMSnapshot data is intentionally replaced by counts because string-table references cannot be reliably classified without reconstructing sensitive text and attributes.",
      "Computed style values are not persisted; only the requested property count is recorded.",
    ],
  };
  for (let index = 0; index < documents.length; index += 1) {
    const document = documents[index] || {};
    const nodeCount = arrayLength(document.nodes && document.nodes.nodeType);
    const layoutNodeCount = arrayLength(document.layout && document.layout.nodeIndex);
    const textBoxCount = arrayLength(document.textBoxes && document.textBoxes.layoutIndex);
    summary.summary.totalNodeCount += nodeCount;
    summary.summary.totalLayoutNodeCount += layoutNodeCount;
    summary.summary.totalTextBoxCount += textBoxCount;
    summary.documents.push({ index, nodeCount, layoutNodeCount, textBoxCount });
  }
  return summary;
}

function summarizeAxTree(raw) {
  const nodes = Array.isArray(raw.nodes) ? raw.nodes : [];
  const roleCounts = Object.create(null);
  let ignoredNodeCount = 0;
  let nodesWithSuppressedValue = 0;
  for (const node of nodes) {
    if (!node || typeof node !== "object") continue;
    if (node.ignored === true) ignoredNodeCount += 1;
    if (node.name || node.description || node.value || arrayLength(node.properties)) nodesWithSuppressedValue += 1;
    const role = node.role && typeof node.role.value === "string" ? node.role.value : null;
    if (role && SAFE_AX_ROLES.has(role)) roleCounts[role] = (roleCounts[role] || 0) + 1;
  }
  return {
    schemaVersion: "web-ax-tree-summary/1.0",
    sourceProtocolMethod: "Accessibility.getFullAXTree",
    rawPersisted: false,
    summary: {
      nodeCount: nodes.length,
      ignoredNodeCount,
      nodesWithSuppressedTextOrProperties: nodesWithSuppressedValue,
      roleCounts,
    },
    redaction: {
      policy: "AX names, descriptions, values, properties, node identifiers, and relationships are not persisted.",
      sensitiveClassesExcluded: ["input-value", "password", "token", "cookie", "accessible-name", "description"],
    },
    limitations: [
      "The persisted AX artifact is a structural summary, not a replayable raw accessibility tree.",
      "Only recognized role enum values are counted; unknown role strings are discarded.",
    ],
  };
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function jsonBuffer(value) {
  return Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8");
}

async function atomicWrite(filePath, content) {
  const temporary = path.join(path.dirname(filePath), "." + path.basename(filePath) + "." + crypto.randomUUID() + ".tmp");
  let handle;
  try {
    handle = await fsp.open(temporary, "wx", 0o600);
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = null;
    await fsp.rename(temporary, filePath);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fsp.unlink(temporary).catch(() => {});
    throw new CaptureError("an artifact could not be written atomically");
  }
}

function artifactRecord(projectRoot, filePath, content, mediaType) {
  return {
    path: path.relative(projectRoot, filePath).split(path.sep).join("/"),
    sha256: sha256(content),
    mediaType,
  };
}

function inventoryIdentityForSnapshotNode(domRaw, documentIndex, nodeIndex, inventory, fallbackBound = null) {
  const document = domRaw.documents[documentIndex] || {};
  const nodes = document.nodes || {};
  const layout = document.layout || {};
  const strings = Array.isArray(domRaw.strings) ? domRaw.strings : [];
  const nodeNames = Array.isArray(nodes.nodeName) ? nodes.nodeName : [];
  const layoutNodes = Array.isArray(layout.nodeIndex) ? layout.nodeIndex : [];
  const bounds = Array.isArray(layout.bounds) ? layout.bounds : [];
  const layoutIndex = layoutNodes.indexOf(nodeIndex);
  const nodeNameIndex = nodeNames[nodeIndex];
  const tag = Number.isInteger(nodeNameIndex) && typeof strings[nodeNameIndex] === "string"
    ? strings[nodeNameIndex].toLowerCase()
    : "";
  const bound = layoutIndex >= 0 && Array.isArray(bounds[layoutIndex]) ? bounds[layoutIndex] : fallbackBound;
  const visible = inventory && Array.isArray(inventory.visibleElements) ? inventory.visibleElements : [];
  const matches = bound ? visible.filter(record => {
    if (!record || record.tag !== tag || !record.geometry) return false;
    const geometry = record.geometry;
    const x = Number.isFinite(geometry.documentX) ? geometry.documentX : geometry.x;
    const y = Number.isFinite(geometry.documentY) ? geometry.documentY : geometry.y;
    return [x, y, geometry.width, geometry.height].every((value, index) =>
      Number.isFinite(value) && Math.abs(value - bound[index]) <= 0.75
    );
  }) : [];
  matches.sort((left, right) => String(left.locator || "").localeCompare(String(right.locator || "")));
  const match = matches[0];
  return match && typeof match.locator === "string" ? {
    locator: match.locator,
    ancestorLocators: Array.isArray(match.ancestorLocators) ? match.ancestorLocators : [],
    paintedVisible: match.paintVisibility && match.paintVisibility.paintedVisible === true,
  } : {
    locator: `domsnapshot:${documentIndex}:${nodeIndex}`,
    ancestorLocators: [],
    paintedVisible: false,
  };
}

function normalizedScopeLocator(value) {
  return String(value || "").trim().replace(/\[([^\]=]+)=(?:"([^"]*)"|'([^']*)')\]/g, (_match, name, doubleQuoted, singleQuoted) => {
    const attributeValue = doubleQuoted == null ? singleQuoted : doubleQuoted;
    return `[${name}=${attributeValue}]`;
  });
}

function renderedTextCandidates(domRaw, inventory, options = {}) {
  const limit = Number.isInteger(options.limit) && options.limit > 0 ? Math.min(options.limit, 5000) : 1000;
  const scopeRoots = Array.isArray(options.scopeRoots)
    ? Array.from(new Set(options.scopeRoots.filter(value => typeof value === "string" && value.trim()).map(value => value.trim())))
    : [];
  const normalizedScopeRoots = new Set(scopeRoots.map(normalizedScopeLocator));
  const isScopeRoot = locator => normalizedScopeRoots.has(normalizedScopeLocator(locator));
  const inventoryVisible = inventory && Array.isArray(inventory.visibleElements) ? inventory.visibleElements : [];
  const scopeExists = !scopeRoots.length || scopeRoots.includes("*") || scopeRoots.every(root => inventoryVisible.some(record =>
    record && (normalizedScopeLocator(record.locator) === normalizedScopeLocator(root)
      || (Array.isArray(record.ancestorLocators) && record.ancestorLocators.some(locator => normalizedScopeLocator(locator) === normalizedScopeLocator(root))))
  ));
  const strings = Array.isArray(domRaw && domRaw.strings) ? domRaw.strings : [];
  const candidates = [];
  const seen = new Set();
  const documents = Array.isArray(domRaw && domRaw.documents) ? domRaw.documents : [];
  for (let documentIndex = 0; documentIndex < documents.length; documentIndex += 1) {
    const document = documents[documentIndex] || {};
    const nodes = document.nodes || {};
    const layout = document.layout || {};
    const layoutNodes = Array.isArray(layout.nodeIndex) ? layout.nodeIndex : [];
    const layoutText = Array.isArray(layout.text) ? layout.text : [];
    const nodeTypes = Array.isArray(nodes.nodeType) ? nodes.nodeType : [];
    const parents = Array.isArray(nodes.parentIndex) ? nodes.parentIndex : [];
    const backendIds = Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : [];
    for (let layoutIndex = 0; layoutIndex < layoutNodes.length; layoutIndex += 1) {
      const textIndex = layoutText[layoutIndex];
      const text = Number.isInteger(textIndex) && typeof strings[textIndex] === "string" ? strings[textIndex].trim() : "";
      if (!text) continue;
      let nodeIndex = layoutNodes[layoutIndex];
      while (Number.isInteger(nodeIndex) && nodeIndex >= 0 && nodeTypes[nodeIndex] !== 1) {
        nodeIndex = parents[nodeIndex];
      }
      const queryNodeIndex = nodeIndex;
      const pseudoType = rareStringAt(nodes.pseudoType, queryNodeIndex, strings);
      let identityNodeIndex = queryNodeIndex;
      if (pseudoType) {
        identityNodeIndex = parents[identityNodeIndex];
        while (Number.isInteger(identityNodeIndex) && identityNodeIndex >= 0 && nodeTypes[identityNodeIndex] !== 1) {
          identityNodeIndex = parents[identityNodeIndex];
        }
      }
      const backendNodeId = Number.isInteger(nodeIndex) ? backendIds[nodeIndex] : null;
      if (!Number.isInteger(backendNodeId) || backendNodeId <= 0 || seen.has(backendNodeId)) continue;
      seen.add(backendNodeId);
      candidates.push({
        documentIndex,
        nodeIndex: queryNodeIndex,
        backendNodeId,
        pseudo: pseudoType ? `::${pseudoType.replace(/^:+/, "")}` : null,
        ...inventoryIdentityForSnapshotNode(
          domRaw,
          documentIndex,
          identityNodeIndex,
          inventory,
          Array.isArray(layout.bounds?.[layoutIndex]) ? layout.bounds[layoutIndex] : null,
        ),
      });
    }
  }
  const paintedCandidates = candidates.filter(candidate => candidate.paintedVisible === true);
  const scoped = scopeRoots.length && !scopeRoots.includes("*") ? paintedCandidates.filter(candidate =>
    isScopeRoot(candidate.locator)
    || candidate.ancestorLocators.some(isScopeRoot)
  ) : paintedCandidates;
  return {
    candidates: scoped.slice(0, limit),
    candidateCount: scoped.length,
    scanTruncated: scoped.length > limit,
    scopeRoots,
    scopeMissing: !scopeExists,
  };
}

async function capturePlatformFonts(client, domRaw, inventory, options = {}) {
  const selection = renderedTextCandidates(domRaw, inventory, options);
  const batchSize = Number.isInteger(options.batchSize) && options.batchSize > 0 ? Math.min(options.batchSize, 50) : 50;
  const perCallTimeoutMs = Number.isInteger(options.perCallTimeoutMs) && options.perCallTimeoutMs > 0 ? options.perCallTimeoutMs : COMMAND_TIMEOUT_MS;
  const totalBudgetMs = Number.isInteger(options.totalBudgetMs) && options.totalBudgetMs > 0 ? options.totalBudgetMs : COMMAND_TIMEOUT_MS * 20;
  const deadline = Date.now() + totalBudgetMs;
  const boundedCall = async (method, params = {}) => {
    const remaining = Math.max(1, Math.min(perCallTimeoutMs, deadline - Date.now()));
    let timer;
    return Promise.race([
      client.call(method, params),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("FONT_CAPTURE_TIMEOUT")), remaining); }),
    ]).finally(() => clearTimeout(timer));
  };
  const pseudoHasText = record => {
    const content = record && record.content;
    const value = content && typeof content === "object" ? content.value : content;
    return typeof value === "string" && value !== "" && value !== "\"\"" && value !== "''";
  };
  const pseudoDeclarations = (inventory && Array.isArray(inventory.pseudoElements) ? inventory.pseudoElements : [])
    .filter(record => record && pseudoHasText(record) && record.font && record.font.family)
    .map(record => ({
      locator: record.locator,
      ancestorLocators: Array.isArray(record.ancestorLocators) ? record.ancestorLocators : [],
      pseudo: record.pseudo,
      content: record.content,
      font: record.font,
    }))
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  if (!selection.candidates.length) {
    return {
      schemaVersion: "web-platform-font-usage/1.0",
      candidateNodeCount: 0,
      queriedNodeCount: 0,
      failedNodeCount: 0,
      unmappedNodeCount: 0,
      scanTruncated: false,
      scopeRoots: selection.scopeRoots,
      expectedLocators: [],
      expectedRecords: [],
      records: [],
      families: [],
      pseudoDeclarations,
      budgetExhausted: false,
      timedOutNodeCount: 0,
      scopeMissing: selection.scopeMissing,
    };
  }
  let pushed;
  try {
    await boundedCall("DOM.getDocument", { depth: -1, pierce: true });
    pushed = await boundedCall("DOM.pushNodesByBackendIdsToFrontend", {
      backendNodeIds: selection.candidates.map(candidate => candidate.backendNodeId),
    });
  } catch (_error) {
    return {
      schemaVersion: "web-platform-font-usage/1.0",
      candidateNodeCount: selection.candidateCount,
      queriedNodeCount: 0,
      failedNodeCount: selection.candidates.length,
      unmappedNodeCount: 0,
      scanTruncated: selection.scanTruncated,
      scopeRoots: selection.scopeRoots,
      expectedLocators: Array.from(new Set(selection.candidates.map(candidate => candidate.locator))).sort(),
      expectedRecords: selection.candidates.map(candidate => ({ locator: candidate.locator, pseudo: candidate.pseudo })),
      records: [],
      families: [],
      pseudoDeclarations,
      budgetExhausted: true,
      timedOutNodeCount: selection.candidates.length,
      scopeMissing: selection.scopeMissing,
    };
  }
  const nodeIds = Array.isArray(pushed && pushed.nodeIds) ? pushed.nodeIds : [];
  const records = [];
  let failedNodeCount = 0;
  let timedOutNodeCount = 0;
  let budgetExhausted = false;
  for (let start = 0; start < selection.candidates.length; start += batchSize) {
    if (Date.now() >= deadline) {
      budgetExhausted = true;
      timedOutNodeCount += selection.candidates.length - start;
      failedNodeCount += selection.candidates.length - start;
      break;
    }
    const batch = selection.candidates.slice(start, start + batchSize);
    const results = await Promise.all(batch.map(async (candidate, offset) => {
      const nodeId = nodeIds[start + offset];
      if (!Number.isInteger(nodeId) || nodeId <= 0) return { record: null, timedOut: false };
      try {
        const response = await boundedCall("CSS.getPlatformFontsForNode", { nodeId });
        return { record: {
          documentIndex: candidate.documentIndex,
          nodeIndex: candidate.nodeIndex,
          locator: candidate.locator,
          pseudo: candidate.pseudo,
          ancestorLocators: candidate.ancestorLocators,
          paintedVisible: candidate.paintedVisible,
          fonts: Array.isArray(response && response.fonts) ? response.fonts.map(font => ({
            familyName: font.familyName || null,
            postScriptName: font.postScriptName || null,
            isCustomFont: font.isCustomFont === true,
            glyphCount: Number.isInteger(font.glyphCount) ? font.glyphCount : 0,
          })) : [],
        }, timedOut: false };
      } catch (error) {
        return { record: null, timedOut: error && error.message === "FONT_CAPTURE_TIMEOUT" };
      }
    }));
    for (const result of results) {
      if (result.record) records.push(result.record);
      else {
        failedNodeCount += 1;
        if (result.timedOut) timedOutNodeCount += 1;
      }
    }
  }
  const families = new Map();
  for (const record of records) {
    for (const font of record.fonts) {
      const key = JSON.stringify([font.familyName, font.postScriptName, font.isCustomFont]);
      const current = families.get(key) || { ...font, glyphCount: 0, nodeCount: 0 };
      current.glyphCount += font.glyphCount;
      current.nodeCount += 1;
      families.set(key, current);
    }
  }
  return {
    schemaVersion: "web-platform-font-usage/1.0",
    candidateNodeCount: selection.candidateCount,
    queriedNodeCount: records.length,
    failedNodeCount,
    unmappedNodeCount: records.filter(record => record.locator.startsWith("domsnapshot:")).length,
    scanTruncated: selection.scanTruncated,
    scopeRoots: selection.scopeRoots,
    budgetExhausted,
    timedOutNodeCount,
    scopeMissing: selection.scopeMissing,
    expectedLocators: Array.from(new Set(selection.candidates.map(candidate => candidate.locator))).sort(),
    expectedRecords: selection.candidates.map(candidate => ({ locator: candidate.locator, pseudo: candidate.pseudo }))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    records,
    families: Array.from(families.values()).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    pseudoDeclarations,
  };
}

async function capture(options) {
  const endpoint = parseLoopbackEndpoint(options.endpoint);
  const loadedStateContract = await loadStateContract(options.projectRoot, options.stateContractPath);
  const paths = await prepareOutputDirectory(options.projectRoot, options.outputDir);
  const websocketUrl = await selectTarget(endpoint, options.targetId, options.targetUrl);
  const probePath = path.join(__dirname, "web_asset_probe.js");
  let probeSource;
  try {
    probeSource = await fsp.readFile(probePath, "utf8");
  } catch (_error) {
    throw new CaptureError("the required web_asset_probe.js could not be read");
  }

  const client = new CdpClient(websocketUrl);
  try {
    await client.connect();
    await client.call("DOM.enable", {});
    await client.call("CSS.enable", {});
    const browserVersion = await client.call("Browser.getVersion", {});
    const layoutMetrics = await client.call("Page.getLayoutMetrics", {});
    const readiness = await client.call("Runtime.evaluate", {
      expression: `(async () => {
        await document.fonts.ready;
        await Promise.all(Array.from(document.images).map(image => image.decode().catch(() => undefined)));
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        const publicLocation = location.origin + location.pathname;
        return {
          publicLocation,
          navigationTimeOrigin: performance.timeOrigin,
          readyState: document.readyState,
          fontsStatus: document.fonts.status,
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
            scrollbarWidth: window.innerWidth - document.documentElement.clientWidth,
            screenWidth: screen.width,
            screenHeight: screen.height,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth
          },
          viewport: {
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            devicePixelRatio: window.devicePixelRatio,
            visualViewportScale: window.visualViewport ? window.visualViewport.scale : 1,
            scrollX: window.scrollX,
            scrollY: window.scrollY
          }
        };
      })()`,
      returnByValue: true,
      awaitPromise: true,
      silent: true,
    });
    const readinessValue = readiness && readiness.result && readiness.result.value;
    if (!readinessValue || typeof readinessValue !== "object" || readinessValue.readyState !== "complete") {
      const reason = readiness && readiness.exceptionDetails
        ? "runtime-exception"
        : !readiness || !readiness.result
          ? "missing-runtime-result"
          : readiness.result.type !== "object"
            ? "non-object-runtime-result"
            : readiness.result.subtype === "error"
              ? "runtime-error-result"
              : "ready-state-" + String(readinessValue && readinessValue.readyState || "missing");
      throw new CaptureError("the selected target did not reach a complete render-ready state (" + reason + ")");
    }
    const stateWitness = await captureStateWitness(client, loadedStateContract.contract, readinessValue, "pre");
    const navigationFingerprint = sha256(Buffer.from(JSON.stringify({
      publicLocation: readinessValue.publicLocation,
      navigationTimeOrigin: readinessValue.navigationTimeOrigin,
    }), "utf8"));
    const referenceFingerprint = sha256(Buffer.from(readinessValue.publicLocation, "utf8"));
    const inventoryResult = await client.call("Runtime.evaluate", {
      expression: probeSource,
      returnByValue: true,
      awaitPromise: true,
      silent: true,
    });
    if (
      inventoryResult.exceptionDetails
      || !inventoryResult.result
      || !inventoryResult.result.value
      || typeof inventoryResult.result.value !== "object"
      || Array.isArray(inventoryResult.result.value)
    ) {
      throw new CaptureError("web_asset_probe.js did not return a serializable inventory");
    }
    const domRaw = await client.call("DOMSnapshot.captureSnapshot", {
      computedStyles: COMPUTED_STYLES,
      includePaintOrder: true,
      includeDOMRects: true,
      includeBlendedBackgroundColors: false,
      includeTextColorOpacities: false,
    });
    const axRaw = await client.call("Accessibility.getFullAXTree", {});
    const platformFonts = await capturePlatformFonts(client, domRaw, inventoryResult.result.value, { scopeRoots: [options.fontScopeRoot] });
    if (platformFonts.scanTruncated || platformFonts.failedNodeCount || platformFonts.unmappedNodeCount || platformFonts.budgetExhausted || platformFonts.scopeMissing) {
      const diagnostics = {
        scopeRoots: platformFonts.scopeRoots,
        scopeMissing: platformFonts.scopeMissing,
        candidateNodeCount: platformFonts.candidateNodeCount,
        queriedNodeCount: platformFonts.queriedNodeCount,
        failedNodeCount: platformFonts.failedNodeCount,
        unmappedNodeCount: platformFonts.unmappedNodeCount,
        scanTruncated: platformFonts.scanTruncated,
        budgetExhausted: platformFonts.budgetExhausted,
        timedOutNodeCount: platformFonts.timedOutNodeCount,
      };
      throw new CaptureError(`platform font capture was incomplete: ${JSON.stringify(diagnostics)}; use a component-scoped supported-browser capture or reduce the page scope`);
    }
    const screenshotRaw = await client.call("Page.captureScreenshot", {
      format: "png",
      fromSurface: true,
      captureBeyondViewport: true,
    });
    if (typeof screenshotRaw.data !== "string") throw new CaptureError("CDP did not return screenshot data");
    const screenshot = Buffer.from(screenshotRaw.data, "base64");
    if (screenshot.length < 8 || screenshot.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") {
      throw new CaptureError("CDP screenshot data was not a PNG");
    }

    const postCaptureIdentity = await client.call("Runtime.evaluate", {
      expression: `({
        publicLocation: location.origin + location.pathname,
        navigationTimeOrigin: performance.timeOrigin
      })`,
      returnByValue: true,
      silent: true,
    });
    const postCaptureValue = postCaptureIdentity && postCaptureIdentity.result && postCaptureIdentity.result.value;
    const stateWitnessPost = await captureStateWitness(client, loadedStateContract.contract, readinessValue, "post");
    const postCaptureFingerprint = sha256(Buffer.from(JSON.stringify(postCaptureValue || {}), "utf8"));
    if (postCaptureFingerprint !== navigationFingerprint) {
      throw new CaptureError("the selected target changed document or route during capture");
    }

    const outputFiles = {
      environment: path.join(paths.outputDir, "environment.json"),
      inventory: path.join(paths.outputDir, "inventory.json"),
      domSnapshot: path.join(paths.outputDir, "dom-snapshot.json"),
      axTree: path.join(paths.outputDir, "ax-tree.json"),
      fontUsage: path.join(paths.outputDir, "font-usage.json"),
      stateContract: path.join(paths.outputDir, "state-contract.json"),
      stateWitness: path.join(paths.outputDir, "state-witness.json"),
      stateWitnessPost: path.join(paths.outputDir, "state-witness-post.json"),
      screenshot: path.join(paths.outputDir, "reference.png"),
      bundle: path.join(paths.outputDir, "capture-bundle.json"),
    };
    const content = {
      environment: jsonBuffer({
        schemaVersion: "web-capture-environment/1.0",
        browser: {
          protocolVersion: browserVersion.protocolVersion || null,
          product: browserVersion.product || null,
          revision: browserVersion.revision || null,
          userAgent: browserVersion.userAgent || null,
          jsVersion: browserVersion.jsVersion || null,
        },
        layout: {
          cssLayoutViewport: layoutMetrics.cssLayoutViewport || null,
          cssVisualViewport: layoutMetrics.cssVisualViewport || null,
          cssContentSize: layoutMetrics.cssContentSize || null,
        },
        probeViewport: inventoryResult.result.value.viewport || null,
        readiness: {
          readyState: readinessValue.readyState,
          fontsStatus: readinessValue.fontsStatus,
        },
        renderingEnvironment: readinessValue.renderingEnvironment || null,
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
      }),
      inventory: jsonBuffer(inventoryResult.result.value),
      domSnapshot: jsonBuffer(options.contentPolicy === "public-observable"
        ? normalizedPublicDomSnapshot(domRaw)
        : summarizeDomSnapshot(domRaw)),
      axTree: jsonBuffer(options.contentPolicy === "public-observable"
        ? normalizedPublicAxTree(axRaw)
        : summarizeAxTree(axRaw)),
      fontUsage: jsonBuffer(platformFonts),
      stateContract: jsonBuffer(loadedStateContract.contract),
      stateWitness: jsonBuffer(stateWitness),
      stateWitnessPost: jsonBuffer(stateWitnessPost),
      screenshot,
    };
    const artifacts = {
      environment: artifactRecord(paths.projectRoot, outputFiles.environment, content.environment, "application/json"),
      inventory: artifactRecord(paths.projectRoot, outputFiles.inventory, content.inventory, "application/json"),
      domSnapshot: artifactRecord(paths.projectRoot, outputFiles.domSnapshot, content.domSnapshot, "application/json"),
      axTree: artifactRecord(paths.projectRoot, outputFiles.axTree, content.axTree, "application/json"),
      fontUsage: artifactRecord(paths.projectRoot, outputFiles.fontUsage, content.fontUsage, "application/json"),
      stateContract: artifactRecord(paths.projectRoot, outputFiles.stateContract, content.stateContract, "application/json"),
      stateWitness: artifactRecord(paths.projectRoot, outputFiles.stateWitness, content.stateWitness, "application/json"),
      stateWitnessPost: artifactRecord(paths.projectRoot, outputFiles.stateWitnessPost, content.stateWitnessPost, "application/json"),
      screenshot: artifactRecord(paths.projectRoot, outputFiles.screenshot, content.screenshot, "image/png"),
    };
    const bundle = {
      schemaVersion: BUNDLE_SCHEMA,
      capturedAt: new Date().toISOString(),
      captureMode: "read-only-existing-target",
      contentPolicy: options.contentPolicy,
      context: options.context,
      navigationFingerprint,
      referenceFingerprint,
      stateContractSha256: sha256(content.stateContract),
      stateWitnessSha256: sha256(content.stateWitness),
      stateWitnessPostSha256: sha256(content.stateWitnessPost),
      viewport: readinessValue.viewport,
      targetSelection: { kind: options.targetId != null ? "target-id" : "target-url", valuePersisted: false },
      probe: {
        path: "scripts/web_asset_probe.js",
        sha256: sha256(Buffer.from(probeSource, "utf8")),
      },
      protocolMethods: [
        "Browser.getVersion",
        "Page.getLayoutMetrics",
        "Runtime.evaluate",
        "DOM.enable",
        "CSS.enable",
        "DOMSnapshot.captureSnapshot",
        "Accessibility.getFullAXTree",
        "CSS.getPlatformFontsForNode",
        "Page.captureScreenshot",
      ],
      sideEffects: {
        reload: false,
        navigation: false,
        clicks: false,
        domMutation: false,
        assetDownloads: false,
      },
      privacy: {
        cdpEndpointPersisted: false,
        websocketUrlPersisted: false,
        targetSelectorValuePersisted: false,
        domSnapshotRawPersisted: false,
        axTreeRawPersisted: false,
        normalizedPublicObservableValuesPersisted: options.contentPolicy === "public-observable",
      },
      artifacts,
      limitations: [
        options.contentPolicy === "public-observable"
          ? "Public observable DOM/AX values are normalized and secret-bearing fields remain excluded."
          : "DOMSnapshot and accessibility artifacts are privacy-minimized structural summaries.",
        "The screenshot may visibly contain information already rendered in the selected target.",
        "capture-bundle.json is the manifest and therefore cannot contain a stable hash of itself.",
      ],
    };
    const bundleContent = jsonBuffer(bundle);

    await atomicWrite(outputFiles.environment, content.environment);
    await atomicWrite(outputFiles.inventory, content.inventory);
    await atomicWrite(outputFiles.domSnapshot, content.domSnapshot);
    await atomicWrite(outputFiles.axTree, content.axTree);
    await atomicWrite(outputFiles.fontUsage, content.fontUsage);
    await atomicWrite(outputFiles.stateContract, content.stateContract);
    await atomicWrite(outputFiles.stateWitness, content.stateWitness);
    await atomicWrite(outputFiles.stateWitnessPost, content.stateWitnessPost);
    await atomicWrite(outputFiles.screenshot, content.screenshot);
    await atomicWrite(outputFiles.bundle, bundleContent);

    return {
      ok: true,
      schemaVersion: BUNDLE_SCHEMA,
      bundle: artifactRecord(paths.projectRoot, outputFiles.bundle, bundleContent, "application/json"),
    };
  } finally {
    client.close();
  }
}

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
      process.stdout.write(usage() + "\n");
      return;
    }
    const result = await capture(options);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } catch (error) {
    const message = error instanceof CaptureError ? error.message : "unexpected capture failure";
    process.stderr.write("web_capture_cdp: " + message + "\n");
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
} else {
  module.exports = {
    COMPUTED_STYLES,
    artifactRecord,
    capturePlatformFonts,
    captureStateWitness,
    jsonBuffer,
    normalizedScopeLocator,
    stateContract,
    normalizedPublicAxTree,
    normalizedPublicDomSnapshot,
    publicUrl,
    sha256,
  };
}
