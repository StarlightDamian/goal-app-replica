/*
 * Read-only Web asset discovery probe.
 *
 * Run this whole file as a DevTools console expression, or pass it directly to
 * Playwright/Puppeteer page.evaluate(). It only observes the already-rendered
 * document: it does not fetch, download, click, write storage, or modify either
 * the live DOM or page state. Discovery of an asset is not evidence that the
 * operator owns it or has permission to copy/reuse it; authorization and
 * licensing must be established separately.
 */
(function webAssetProbe() {
  "use strict";

  const SCHEMA_VERSION = "web-asset-inventory/1.0";
  const MAX_ELEMENTS = 25000;
  const MAX_WARNINGS = 500;
  const MAX_CSS_VALUE_CHARS = 16384;
  const MAX_SVG_MARKUP_CHARS = 2000000;
  const warnings = [];
  let suppressedWarnings = 0;
  let redactedSourceCount = 0;
  // Some read-only browser sandboxes intentionally remove WeakMap from the
  // page-evaluation global. The probe is short-lived, so Map is a safe local
  // fallback and keeps the exact same cache semantics for this run.
  const identityCache = typeof WeakMap === "function" ? new WeakMap() : new Map();

  function finite(value, digits) {
    const number = Number(value);
    if (!Number.isFinite(number)) return null;
    const rounded = Number(number.toFixed(digits == null ? 3 : digits));
    return Object.is(rounded, -0) ? 0 : rounded;
  }

  function stringOrNull(value) {
    return value == null || value === "" ? null : String(value);
  }

  function trimTo(value, maxLength) {
    const text = String(value == null ? "" : value);
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + "[truncated]";
  }

  function warn(code, message, context) {
    if (warnings.length >= MAX_WARNINGS) {
      suppressedWarnings += 1;
      return;
    }
    const item = {
      code: String(code),
      message: trimTo(message, 1000),
    };
    if (context) item.context = context;
    warnings.push(item);
  }

  function fnv1a32(value) {
    const text = String(value);
    let hash = 0x811c9dc5;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193);
    }
    return "fnv1a32:" + (hash >>> 0).toString(16).padStart(8, "0");
  }

  function normalizedScheme(value) {
    return String(value == null ? "" : value)
      .replace(/[\u0000-\u0020]+/g, "")
      .toLowerCase();
  }

  function isJavascriptUrl(value) {
    return normalizedScheme(value).startsWith("javascript:");
  }

  function dataMediaType(value) {
    const match = /^data:([^;,\s]*)/i.exec(String(value || ""));
    if (!match || !match[1]) return "text/plain";
    const candidate = match[1].toLowerCase();
    return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(candidate)
      ? candidate
      : "application/octet-stream";
  }

  /**
   * Return a JSON-safe source reference. Normal URLs are resolved and stripped
   * of credentials, query, and fragment. data:/blob: bodies are never retained.
   */
  function sourceRef(value, baseUrl) {
    if (value == null) return null;
    const raw = String(value).trim();
    if (!raw) return null;

    if (/^data:/i.test(raw)) {
      redactedSourceCount += 1;
      return { kind: "data", mediaType: dataMediaType(raw) };
    }
    if (/^blob:/i.test(raw)) {
      redactedSourceCount += 1;
      return { kind: "blob" };
    }
    if (raw.startsWith("#")) {
      return { kind: "fragment", target: trimTo(raw.slice(1), 512) };
    }
    if (isJavascriptUrl(raw)) {
      redactedSourceCount += 1;
      return { kind: "blocked", scheme: "javascript" };
    }

    try {
      const parsed = new URL(raw, baseUrl || document.baseURI);
      const protocol = parsed.protocol.toLowerCase();
      if (protocol === "data:") {
        redactedSourceCount += 1;
        return { kind: "data", mediaType: dataMediaType(raw) };
      }
      if (protocol === "blob:") {
        redactedSourceCount += 1;
        return { kind: "blob" };
      }
      if (protocol === "javascript:") {
        redactedSourceCount += 1;
        return { kind: "blocked", scheme: "javascript" };
      }
      parsed.username = "";
      parsed.password = "";
      parsed.search = "";
      parsed.hash = "";
      return { kind: "url", url: parsed.href };
    } catch (_error) {
      redactedSourceCount += 1;
      const schemeMatch = /^([a-z][a-z0-9+.-]*):/i.exec(raw);
      return {
        kind: "invalid",
        scheme: schemeMatch ? schemeMatch[1].toLowerCase() : null,
      };
    }
  }

  function sourceRefForMarkup(reference) {
    if (!reference) return null;
    if (reference.kind === "url") return reference.url;
    if (reference.kind === "fragment") return "#" + reference.target;
    if (reference.kind === "data") return "[data-type=" + reference.mediaType + "]";
    if (reference.kind === "blob") return "[blob-type=unknown]";
    return null;
  }

  function redactLooseDataAndBlob(value) {
    return String(value)
      .replace(/data:([^;,\s"')]*)(?:[;,][^\s"')<]*)?/gi, function (_all, type) {
        redactedSourceCount += 1;
        return "[data-type=" + dataMediaType("data:" + (type || "")) + "]";
      })
      .replace(/blob:[^\s"')<]*/gi, function () {
        redactedSourceCount += 1;
        return "[blob-type=unknown]";
      });
  }

  function sanitizeCssValue(value, maxLength) {
    const raw = String(value == null ? "" : value);
    const sources = [];
    const urlPattern = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi;
    let safe = raw.replace(urlPattern, function (_whole, doubleQuoted, singleQuoted, bare) {
      const candidate = doubleQuoted != null
        ? doubleQuoted
        : singleQuoted != null
          ? singleQuoted
          : String(bare || "").trim();
      const reference = sourceRef(candidate);
      sources.push(reference);
      const replacement = sourceRefForMarkup(reference);
      return replacement == null ? "url([redacted])" : 'url("' + replacement.replace(/"/g, "\\\"") + '")';
    });

    // Computed CSS normally quotes url(), but this second pass prevents a
    // malformed/unusual data: or blob: token from leaking a payload.
    safe = redactLooseDataAndBlob(safe);
    return {
      value: trimTo(safe, maxLength || MAX_CSS_VALUE_CHARS),
      sources: sources.filter(Boolean),
    };
  }

  function sanitizeCssText(value) {
    let result = sanitizeCssValue(value, MAX_SVG_MARKUP_CHARS).value;
    result = result.replace(
      /@import\s+(["'])(.*?)\1/gi,
      function (_whole, _quote, importUrl) {
        const replacement = sourceRefForMarkup(sourceRef(importUrl));
        return '@import "' + (replacement || "[redacted]").replace(/"/g, "\\\"") + '"';
      }
    );
    return result;
  }

  function parseSrcset(value) {
    const input = String(value == null ? "" : value);
    const candidates = [];
    let position = 0;

    // This follows the useful portion of the HTML srcset tokenizer: a URL is a
    // non-whitespace token (so commas inside data: URLs remain inside it), and
    // descriptors end at the next candidate-separating comma.
    while (position < input.length) {
      while (position < input.length && /[\s,]/.test(input[position])) position += 1;
      if (position >= input.length) break;

      const urlStart = position;
      while (position < input.length && !/\s/.test(input[position])) position += 1;
      let url = input.slice(urlStart, position);
      let endedWithComma = false;
      while (url.endsWith(",")) {
        url = url.slice(0, -1);
        endedWithComma = true;
      }

      while (position < input.length && /\s/.test(input[position])) position += 1;
      const descriptorStart = position;
      if (!endedWithComma) {
        while (position < input.length && input[position] !== ",") position += 1;
      }
      const descriptor = input.slice(descriptorStart, position).trim();
      if (position < input.length && input[position] === ",") position += 1;

      if (url) {
        candidates.push({
          source: sourceRef(url),
          descriptor: descriptor || null,
        });
      }
    }
    return candidates;
  }

  function cssEscape(value) {
    if (typeof CSS !== "undefined" && CSS && typeof CSS.escape === "function") {
      return CSS.escape(String(value));
    }
    return String(value).replace(/[^a-zA-Z0-9_-]/g, function (character) {
      return "\\" + character.codePointAt(0).toString(16) + " ";
    });
  }

  function attrSelectorEscape(value) {
    return String(value)
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/[\n\r\f]/g, function (character) {
        return "\\" + character.codePointAt(0).toString(16) + " ";
      });
  }

  function selectorIsUnique(root, selector, element) {
    try {
      const matches = root.querySelectorAll(selector);
      return matches.length === 1 && matches[0] === element;
    } catch (_error) {
      return false;
    }
  }

  function nthOfType(element) {
    let index = 1;
    let sibling = element.previousElementSibling;
    while (sibling) {
      if (sibling.localName === element.localName) index += 1;
      sibling = sibling.previousElementSibling;
    }
    return index;
  }

  function localStableSelector(element, root) {
    const tag = String(element.localName || element.tagName || "element").toLowerCase();
    const id = element.getAttribute("id");
    if (id) {
      const selector = "#" + cssEscape(id);
      if (selectorIsUnique(root, selector, element)) return selector;
    }

    const stableAttributes = [
      "data-testid",
      "data-test",
      "data-qa",
      "data-cy",
      "aria-label",
      "name",
    ];
    for (const name of stableAttributes) {
      const value = element.getAttribute(name);
      if (!value || value.length > 160) continue;
      const selector = tag + "[" + name + '=\"' + attrSelectorEscape(value) + '\"]';
      if (selectorIsUnique(root, selector, element)) return selector;
    }

    const classNames = Array.from(element.classList || [])
      .filter(function (name) {
        return name && name.length <= 80 && !/^(?:active|selected|focus|hover|open|closed|ng-|css-[a-z0-9]{5,}|jsx-)/i.test(name);
      })
      .slice(0, 3);
    if (classNames.length) {
      const selector = tag + classNames.map(function (name) { return "." + cssEscape(name); }).join("");
      if (selectorIsUnique(root, selector, element)) return selector;
    }

    const parts = [];
    let current = element;
    while (current && current.nodeType === 1) {
      const currentTag = String(current.localName || current.tagName).toLowerCase();
      const currentId = current.getAttribute("id");
      if (currentId) {
        const idSelector = "#" + cssEscape(currentId);
        if (selectorIsUnique(root, idSelector, current)) {
          parts.unshift(idSelector);
          break;
        }
      }
      parts.unshift(currentTag + ":nth-of-type(" + nthOfType(current) + ")");
      const candidate = parts.join(" > ");
      if (selectorIsUnique(root, candidate, element)) break;
      current = current.parentElement;
    }
    return parts.join(" > ") || tag;
  }

  function stableLocator(element) {
    const root = element.getRootNode ? element.getRootNode() : document;
    const local = localStableSelector(element, root);
    if (typeof ShadowRoot !== "undefined" && root instanceof ShadowRoot) {
      return stableLocator(root.host) + " >>> " + local;
    }
    return local;
  }

  function stableAttributeSignature(element) {
    const names = ["id", "data-testid", "data-test", "data-qa", "data-cy", "role", "type", "name"];
    const parts = [];
    for (const name of names) {
      const value = element.getAttribute(name);
      if (value) parts.push(name + "=" + trimTo(value, 160));
    }
    const classes = Array.from(element.classList || []).slice(0, 8).sort();
    if (classes.length) parts.push("class=" + classes.join("."));
    return parts.join("|");
  }

  function stableAncestorLocators(element) {
    const locators = [];
    const seen = {};
    let current = element && element.parentElement;
    let depth = 0;
    while (current && depth < 64) {
      const locator = stableLocator(current);
      if (locator && !seen[locator]) {
        seen[locator] = true;
        locators.push(locator);
      }
      current = current.parentElement;
      depth += 1;
    }

    const root = element && element.getRootNode ? element.getRootNode() : null;
    if (typeof ShadowRoot !== "undefined" && root instanceof ShadowRoot && root.host) {
      current = root.host;
      depth = 0;
      while (current && depth < 64) {
        const locator = stableLocator(current);
        if (locator && !seen[locator]) {
          seen[locator] = true;
          locators.push(locator);
        }
        current = current.parentElement;
        depth += 1;
      }
    }
    return locators;
  }

  function identity(element) {
    if (identityCache.has(element)) return identityCache.get(element);
    const locator = stableLocator(element);
    const tag = String(element.localName || element.tagName || "element").toLowerCase();
    const item = {
      tag: tag,
      locator: locator,
      ancestorLocators: stableAncestorLocators(element),
      domFingerprint: fnv1a32(tag + "|" + locator + "|" + stableAttributeSignature(element)),
    };
    identityCache.set(element, item);
    return item;
  }

  function rectOf(element) {
    try {
      const rect = element.getBoundingClientRect();
      return {
        x: finite(rect.x),
        y: finite(rect.y),
        documentX: finite(rect.x + window.scrollX),
        documentY: finite(rect.y + window.scrollY),
        width: finite(rect.width),
        height: finite(rect.height),
        top: finite(rect.top),
        right: finite(rect.right),
        bottom: finite(rect.bottom),
        left: finite(rect.left),
        clientRectCount: typeof element.getClientRects === "function" ? element.getClientRects().length : null,
      };
    } catch (error) {
      warn("geometry-read-failed", String(error && error.message || error), identity(element));
      return null;
    }
  }

  function computedStyleOf(element, pseudo) {
    try {
      return window.getComputedStyle(element, pseudo || null);
    } catch (error) {
      warn("computed-style-read-failed", String(error && error.message || error), {
        locator: identity(element).locator,
        pseudo: pseudo || null,
      });
      return null;
    }
  }

  function isVisible(element, style, rect) {
    if (!style || !rect) return false;
    if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
    if (style.contentVisibility === "hidden") return false;
    if (Number(style.opacity) === 0) return false;
    return paintVisibilityOf(element, style, rect).paintedVisible;
  }

  function paintVisibilityOf(element, style, rect) {
    const original = rect || rectOf(element);
    if (!style || !original || original.width <= 0 || original.height <= 0 || original.clientRectCount <= 0) {
      return { paintedVisible: false, hitTestVisible: false, clippedByAncestors: false, visibleRect: null };
    }
    if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse" ||
        style.contentVisibility === "hidden" || Number(style.opacity) === 0) {
      return { paintedVisible: false, hitTestVisible: false, clippedByAncestors: false, visibleRect: null };
    }

    let left = Math.max(0, original.left);
    let top = Math.max(0, original.top);
    let right = Math.min(window.innerWidth, original.right);
    let bottom = Math.min(window.innerHeight, original.bottom);
    let clippedByAncestors = left !== original.left || top !== original.top || right !== original.right || bottom !== original.bottom;
    let ancestor = element.parentElement;
    while (ancestor && right > left && bottom > top) {
      const ancestorStyle = computedStyleOf(ancestor);
      const ancestorRect = rectOf(ancestor);
      if (!ancestorStyle || !ancestorRect || ancestorStyle.display === "none" ||
          ancestorStyle.visibility === "hidden" || ancestorStyle.visibility === "collapse" ||
          ancestorStyle.contentVisibility === "hidden" || Number(ancestorStyle.opacity) === 0) {
        return { paintedVisible: false, hitTestVisible: false, clippedByAncestors: true, visibleRect: null };
      }
      const clipsX = /^(?:hidden|clip|scroll|auto)$/.test(ancestorStyle.overflowX || "");
      const clipsY = /^(?:hidden|clip|scroll|auto)$/.test(ancestorStyle.overflowY || "");
      if (clipsX) {
        const nextLeft = Math.max(left, ancestorRect.left);
        const nextRight = Math.min(right, ancestorRect.right);
        clippedByAncestors = clippedByAncestors || nextLeft !== left || nextRight !== right;
        left = nextLeft;
        right = nextRight;
      }
      if (clipsY) {
        const nextTop = Math.max(top, ancestorRect.top);
        const nextBottom = Math.min(bottom, ancestorRect.bottom);
        clippedByAncestors = clippedByAncestors || nextTop !== top || nextBottom !== bottom;
        top = nextTop;
        bottom = nextBottom;
      }
      ancestor = ancestor.parentElement;
    }
    const paintedVisible = right > left && bottom > top;
    let hitTestVisible = false;
    if (paintedVisible && typeof document.elementFromPoint === "function") {
      const hit = document.elementFromPoint((left + right) / 2, (top + bottom) / 2);
      hitTestVisible = Boolean(hit && (hit === element || element.contains(hit)));
    }
    return {
      paintedVisible: paintedVisible,
      hitTestVisible: hitTestVisible,
      clippedByAncestors: clippedByAncestors,
      visibleRect: paintedVisible ? {
        x: finite(left), y: finite(top), width: finite(right - left), height: finite(bottom - top),
        top: finite(top), right: finite(right), bottom: finite(bottom), left: finite(left),
      } : null,
    };
  }

  function cssAssetProperties(style) {
    if (!style) return null;
    const raw = {
      backgroundImage: style.backgroundImage,
      maskImage: style.maskImage && style.maskImage !== "none"
        ? style.maskImage
        : (style.webkitMaskImage || style.getPropertyValue("-webkit-mask-image")),
      borderImageSource: style.borderImageSource,
      listStyleImage: style.listStyleImage,
    };
    const result = {};
    for (const name of Object.keys(raw)) {
      const value = raw[name];
      if (value && value !== "none" && value !== "normal") {
        result[name] = sanitizeCssValue(value);
      }
    }
    return Object.keys(result).length ? result : null;
  }

  function stackingContextReasons(element, style) {
    const reasons = [];
    if (element === document.documentElement) reasons.push("document-root");
    if (style.position === "fixed" || style.position === "sticky") reasons.push("position:" + style.position);
    if ((style.position === "absolute" || style.position === "relative") && style.zIndex !== "auto") reasons.push("positioned-z-index");
    if (Number(style.opacity) < 1) reasons.push("opacity");
    if (style.transform !== "none") reasons.push("transform");
    if (style.perspective !== "none") reasons.push("perspective");
    if (style.filter !== "none" || (style.backdropFilter && style.backdropFilter !== "none")) reasons.push("filter");
    if (style.mixBlendMode !== "normal") reasons.push("mix-blend-mode");
    if (style.isolation === "isolate") reasons.push("isolation");
    if (/\b(?:transform|opacity|filter|perspective)\b/.test(style.willChange || "")) reasons.push("will-change");
    if (/\b(?:layout|paint|strict|content)\b/.test(style.contain || "")) reasons.push("contain");
    return reasons;
  }

  function visibleStyleRecord(element, style, rect) {
    const stackingReasons = stackingContextReasons(element, style);
    return Object.assign({}, identity(element), {
      geometry: rect,
      paintVisibility: paintVisibilityOf(element, style, rect),
      font: {
        family: stringOrNull(style.fontFamily),
        size: stringOrNull(style.fontSize),
        weight: stringOrNull(style.fontWeight),
        style: stringOrNull(style.fontStyle),
        stretch: stringOrNull(style.fontStretch),
        lineHeight: stringOrNull(style.lineHeight),
        letterSpacing: stringOrNull(style.letterSpacing),
        wordSpacing: stringOrNull(style.wordSpacing),
        variant: stringOrNull(style.fontVariant),
        kerning: stringOrNull(style.fontKerning),
        featureSettings: stringOrNull(style.fontFeatureSettings),
        variationSettings: stringOrNull(style.fontVariationSettings),
        textRendering: stringOrNull(style.textRendering),
      },
      layout: {
        boxSizing: stringOrNull(style.boxSizing),
        width: stringOrNull(style.width),
        height: stringOrNull(style.height),
        minWidth: stringOrNull(style.minWidth),
        minHeight: stringOrNull(style.minHeight),
        maxWidth: stringOrNull(style.maxWidth),
        maxHeight: stringOrNull(style.maxHeight),
        marginTop: stringOrNull(style.marginTop),
        marginRight: stringOrNull(style.marginRight),
        marginBottom: stringOrNull(style.marginBottom),
        marginLeft: stringOrNull(style.marginLeft),
        paddingTop: stringOrNull(style.paddingTop),
        paddingRight: stringOrNull(style.paddingRight),
        paddingBottom: stringOrNull(style.paddingBottom),
        paddingLeft: stringOrNull(style.paddingLeft),
        flexDirection: stringOrNull(style.flexDirection),
        flexWrap: stringOrNull(style.flexWrap),
        flexGrow: stringOrNull(style.flexGrow),
        flexShrink: stringOrNull(style.flexShrink),
        flexBasis: stringOrNull(style.flexBasis),
        justifyContent: stringOrNull(style.justifyContent),
        alignItems: stringOrNull(style.alignItems),
        alignContent: stringOrNull(style.alignContent),
        alignSelf: stringOrNull(style.alignSelf),
        gap: stringOrNull(style.gap),
        rowGap: stringOrNull(style.rowGap),
        columnGap: stringOrNull(style.columnGap),
        gridTemplateColumns: stringOrNull(style.gridTemplateColumns),
        gridTemplateRows: stringOrNull(style.gridTemplateRows),
        gridAutoFlow: stringOrNull(style.gridAutoFlow),
        textAlign: stringOrNull(style.textAlign),
        verticalAlign: stringOrNull(style.verticalAlign),
        whiteSpace: stringOrNull(style.whiteSpace),
      },
      layer: {
        display: stringOrNull(style.display),
        visibility: stringOrNull(style.visibility),
        position: stringOrNull(style.position),
        zIndex: stringOrNull(style.zIndex),
        opacity: finite(style.opacity),
        overflowX: stringOrNull(style.overflowX),
        overflowY: stringOrNull(style.overflowY),
        isolation: stringOrNull(style.isolation),
        mixBlendMode: stringOrNull(style.mixBlendMode),
        filter: stringOrNull(style.filter),
        backdropFilter: stringOrNull(style.backdropFilter || style.webkitBackdropFilter),
        willChange: stringOrNull(style.willChange),
        contain: stringOrNull(style.contain),
        contentVisibility: stringOrNull(style.contentVisibility),
        clipPath: stringOrNull(style.clipPath),
        pointerEvents: stringOrNull(style.pointerEvents),
        createsStackingContext: stackingReasons.length > 0,
        stackingContextReasons: stackingReasons,
      },
      transform: {
        value: stringOrNull(style.transform),
        origin: stringOrNull(style.transformOrigin),
        style: stringOrNull(style.transformStyle),
        perspective: stringOrNull(style.perspective),
        perspectiveOrigin: stringOrNull(style.perspectiveOrigin),
      },
      replacedContent: {
        objectFit: stringOrNull(style.objectFit),
        objectPosition: stringOrNull(style.objectPosition),
        imageRendering: stringOrNull(style.imageRendering),
      },
      paint: {
        color: stringOrNull(style.color),
        backgroundColor: stringOrNull(style.backgroundColor),
        borderTop: [style.borderTopWidth, style.borderTopStyle, style.borderTopColor].join(" "),
        borderRight: [style.borderRightWidth, style.borderRightStyle, style.borderRightColor].join(" "),
        borderBottom: [style.borderBottomWidth, style.borderBottomStyle, style.borderBottomColor].join(" "),
        borderLeft: [style.borderLeftWidth, style.borderLeftStyle, style.borderLeftColor].join(" "),
        borderRadius: stringOrNull(style.borderRadius),
        boxShadow: stringOrNull(style.boxShadow),
        textShadow: stringOrNull(style.textShadow),
      },
    });
  }

  function collectElementsAndShadowRoots() {
    const elements = [];
    const shadowRoots = [];
    let truncated = false;

    function walk(root) {
      if (elements.length >= MAX_ELEMENTS) {
        truncated = true;
        return;
      }
      let descendants;
      try {
        descendants = Array.from(root.querySelectorAll("*"));
      } catch (error) {
        warn("dom-scan-failed", String(error && error.message || error));
        return;
      }
      for (const element of descendants) {
        if (elements.length >= MAX_ELEMENTS) {
          truncated = true;
          return;
        }
        elements.push(element);
        if (element.shadowRoot && element.shadowRoot.mode === "open") {
          const hostIdentity = identity(element);
          shadowRoots.push({
            host: hostIdentity,
            mode: "open",
            childElementCount: element.shadowRoot.querySelectorAll("*").length,
          });
          walk(element.shadowRoot);
          if (truncated) return;
        }
      }
    }

    walk(document);
    if (truncated) {
      warn("element-limit-reached", "DOM scan stopped at " + MAX_ELEMENTS + " elements; inventory is partial.");
    }
    return { elements: elements, shadowRoots: shadowRoots, truncated: truncated };
  }

  function escapeXmlText(value) {
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function escapeXmlAttribute(value) {
    return escapeXmlText(value).replace(/"/g, "&quot;");
  }

  function svgAttributeValue(attribute) {
    const name = attribute.name;
    const lowerName = name.toLowerCase();
    const lowerLocalName = String(attribute.localName || name).toLowerCase();
    const raw = attribute.value;

    if (/^on/.test(lowerLocalName)) return null;
    if (lowerLocalName === "href" || lowerLocalName === "src") {
      if (isJavascriptUrl(raw)) return null;
      return sourceRefForMarkup(sourceRef(raw));
    }
    if (
      lowerName === "style" ||
      /^(?:fill|stroke|filter|mask|clip-path|cursor|marker-start|marker-mid|marker-end)$/.test(lowerName) ||
      /url\s*\(/i.test(raw)
    ) {
      return sanitizeCssValue(raw, MAX_SVG_MARKUP_CHARS).value;
    }
    return redactLooseDataAndBlob(raw);
  }

  function serializeSanitizedSvg(svg) {
    function serialize(node, parentLocalName) {
      if (node.nodeType === Node.TEXT_NODE || node.nodeType === Node.CDATA_SECTION_NODE) {
        const text = parentLocalName === "style" ? sanitizeCssText(node.nodeValue || "") : node.nodeValue || "";
        return escapeXmlText(text);
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return "";

      const localName = String(node.localName || node.nodeName).toLowerCase();
      if (localName === "script" || localName === "foreignobject") return "";
      const qualifiedName = node.prefix ? node.prefix + ":" + node.localName : node.localName;
      const attributes = [];
      for (const attribute of Array.from(node.attributes || [])) {
        const value = svgAttributeValue(attribute);
        if (value == null) continue;
        attributes.push(attribute.name + '=\"' + escapeXmlAttribute(value) + '\"');
      }
      const start = "<" + qualifiedName + (attributes.length ? " " + attributes.join(" ") : "") + ">";
      const children = Array.from(node.childNodes || []).map(function (child) {
        return serialize(child, localName);
      }).join("");
      return start + children + "</" + qualifiedName + ">";
    }

    return serialize(svg, null);
  }

  function svgUseReference(element) {
    const raw = element.getAttribute("href") || element.getAttribute("xlink:href") ||
      (element.href && typeof element.href.baseVal === "string" ? element.href.baseVal : null);
    if (!raw) return null;
    const reference = sourceRef(raw);
    const fragmentMatch = /#([^#?]*)$/.exec(raw);
    return {
      source: reference,
      // The fragment is represented separately because source URLs themselves
      // are always emitted without a hash.
      fragmentTarget: fragmentMatch ? trimTo(fragmentMatch[1], 512) : null,
    };
  }

  const collected = collectElementsAndShadowRoots();
  const elements = collected.elements;
  const inventory = {
    schemaVersion: SCHEMA_VERSION,
    probe: {
      mode: "read-only-discovery",
      networkRequestsMadeByProbe: false,
      pageMutationsMadeByProbe: false,
      establishesCopyPermission: false,
      limitations: [
        "Closed and user-agent shadow roots are not observable from page JavaScript.",
        "Cross-origin iframe documents are listed but cannot be inspected by this probe.",
        "Canvas pixels are intentionally not extracted.",
        "data: and blob: payloads are intentionally redacted to type-only references.",
      ],
    },
    page: {
      url: sourceRef(window.location.href),
      baseUrl: sourceRef(document.baseURI),
      title: trimTo(document.title || "", 1000),
      readyState: document.readyState,
      compatMode: document.compatMode,
      characterSet: document.characterSet || null,
    },
    viewport: null,
    dom: {
      discoveredElementCount: elements.length,
      scanTruncated: collected.truncated,
      fingerprint: null,
      shadowRoots: collected.shadowRoots,
    },
    images: [],
    imageInputs: [],
    videos: [],
    sources: [],
    inlineSvgs: [],
    svgUses: [],
    svgExternalReferences: [],
    cssImages: [],
    pseudoElements: [],
    visibleElements: [],
    canvases: [],
    iframes: [],
    performanceResources: [],
    fonts: {
      status: null,
      faces: [],
      visibleFamilyDeclarations: [],
    },
    redaction: null,
    warnings: warnings,
  };

  const documentElement = document.documentElement;
  const scrollingElement = document.scrollingElement || documentElement;
  const visualViewport = window.visualViewport;
  inventory.viewport = {
    innerWidth: finite(window.innerWidth),
    innerHeight: finite(window.innerHeight),
    documentClientWidth: finite(documentElement && documentElement.clientWidth),
    documentClientHeight: finite(documentElement && documentElement.clientHeight),
    devicePixelRatio: finite(window.devicePixelRatio, 4),
    scrollX: finite(window.scrollX),
    scrollY: finite(window.scrollY),
    maxScrollX: finite(scrollingElement ? scrollingElement.scrollWidth - scrollingElement.clientWidth : 0),
    maxScrollY: finite(scrollingElement ? scrollingElement.scrollHeight - scrollingElement.clientHeight : 0),
    documentWidth: finite(scrollingElement && scrollingElement.scrollWidth),
    documentHeight: finite(scrollingElement && scrollingElement.scrollHeight),
    visualViewport: visualViewport ? {
      width: finite(visualViewport.width),
      height: finite(visualViewport.height),
      offsetLeft: finite(visualViewport.offsetLeft),
      offsetTop: finite(visualViewport.offsetTop),
      pageLeft: finite(visualViewport.pageLeft),
      pageTop: finite(visualViewport.pageTop),
      scale: finite(visualViewport.scale, 4),
    } : null,
  };

  const styleCache = typeof WeakMap === "function" ? new WeakMap() : new Map();
  const rectCache = typeof WeakMap === "function" ? new WeakMap() : new Map();
  const visibleFontFamilies = new Map();
  function styleFor(element) {
    if (!styleCache.has(element)) styleCache.set(element, computedStyleOf(element));
    return styleCache.get(element);
  }
  function rectFor(element) {
    if (!rectCache.has(element)) rectCache.set(element, rectOf(element));
    return rectCache.get(element);
  }

  for (const element of elements) {
    const tag = String(element.localName || "").toLowerCase();
    const style = styleFor(element);
    const rect = rectFor(element);
    const baseIdentity = Object.assign({}, identity(element), {
      paintVisibility: paintVisibilityOf(element, style, rect),
    });

    if (tag === "img") {
      const picture = element.parentElement && element.parentElement.localName === "picture"
        ? element.parentElement
        : null;
      const pictureSources = picture
        ? Array.from(picture.querySelectorAll(":scope > source")).map(function (source) {
          return Object.assign({}, identity(source), {
            srcset: parseSrcset(source.getAttribute("srcset")),
            sizes: stringOrNull(source.getAttribute("sizes")),
            media: stringOrNull(source.getAttribute("media")),
            type: stringOrNull(source.getAttribute("type")),
          });
        })
        : [];
      inventory.images.push(Object.assign({}, baseIdentity, {
        src: sourceRef(element.getAttribute("src")),
        currentSrc: sourceRef(element.currentSrc),
        srcset: parseSrcset(element.getAttribute("srcset")),
        sizes: stringOrNull(element.getAttribute("sizes")),
        picture: picture ? {
          identity: identity(picture),
          sources: pictureSources,
        } : null,
        loading: stringOrNull(element.loading),
        decoding: stringOrNull(element.decoding),
        crossOrigin: stringOrNull(element.crossOrigin),
        referrerPolicy: stringOrNull(element.referrerPolicy),
        width: finite(element.width),
        height: finite(element.height),
        naturalWidth: finite(element.naturalWidth),
        naturalHeight: finite(element.naturalHeight),
        complete: Boolean(element.complete),
        geometry: rectFor(element),
      }));
    } else if (tag === "input" && String(element.type).toLowerCase() === "image") {
      inventory.imageInputs.push(Object.assign({}, baseIdentity, {
        src: sourceRef(element.getAttribute("src")),
        currentSrc: sourceRef(element.currentSrc || element.src),
        width: finite(element.width),
        height: finite(element.height),
        geometry: rectFor(element),
      }));
    } else if (tag === "video") {
      const childSources = Array.from(element.querySelectorAll(":scope > source")).map(function (source) {
        return Object.assign({}, identity(source), {
          src: sourceRef(source.getAttribute("src")),
          srcset: parseSrcset(source.getAttribute("srcset")),
          media: stringOrNull(source.getAttribute("media")),
          type: stringOrNull(source.getAttribute("type")),
        });
      });
      inventory.videos.push(Object.assign({}, baseIdentity, {
        src: sourceRef(element.getAttribute("src")),
        currentSrc: sourceRef(element.currentSrc),
        poster: sourceRef(element.getAttribute("poster") || element.poster),
        sources: childSources,
        preload: stringOrNull(element.preload),
        crossOrigin: stringOrNull(element.crossOrigin),
        playsInline: Boolean(element.playsInline),
        muted: Boolean(element.muted),
        loop: Boolean(element.loop),
        controls: Boolean(element.controls),
        width: finite(element.width),
        height: finite(element.height),
        videoWidth: finite(element.videoWidth),
        videoHeight: finite(element.videoHeight),
        readyState: finite(element.readyState, 0),
        geometry: rectFor(element),
      }));
    } else if (tag === "source") {
      inventory.sources.push(Object.assign({}, baseIdentity, {
        parentTag: element.parentElement ? element.parentElement.localName : null,
        src: sourceRef(element.getAttribute("src")),
        srcset: parseSrcset(element.getAttribute("srcset")),
        sizes: stringOrNull(element.getAttribute("sizes")),
        media: stringOrNull(element.getAttribute("media")),
        type: stringOrNull(element.getAttribute("type")),
      }));
    }

    if (tag === "svg") {
      const markup = serializeSanitizedSvg(element);
      const markupTruncated = markup.length > MAX_SVG_MARKUP_CHARS;
      if (markupTruncated) {
        warn("svg-markup-truncated", "Sanitized SVG markup exceeded the per-item output limit.", baseIdentity);
      }
      inventory.inlineSvgs.push(Object.assign({}, baseIdentity, {
        viewBox: stringOrNull(element.getAttribute("viewBox")),
        width: stringOrNull(element.getAttribute("width")),
        height: stringOrNull(element.getAttribute("height")),
        preserveAspectRatio: stringOrNull(element.getAttribute("preserveAspectRatio")),
        role: stringOrNull(element.getAttribute("role")),
        ariaLabel: stringOrNull(element.getAttribute("aria-label")),
        geometry: rectFor(element),
        sanitizedMarkup: markupTruncated ? markup.slice(0, MAX_SVG_MARKUP_CHARS) + "[truncated]" : markup,
        markupTruncated: markupTruncated,
        sanitizedMarkupFingerprint: fnv1a32(markup),
      }));
    } else if (tag === "use") {
      inventory.svgUses.push(Object.assign({}, baseIdentity, svgUseReference(element) || {
        source: null,
        fragmentTarget: null,
      }, {
        geometry: rectFor(element),
      }));
    } else if ((tag === "image" || tag === "feimage") && element.namespaceURI === "http://www.w3.org/2000/svg") {
      const rawHref = element.getAttribute("href") || element.getAttribute("xlink:href");
      inventory.svgExternalReferences.push(Object.assign({}, baseIdentity, {
        kind: tag,
        source: sourceRef(rawHref),
        geometry: rectFor(element),
      }));
    }

    if (tag === "canvas") {
      inventory.canvases.push(Object.assign({}, baseIdentity, {
        bitmapWidth: finite(element.width),
        bitmapHeight: finite(element.height),
        geometry: rectFor(element),
        pixelsExtracted: false,
      }));
    } else if (tag === "iframe") {
      const iframeRecord = Object.assign({}, baseIdentity, {
        src: sourceRef(element.getAttribute("src")),
        hasSrcdoc: element.hasAttribute("srcdoc"),
        name: stringOrNull(element.getAttribute("name")),
        title: stringOrNull(element.getAttribute("title")),
        loading: stringOrNull(element.getAttribute("loading")),
        sandbox: element.hasAttribute("sandbox") ? Array.from(element.sandbox || []) : null,
        allow: stringOrNull(element.getAttribute("allow")),
        referrerPolicy: stringOrNull(element.getAttribute("referrerpolicy")),
        geometry: rectFor(element),
        contentAccessible: false,
        content: null,
      });
      try {
        const childDocument = element.contentDocument;
        if (childDocument && childDocument.documentElement) {
          iframeRecord.contentAccessible = true;
          iframeRecord.content = {
            url: sourceRef(childDocument.URL),
            readyState: childDocument.readyState,
            title: trimTo(childDocument.title || "", 1000),
            elementCount: childDocument.querySelectorAll("*").length,
            width: finite(childDocument.documentElement.scrollWidth),
            height: finite(childDocument.documentElement.scrollHeight),
          };
        } else {
          warn("iframe-content-unavailable", "Iframe content document is unavailable or cross-origin.", baseIdentity);
        }
      } catch (error) {
        warn("iframe-cross-origin", "Iframe content could not be read: " + String(error && error.message || error), baseIdentity);
      }
      inventory.iframes.push(iframeRecord);
    }

    const cssAssets = cssAssetProperties(style);
    if (cssAssets) {
      inventory.cssImages.push(Object.assign({}, baseIdentity, {
        geometry: rect,
        properties: cssAssets,
      }));
    }

    if (isVisible(element, style, rect)) {
      inventory.visibleElements.push(visibleStyleRecord(element, style, rect));
      const family = String(style.fontFamily || "").trim();
      if (family) visibleFontFamilies.set(family, (visibleFontFamilies.get(family) || 0) + 1);
    }

    for (const pseudo of ["::before", "::after"]) {
      const pseudoStyle = computedStyleOf(element, pseudo);
      if (!pseudoStyle) continue;
      const content = pseudoStyle.content;
      const pseudoAssets = cssAssetProperties(pseudoStyle);
      const hasContent = content && content !== "none" && content !== "normal";
      if (hasContent || pseudoAssets) {
        inventory.pseudoElements.push(Object.assign({}, baseIdentity, {
          pseudo: pseudo,
          content: hasContent ? sanitizeCssValue(content) : null,
          font: {
            family: stringOrNull(pseudoStyle.fontFamily),
            style: stringOrNull(pseudoStyle.fontStyle),
            weight: stringOrNull(pseudoStyle.fontWeight),
            stretch: stringOrNull(pseudoStyle.fontStretch),
          },
          display: stringOrNull(pseudoStyle.display),
          visibility: stringOrNull(pseudoStyle.visibility),
          opacity: finite(pseudoStyle.opacity),
          position: stringOrNull(pseudoStyle.position),
          zIndex: stringOrNull(pseudoStyle.zIndex),
          properties: pseudoAssets,
        }));
        const pseudoFamily = String(pseudoStyle.fontFamily || "").trim();
        if (pseudoFamily) visibleFontFamilies.set(pseudoFamily, (visibleFontFamilies.get(pseudoFamily) || 0) + 1);
      }
    }
  }

  inventory.dom.fingerprint = fnv1a32(elements.map(function (element) {
    const item = identity(element);
    return item.domFingerprint + "|" + item.locator;
  }).join("\n"));

  inventory.fonts.visibleFamilyDeclarations = Array.from(visibleFontFamilies.entries())
    .map(function (entry) { return { family: entry[0], visibleElementCount: entry[1] }; })
    .sort(function (left, right) {
      return right.visibleElementCount - left.visibleElementCount || left.family.localeCompare(right.family);
    });

  try {
    if (document.fonts) {
      inventory.fonts.status = document.fonts.status || null;
      inventory.fonts.faces = Array.from(document.fonts).map(function (face) {
        return {
          family: stringOrNull(face.family),
          style: stringOrNull(face.style),
          weight: stringOrNull(face.weight),
          stretch: stringOrNull(face.stretch),
          unicodeRange: stringOrNull(face.unicodeRange),
          variant: stringOrNull(face.variant),
          featureSettings: stringOrNull(face.featureSettings),
          variationSettings: stringOrNull(face.variationSettings),
          display: stringOrNull(face.display),
          status: stringOrNull(face.status),
        };
      }).sort(function (left, right) {
        return JSON.stringify(left).localeCompare(JSON.stringify(right));
      });
    }
  } catch (error) {
    warn("font-inventory-failed", String(error && error.message || error));
  }

  try {
    if (window.performance && typeof window.performance.getEntriesByType === "function") {
      inventory.performanceResources = window.performance.getEntriesByType("resource").map(function (entry) {
        return {
          source: sourceRef(entry.name),
          initiatorType: stringOrNull(entry.initiatorType),
          startTime: finite(entry.startTime),
          duration: finite(entry.duration),
          fetchStart: finite(entry.fetchStart),
          responseStart: finite(entry.responseStart),
          responseEnd: finite(entry.responseEnd),
          transferSize: finite(entry.transferSize, 0),
          encodedBodySize: finite(entry.encodedBodySize, 0),
          decodedBodySize: finite(entry.decodedBodySize, 0),
          nextHopProtocol: stringOrNull(entry.nextHopProtocol),
          deliveryType: stringOrNull(entry.deliveryType),
          renderBlockingStatus: stringOrNull(entry.renderBlockingStatus),
        };
      });
    }
  } catch (error) {
    warn("performance-resource-inventory-failed", String(error && error.message || error));
  }

  warn(
    "closed-shadow-roots-unobservable",
    "Only open shadow roots are included; closed and user-agent roots cannot be enumerated from page JavaScript."
  );
  if (suppressedWarnings) {
    warnings.push({
      code: "warnings-suppressed",
      message: String(suppressedWarnings) + " additional warnings were suppressed after the output limit.",
    });
  }
  inventory.redaction = {
    policy: "normal URLs omit userinfo/query/hash; data/blob payloads are type-only; javascript URLs are blocked",
    redactedSourceCount: redactedSourceCount,
  };

  return inventory;
})();
