#!/usr/bin/env python3
"""Offline helpers for turning Web probe evidence into fidelity work items.

The commands in this module are deliberately read-only with respect to the
Web: they only read local JSON, hash it, and optionally write a local JSON
result.  No URL is fetched and no discovered asset is treated as resolved.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit


PROBE_SCHEMA = "web-asset-inventory/1.0"
OUTPUT_SCHEMA = 1
EXIT_OK = 0
EXIT_ARGUMENT = 2
EXIT_INVENTORY = 3
EXIT_TRUNCATED = 4
EXIT_OUTPUT = 5

COLLECTIONS = (
    "images",
    "imageInputs",
    "videos",
    "sources",
    "inlineSvgs",
    "svgUses",
    "svgExternalReferences",
    "canvases",
    "iframes",
    "cssImages",
    "pseudoElements",
    "visibleElements",
)
RIGHTS_VALUES = {
    "user_owned",
    "licensed",
    "explicit_authorized",
    "reference_only",
    "unknown",
    "unauthorized",
}


class PipelineError(Exception):
    """Expected CLI failure with a stable machine-readable exit code."""

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse owns wording
        raise PipelineError("invalid_arguments", message, EXIT_ARGUMENT)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value)[:16]}"


def _safe_url(raw_value: str) -> str:
    """Return a reference that cannot expose credentials, query, or fragment."""

    raw = raw_value.strip()
    lowered = raw.lower()
    if lowered.startswith("data:"):
        media = re.match(r"^data:([^;,\s]+)", raw, re.IGNORECASE)
        media_type = media.group(1).lower() if media else "application/octet-stream"
        if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
            media_type = "application/octet-stream"
        return f"data:{media_type}"
    if lowered.startswith("blob:"):
        return "blob:redacted"
    if lowered.startswith("javascript:"):
        return "blocked:javascript"
    if raw.startswith("#"):
        fragment = re.sub(r"[^A-Za-z0-9_.:-]", "_", raw[1:])[:256]
        return f"#{fragment}"

    try:
        parsed = urlsplit(raw)
    except ValueError:
        return f"invalid:sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"

    if parsed.scheme.lower() in {"http", "https"}:
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        try:
            port = f":{parsed.port}" if parsed.port is not None else ""
        except ValueError:
            return f"invalid:sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"
        return urlunsplit((parsed.scheme.lower(), hostname + port, parsed.path or "/", "", ""))

    # Relative Web paths and uncommon non-sensitive schemes retain only their
    # scheme/path.  Query and fragment are discarded in every case.
    safe_path = parsed.path.replace("\x00", "")
    if parsed.netloc:
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.split("@")[-1], safe_path, "", ""))
    return urlunsplit((parsed.scheme.lower(), "", safe_path, "", "")) or "invalid:empty"


def _source_ref(value: Any) -> Optional[str]:
    """Normalize probe sourceRef objects without re-emitting arbitrary fields."""

    if value is None:
        return None
    if isinstance(value, str):
        return _safe_url(value)
    if not isinstance(value, Mapping):
        return f"invalid:sha256:{_digest(value)}"

    kind = str(value.get("kind", "")).strip().lower()
    if kind == "url" and isinstance(value.get("url"), str):
        return _safe_url(value["url"])
    if kind == "fragment":
        target = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(value.get("target", "")))[:256]
        return f"#{target}"
    if kind == "data":
        return _safe_url(f"data:{value.get('mediaType') or 'application/octet-stream'},")
    if kind == "blob":
        return "blob:redacted"
    if kind == "blocked":
        scheme = re.sub(r"[^a-z0-9+.-]", "", str(value.get("scheme", "unknown")).lower())
        return f"blocked:{scheme or 'unknown'}"
    if kind == "invalid":
        scheme = re.sub(r"[^a-z0-9+.-]", "", str(value.get("scheme", "unknown")).lower())
        return f"invalid:{scheme or 'unknown'}"
    return f"source:{kind or 'unknown'}:sha256:{_digest(value)}"


def _identity(record: Mapping[str, Any]) -> str:
    """Fingerprint DOM identity without persisting selectors or page text."""

    return _digest(
        {
            "tag": record.get("tag"),
            "locator": record.get("locator"),
            "domFingerprint": record.get("domFingerprint"),
        }
    )[:20]


def _inventory_identity(record: Mapping[str, Any], index: int) -> str:
    explicit = record.get("occurrence_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    for field in ("domFingerprint", "locator"):
        candidate = record.get(field)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return f"index-{index}"


def _geometry_visible(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    width = value.get("width")
    height = value.get("height")
    if not isinstance(width, (int, float)) or isinstance(width, bool) or width <= 0:
        return False
    if not isinstance(height, (int, float)) or isinstance(height, bool) or height <= 0:
        return False
    rect_count = value.get("clientRectCount")
    return rect_count is None or (isinstance(rect_count, (int, float)) and rect_count > 0)


def _paint_visible(record: Mapping[str, Any]) -> bool:
    visibility = record.get("paintVisibility")
    if isinstance(visibility, Mapping) and visibility.get("paintedVisible") is False:
        return False
    return _geometry_visible(record.get("geometry"))


def _source_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if not isinstance(value, Mapping):
        return False
    if value.get("kind") in {"blocked", "invalid"}:
        return False
    return any(value.get(field) not in (None, "") for field in ("url", "target", "mediaType", "kind"))


def _property_sources(value: Any, path: str) -> List[Any]:
    """Mirror Gate source counting and return one source per derived slot."""

    if not isinstance(value, Mapping):
        return []
    sources = value.get("sources")
    if isinstance(sources, list):
        return [source for source in sources if _source_present(source)]
    if sources is not None:
        raise PipelineError("invalid_inventory", f"{path}.sources must be an array", EXIT_INVENTORY)
    if value.get("value") not in (None, "", "none", "normal"):
        return [{"kind": "declaration", "fingerprint": _digest(value.get("value"))}]
    return []


def _list(value: Any, path: str) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PipelineError("invalid_inventory", f"{path} must be an array", EXIT_INVENTORY)
    return value


def _load_inventory(path: Path) -> Tuple[Dict[str, Any], str, Path]:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PipelineError("inventory_not_found", "inventory path is not a readable local file", EXIT_INVENTORY) from error
    if not resolved.is_file():
        raise PipelineError("inventory_not_file", "inventory path must identify a local file", EXIT_INVENTORY)
    try:
        payload = resolved.read_bytes()
        inventory = json.loads(payload.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PipelineError("inventory_unreadable", "inventory must be readable UTF-8 JSON", EXIT_INVENTORY) from error
    if not isinstance(inventory, dict):
        raise PipelineError("invalid_inventory", "inventory root must be an object", EXIT_INVENTORY)
    if inventory.get("schemaVersion") != PROBE_SCHEMA:
        raise PipelineError("unsupported_inventory_schema", f"schemaVersion must be {PROBE_SCHEMA}", EXIT_INVENTORY)
    dom = inventory.get("dom")
    if not isinstance(dom, dict) or not isinstance(dom.get("scanTruncated"), bool):
        raise PipelineError("invalid_inventory", "dom.scanTruncated must be a boolean", EXIT_INVENTORY)
    if dom["scanTruncated"]:
        raise PipelineError("scan_truncated", "probe scan is partial; capture a complete inventory before import", EXIT_TRUNCATED)
    for name in COLLECTIONS:
        if name in inventory and not isinstance(inventory[name], list):
            raise PipelineError("invalid_inventory", f"{name} must be an array", EXIT_INVENTORY)
    fonts = inventory.get("fonts")
    if fonts is not None and not isinstance(fonts, dict):
        raise PipelineError("invalid_inventory", "fonts must be an object", EXIT_INVENTORY)
    if isinstance(fonts, dict):
        _list(fonts.get("faces"), "fonts.faces")
        _list(fonts.get("visibleFamilyDeclarations"), "fonts.visibleFamilyDeclarations")
    return inventory, hashlib.sha256(payload).hexdigest(), resolved


def _project_artifact(root: Path, path: Path) -> Dict[str, str]:
    resolved = path.expanduser().resolve(strict=True)
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise PipelineError("artifact_outside_project", "artifact path escapes project-root", EXIT_ARGUMENT) from exc
    return {"path": relative, "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()}


def _resolve_artifact(root: Path, value: Any, field: str) -> Path:
    if not isinstance(value, Mapping):
        raise PipelineError("bundle_invalid", f"{field} must contain path and sha256", EXIT_INVENTORY)
    raw_path = value.get("path")
    expected = value.get("sha256")
    if not isinstance(raw_path, str) or not raw_path.strip() or not isinstance(expected, str):
        raise PipelineError("bundle_invalid", f"{field} must contain path and sha256", EXIT_INVENTORY)
    try:
        candidate = (root / raw_path).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PipelineError("bundle_invalid", f"{field} is unavailable inside project-root", EXIT_INVENTORY) from exc
    actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or actual != expected.lower():
        raise PipelineError("bundle_hash_mismatch", f"{field} sha256 does not match", EXIT_INVENTORY)
    return candidate


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _locator_in_scope(record: Mapping[str, Any], root_locator: str) -> bool:
    if root_locator == "*":
        return True
    locator = record.get("locator")
    if not isinstance(locator, str):
        return False
    if locator == root_locator or locator.startswith(root_locator + " > ") or locator.startswith(root_locator + " >>> "):
        return True
    ancestors = record.get("ancestorLocators")
    if ancestors is None:
        return False
    if not isinstance(ancestors, list) or any(not isinstance(item, str) for item in ancestors):
        raise PipelineError("inventory_invalid", "ancestorLocators must be an array of strings", EXIT_INVENTORY)
    return root_locator in ancestors


def _font_family_names(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    return {
        part.strip().strip("\"'").casefold()
        for part in value.split(",")
        if part.strip().strip("\"'")
    }


def _scoped_fonts(inventory: Mapping[str, Any], elements: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Keep only font declarations that can affect the declared component scope."""

    fonts = inventory.get("fonts")
    if not isinstance(fonts, Mapping):
        return {}
    scoped = copy.deepcopy(dict(fonts))
    used_names: set[str] = set()
    for element in elements:
        font = element.get("font") if isinstance(element, Mapping) else None
        if isinstance(font, Mapping):
            used_names.update(_font_family_names(font.get("family")))
    faces = fonts.get("faces", [])
    declarations = fonts.get("visibleFamilyDeclarations", [])
    if isinstance(faces, list):
        scoped["faces"] = [
            copy.deepcopy(face)
            for face in faces
            if isinstance(face, Mapping) and _font_family_names(face.get("family")) & used_names
        ]
    if isinstance(declarations, list):
        scoped["visibleFamilyDeclarations"] = [
            copy.deepcopy(declaration)
            for declaration in declarations
            if isinstance(declaration, Mapping)
            and _font_family_names(declaration.get("family")) & used_names
        ]
    return scoped


def _scoped_inventory(inventory: Mapping[str, Any], scope_id: str, root_locator: str) -> Dict[str, Any]:
    scoped = copy.deepcopy(dict(inventory))
    for collection in COLLECTIONS:
        records = inventory.get(collection, [])
        if not isinstance(records, list):
            raise PipelineError("inventory_invalid", f"{collection} must be an array", EXIT_INVENTORY)
        scoped[collection] = [
            copy.deepcopy(record)
            for record in records
            if isinstance(record, Mapping) and _locator_in_scope(record, root_locator)
        ]
    scoped["scope"] = {
        "scope_id": scope_id,
        "kind": "page" if root_locator == "*" else "component",
        "root_locator": root_locator,
    }
    scoped.setdefault("dom", {})["scopedVisibleElementCount"] = len(scoped.get("visibleElements", []))
    if root_locator != "*":
        scoped_font_records = list(scoped.get("visibleElements", [])) + list(scoped.get("pseudoElements", []))
        scoped["fonts"] = _scoped_fonts(inventory, scoped_font_records)
    if root_locator != "*" and not any(
        record.get("locator") == root_locator
        for record in scoped.get("visibleElements", [])
        if isinstance(record, Mapping)
    ):
        raise PipelineError("scope_root_missing", "root locator is absent from visibleElements", EXIT_INVENTORY)
    return scoped


def _component_tokens(elements: Sequence[Mapping[str, Any]]) -> Dict[str, List[str]]:
    """Extract a small deterministic token summary without inventing design values."""

    fields = {
        "font_families": ("font", "family"),
        "font_sizes": ("font", "size"),
        "font_weights": ("font", "weight"),
        "foreground_colors": ("paint", "color"),
        "background_colors": ("paint", "backgroundColor"),
        "border_radii": ("paint", "borderRadius"),
        "box_shadows": ("paint", "boxShadow"),
        "gaps": ("layout", "gap"),
    }
    tokens: Dict[str, List[str]] = {}
    for output_name, (section_name, field_name) in fields.items():
        values = {
            str(section[field_name])
            for element in elements
            if isinstance(element, Mapping)
            and isinstance(element.get(section_name), Mapping)
            and (section := element[section_name]).get(field_name) is not None
        }
        tokens[output_name] = sorted(values)
    return tokens


def _apply_resolution_patch(manifest: MutableMapping[str, Any], patch_path: Optional[Path]) -> None:
    if patch_path is None:
        return
    try:
        patch = json.loads(patch_path.expanduser().resolve(strict=True).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PipelineError("resolution_patch_invalid", "resolution patch is not readable UTF-8 JSON", EXIT_ARGUMENT) from exc
    if not isinstance(patch, Mapping) or patch.get("schemaVersion") != "web-asset-resolution/1.0":
        raise PipelineError("resolution_patch_invalid", "resolution patch schemaVersion is invalid", EXIT_ARGUMENT)
    updates = patch.get("assets", {})
    if not isinstance(updates, Mapping):
        raise PipelineError("resolution_patch_invalid", "resolution patch assets must be an object", EXIT_ARGUMENT)
    allowed = {
        "in_scope", "visible", "rights", "resolution", "provenance", "source_ref",
        "local_path", "sha256", "evidence_ids", "accepted_deviation", "scope_exclusion",
    }
    assets_by_id = {
        asset.get("asset_id"): asset
        for asset in manifest.get("assets", [])
        if isinstance(asset, MutableMapping)
    }
    unknown = sorted(asset_id for asset_id in updates if asset_id not in assets_by_id)
    if unknown:
        raise PipelineError("resolution_patch_unknown_asset", "resolution patch contains unknown asset IDs", EXIT_ARGUMENT)
    for asset_id, values in updates.items():
        if not isinstance(values, Mapping) or any(field not in allowed for field in values):
            raise PipelineError("resolution_patch_invalid", f"resolution patch for {asset_id} has unsupported fields", EXIT_ARGUMENT)
        assets_by_id[asset_id].update(copy.deepcopy(dict(values)))
        if values.get("resolution") not in (None, "unresolved"):
            assets_by_id[asset_id]["status"] = "RESOLVED"
    font_update = patch.get("global_fonts")
    if font_update is not None:
        if not isinstance(font_update, Mapping):
            raise PipelineError("resolution_patch_invalid", "global_fonts must be an object", EXIT_ARGUMENT)
        status = font_update.get("status")
        evidence = font_update.get("evidence")
        allowed_font_fields = {"status", "evidence", "rights", "scope_exclusion"}
        if any(field not in allowed_font_fields for field in font_update) or not isinstance(evidence, list) or not evidence:
            raise PipelineError("resolution_patch_invalid", "global_fonts requires non-empty path+sha256 evidence", EXIT_ARGUMENT)
        if status == "RESOLVED":
            if any(field not in {"status", "evidence"} for field in font_update):
                raise PipelineError("resolution_patch_invalid", "resolved global_fonts only accepts status and evidence", EXIT_ARGUMENT)
        elif status == "BLOCKED_RIGHTS":
            exclusion = font_update.get("scope_exclusion")
            if (
                font_update.get("rights") not in {"reference_only", "unknown"}
                or not isinstance(exclusion, Mapping)
                or exclusion.get("reason") != "blocked_rights"
                or not isinstance(exclusion.get("evidence_ids"), list)
                or not exclusion.get("evidence_ids")
            ):
                raise PipelineError("resolution_patch_invalid", "BLOCKED_RIGHTS global_fonts requires reference_only/unknown rights and a blocked_rights scope exclusion", EXIT_ARGUMENT)
        else:
            raise PipelineError("resolution_patch_invalid", "global_fonts status must be RESOLVED or BLOCKED_RIGHTS", EXIT_ARGUMENT)
        metadata = manifest.get("metadata")
        if not isinstance(metadata, MutableMapping) or not isinstance(metadata.get("global_fonts"), MutableMapping):
            raise PipelineError("resolution_patch_invalid", "global_fonts were not discovered in the Manifest", EXIT_ARGUMENT)
        metadata["global_fonts"].update(copy.deepcopy(dict(font_update)))
        blockers = manifest.get("blockers")
        if isinstance(blockers, list):
            manifest["blockers"] = [
                blocker for blocker in blockers
                if not isinstance(blocker, Mapping) or blocker.get("code") != "global_font_resolution_required"
            ]
            if status == "BLOCKED_RIGHTS":
                manifest["blockers"].append(
                    {
                        "blocker_id": _stable_id("BLK", {"scope": "global_fonts", "reason": "global_font_rights_blocked"}),
                        "scope": "global_fonts",
                        "code": "global_font_rights_blocked",
                        "status": "OPEN",
                    }
                )


class ManifestBuilder:
    def __init__(self, *, rights: str, viewport: str, state: str, side: str) -> None:
        self.rights = rights
        self.viewport = viewport
        self.state = state
        self.side = side
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.occurrence_assets: Dict[str, Dict[str, Any]] = {}

    def add(
        self,
        *,
        kind: str,
        source: Any,
        record: Mapping[str, Any],
        slot: str,
        occurrence_id: str,
        discriminator: Optional[Any] = None,
        fragment_target: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        safe_source = _source_ref(source)
        if not safe_source:
            return None
        if occurrence_id in self.occurrence_assets:
            return self.occurrence_assets[occurrence_id]
        asset_key = {"kind": kind, "source_ref": safe_source, "discriminator": discriminator}
        asset_id = _stable_id("AST", asset_key)
        occurrence = {
            "occurrence_id": occurrence_id,
            "component_id": f"CMP-{_identity(record)}",
            "side": self.side,
            "viewport": self.viewport,
            "state": self.state,
            "slot": slot,
            "status": "UNRESOLVED",
        }
        asset = self.assets.setdefault(
            asset_id,
            {
                "asset_id": asset_id,
                "kind": kind,
                "in_scope": True,
                "visible": True,
                "rights": self.rights,
                "resolution": "unresolved",
                "provenance": "unresolved",
                "status": "UNRESOLVED",
                "source_ref": safe_source,
                "local_path": None,
                "sha256": None,
                "evidence_ids": [],
                "occurrences": [],
            },
        )
        if fragment_target:
            asset["fragment_target"] = fragment_target
        if occurrence["occurrence_id"] not in {item["occurrence_id"] for item in asset["occurrences"]}:
            asset["occurrences"].append(occurrence)
        self.occurrence_assets[occurrence_id] = asset

        return asset

    def srcset_candidates(self, *, value: Any, path: str) -> List[Dict[str, Any]]:
        if value is None:
            return []
        if isinstance(value, str):
            # Compatibility for hand-authored fixtures; the official probe
            # emits parsed candidate objects.
            candidates = []
            for index, piece in enumerate(re.split(r",(?=\s*[^,\s]+(?:\s|$))", value)):
                bits = piece.strip().split()
                if bits:
                    candidates.append({"source": bits[0], "descriptor": bits[1] if len(bits) > 1 else None, "index": index})
        else:
            candidates = _list(value, path)
        result = []
        for index, candidate in enumerate(candidates):
            if not isinstance(candidate, Mapping):
                raise PipelineError("invalid_inventory", f"{path} entries must be objects", EXIT_INVENTORY)
            descriptor = candidate.get("descriptor")
            safe_descriptor = descriptor if isinstance(descriptor, str) and re.fullmatch(r"[0-9.]+[whx]", descriptor) else None
            safe_source = _source_ref(candidate.get("source"))
            if safe_source:
                result.append({"source_ref": safe_source, "descriptor": safe_descriptor, "candidate_index": index})
        return result

    def add_css(
        self,
        *,
        collection: str,
        collection_index: int,
        value: Any,
        record: Mapping[str, Any],
    ) -> None:
        if value is None:
            return
        if not isinstance(value, Mapping):
            raise PipelineError("invalid_inventory", f"{collection}.properties must be an object", EXIT_INVENTORY)
        for property_name in sorted(value):
            property_value = value[property_name]
            if not isinstance(property_value, Mapping):
                raise PipelineError("invalid_inventory", f"{collection}.{property_name} must be an object", EXIT_INVENTORY)
            for source_index, source in enumerate(_property_sources(property_value, f"{collection}.{property_name}")):
                gate_slot = f"{property_name}-{source_index}"
                self.add(
                    kind="image",
                    source=source,
                    record=record,
                    slot=gate_slot,
                    occurrence_id=f"{collection}:{_inventory_identity(record, collection_index)}:{gate_slot}",
                )

    def finish(self) -> List[Dict[str, Any]]:
        result = list(self.assets.values())
        for asset in result:
            asset["occurrences"].sort(key=lambda item: item["occurrence_id"])
        result.sort(key=lambda item: item["asset_id"])
        return result


def _extract_assets(inventory: Mapping[str, Any], builder: ManifestBuilder) -> List[Dict[str, Any]]:
    """Create exactly one manifest occurrence for every Gate-derived slot."""

    for collection in ("images", "imageInputs"):
        for index, record in enumerate(_list(inventory.get(collection), collection)):
            if not isinstance(record, Mapping):
                raise PipelineError("invalid_inventory", f"{collection} entries must be objects", EXIT_INVENTORY)
            if not _paint_visible(record):
                continue
            rendered = record.get("currentSrc") if _source_present(record.get("currentSrc")) else record.get("src")
            if not _source_present(rendered):
                continue
            occurrence_id = f"{collection}:{_inventory_identity(record, index)}:content"
            asset = builder.add(
                kind="image",
                source=rendered,
                record=record,
                slot="content",
                occurrence_id=occurrence_id,
            )
            if asset is not None and collection == "images":
                candidates = builder.srcset_candidates(value=record.get("srcset"), path=f"images[{index}].srcset")
                picture = record.get("picture")
                if picture is not None:
                    if not isinstance(picture, Mapping):
                        raise PipelineError("invalid_inventory", "images.picture must be an object", EXIT_INVENTORY)
                    for source_index, source_record in enumerate(_list(picture.get("sources"), "images.picture.sources")):
                        if not isinstance(source_record, Mapping):
                            raise PipelineError("invalid_inventory", "picture source entries must be objects", EXIT_INVENTORY)
                        candidates.extend(
                            builder.srcset_candidates(
                                value=source_record.get("srcset"),
                                path=f"images[{index}].picture.sources[{source_index}].srcset",
                            )
                        )
                if candidates:
                    asset["responsive_candidates"] = sorted(
                        candidates,
                        key=lambda item: (item["source_ref"], item.get("descriptor") or "", item["candidate_index"]),
                    )

    for index, record in enumerate(_list(inventory.get("videos"), "videos")):
        if not isinstance(record, Mapping):
            raise PipelineError("invalid_inventory", "videos entries must be objects", EXIT_INVENTORY)
        if not _paint_visible(record):
            continue
        rendered = record.get("currentSrc") if _source_present(record.get("currentSrc")) else record.get("src")
        if _source_present(rendered):
            asset = builder.add(
                kind="video",
                source=rendered,
                record=record,
                slot="content",
                occurrence_id=f"videos:{_inventory_identity(record, index)}:content",
            )
            if asset is not None:
                alternates = []
                for child_index, child in enumerate(_list(record.get("sources"), "videos.sources")):
                    if not isinstance(child, Mapping):
                        raise PipelineError("invalid_inventory", "video source entries must be objects", EXIT_INVENTORY)
                    if _source_present(child.get("src")):
                        alternates.append({"source_ref": _source_ref(child.get("src")), "source_index": child_index})
                    alternates.extend(
                        builder.srcset_candidates(
                            value=child.get("srcset"),
                            path=f"videos[{index}].sources[{child_index}].srcset",
                        )
                    )
                if alternates:
                    asset["responsive_candidates"] = sorted(alternates, key=lambda item: _canonical(item))
        if _source_present(record.get("poster")):
            builder.add(
                kind="image",
                source=record.get("poster"),
                record=record,
                slot="poster",
                occurrence_id=f"videos:{_inventory_identity(record, index)}:poster",
            )

    visible_identities = {
        _inventory_identity(record, index)
        for index, record in enumerate(_list(inventory.get("visibleElements"), "visibleElements"))
        if isinstance(record, Mapping)
    }

    synthetic_collections = (
        ("inlineSvgs", "markup", "svg"),
        ("svgUses", "reference", "svg"),
        ("svgExternalReferences", "source", "svg"),
        ("canvases", "bitmap", "canvas"),
        ("iframes", "content", "iframe"),
    )
    for collection, slot, kind in synthetic_collections:
        for index, record in enumerate(_list(inventory.get(collection), collection)):
            if not isinstance(record, Mapping):
                raise PipelineError("invalid_inventory", f"{collection} entries must be objects", EXIT_INVENTORY)
            if not _paint_visible(record):
                continue
            source: Any = None
            discriminator: Optional[str] = None
            fragment: Optional[str] = None
            if collection == "inlineSvgs":
                fingerprint = record.get("sanitizedMarkupFingerprint") or _digest(record.get("sanitizedMarkup", ""))
                source = f"inline-svg:{_digest(fingerprint)}"
            elif collection == "svgUses":
                source = record.get("source")
                fragment = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(record.get("fragmentTarget") or ""))[:256] or None
                discriminator = fragment
            elif collection == "svgExternalReferences":
                source = record.get("source")
            elif collection == "iframes":
                source = record.get("src")
            if not _source_present(source):
                source = f"{collection}:{slot}:sha256:{_digest(record)}"
            builder.add(
                kind=kind,
                source=source,
                record=record,
                slot=slot,
                occurrence_id=f"{collection}:{_inventory_identity(record, index)}:{slot}",
                discriminator=discriminator,
                fragment_target=fragment,
            )

    for collection in ("cssImages", "pseudoElements"):
        for index, record in enumerate(_list(inventory.get(collection), collection)):
            if not isinstance(record, Mapping):
                raise PipelineError("invalid_inventory", f"{collection} entries must be objects", EXIT_INVENTORY)
            identity = _inventory_identity(record, index)
            paint_visibility = record.get("paintVisibility")
            if isinstance(paint_visibility, Mapping) and paint_visibility.get("paintedVisible") is False:
                continue
            if not _paint_visible(record) and identity not in visible_identities:
                continue
            builder.add_css(collection=collection, collection_index=index, value=record.get("properties"), record=record)
            for source_index, source in enumerate(_property_sources(record.get("content"), f"{collection}.content")):
                gate_slot = f"content-{source_index}"
                builder.add(
                    kind="image",
                    source=source,
                    record=record,
                    slot=gate_slot,
                    occurrence_id=f"{collection}:{identity}:{gate_slot}",
                )

    return builder.finish()


def import_probe(
    inventory_path: Path,
    *,
    project_id: str,
    page_id: str,
    scenario_id: str,
    baseline_id: str,
    side: str,
    viewport: str,
    state: str,
    rights: str,
) -> Dict[str, Any]:
    if rights not in RIGHTS_VALUES:
        raise PipelineError("invalid_rights", f"rights must be one of: {', '.join(sorted(RIGHTS_VALUES))}", EXIT_ARGUMENT)
    inventory, inventory_hash, resolved = _load_inventory(inventory_path)
    builder = ManifestBuilder(rights=rights, viewport=viewport, state=state, side=side)
    assets = _extract_assets(inventory, builder)
    occurrence_count = sum(len(asset["occurrences"]) for asset in assets)
    blockers = [
        {
            "blocker_id": _stable_id("BLK", {"asset_id": asset["asset_id"], "reason": "asset_resolution_required"}),
            "asset_id": asset["asset_id"],
            "code": "asset_resolution_required",
            "status": "OPEN",
        }
        for asset in assets
    ]
    fonts = inventory.get("fonts") or {}
    font_faces = _list(fonts.get("faces"), "fonts.faces")
    visible_font_families = _list(fonts.get("visibleFamilyDeclarations"), "fonts.visibleFamilyDeclarations")
    global_fonts = {
        "status": "UNRESOLVED" if font_faces else ("OBSERVED_STACK" if visible_font_families else "NOT_DISCOVERED"),
        "probe_status": fonts.get("status") if isinstance(fonts.get("status"), str) else None,
        "face_count": len(font_faces),
        "visible_family_count": len(visible_font_families),
        "declaration_fingerprints": sorted(
            {_digest(item) for item in font_faces + visible_font_families if isinstance(item, Mapping)}
        ),
    }
    if font_faces:
        blockers.append(
            {
                "blocker_id": _stable_id("BLK", {"scope": "global_fonts", "reason": "global_font_resolution_required"}),
                "scope": "global_fonts",
                "code": "global_font_resolution_required",
                "status": "OPEN",
            }
        )
    kind_counts: Dict[str, int] = {}
    for asset in assets:
        kind_counts[asset["kind"]] = kind_counts.get(asset["kind"], 0) + 1
    declared_counts = {
        name: len(inventory.get(name, []))
        for name in COLLECTIONS
    }
    declared_counts["fontFaces"] = len(fonts.get("faces", []))
    declared_counts["visibleFontFamilies"] = len(fonts.get("visibleFamilyDeclarations", []))
    return {
        "schema_version": OUTPUT_SCHEMA,
        "pipeline": "web_pipeline/import-probe",
        "fidelity": "pixel",
        "project_id": project_id,
        "page_id": page_id,
        "scenario_id": scenario_id,
        "baseline_id": baseline_id,
        "side": side,
        "required_viewports": [viewport],
        "covered_viewports": [],
        "required_states": [state],
        "covered_states": [],
        "font_fallback": {"checked": False, "pass": False, "unexpected_fallbacks": []},
        "critical_diffs": [],
        "inventory_binding": {
            "path": str(resolved),
            "sha256": inventory_hash,
            "schema_version": inventory["schemaVersion"],
            "scan_truncated": False,
            "declared_counts": declared_counts,
            "discovered_asset_count": len(assets),
            "discovered_occurrence_count": occurrence_count,
        },
        "metadata": {
            "global_fonts": global_fonts,
            "unbound_source_record_count": len(inventory.get("sources", [])),
        },
        "assets": assets,
        "blockers": blockers,
        "unresolved_summary": {
            "status": "BLOCKED" if assets else "CLEAR",
            "asset_count": len(assets),
            "occurrence_count": occurrence_count,
            "blocker_count": len(blockers),
            "global_font_blocked": bool(font_faces),
            "by_kind": dict(sorted(kind_counts.items())),
            "rights": rights,
        },
    }


def compile_builder(
    bundle_path: Path,
    *,
    project_root: Path,
    output_path: Path,
    project_id: str,
    page_id: str,
    scenario_id: str,
    baseline_id: str,
    scope_id: str,
    root_locator: str,
    viewport: str,
    state: str,
    rights: str,
    resolution_patch: Optional[Path] = None,
) -> Dict[str, Any]:
    """Compile one capture bundle into a component-scoped builder manifest."""

    try:
        root = project_root.expanduser().resolve(strict=True)
        bundle_resolved = bundle_path.expanduser().resolve(strict=True)
        bundle_resolved.relative_to(root)
        bundle = json.loads(bundle_resolved.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PipelineError("bundle_invalid", "capture bundle must be readable JSON inside project-root", EXIT_INVENTORY) from exc
    if not isinstance(bundle, Mapping) or bundle.get("schemaVersion") != "web-capture-bundle/2.0":
        raise PipelineError("bundle_invalid", "capture bundle schemaVersion must be web-capture-bundle/2.0", EXIT_INVENTORY)
    context = bundle.get("context")
    expected_context = {
        "projectId": project_id,
        "pageId": page_id,
        "scenarioId": scenario_id,
        "baselineId": baseline_id,
        "viewportId": viewport,
        "stateId": state,
        "side": "reference",
    }
    if not isinstance(context, Mapping) or any(context.get(key) != value for key, value in expected_context.items()):
        raise PipelineError(
            "bundle_context_mismatch",
            "capture bundle context must match project/page/scenario/baseline/viewport/state/reference side",
            EXIT_INVENTORY,
        )
    if bundle.get("contentPolicy") != "public-observable":
        raise PipelineError(
            "bundle_content_policy_insufficient",
            "pixel builder compilation requires public-observable capture evidence",
            EXIT_INVENTORY,
        )
    reference_fingerprint = bundle.get("referenceFingerprint")
    if not isinstance(reference_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", reference_fingerprint):
        raise PipelineError(
            "bundle_reference_fingerprint_missing",
            "capture bundle requires a SHA-256 referenceFingerprint",
            EXIT_INVENTORY,
        )
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise PipelineError("bundle_invalid", "capture bundle artifacts are missing", EXIT_INVENTORY)
    artifact_paths = {
        name: _resolve_artifact(root, artifacts.get(name), f"bundle.artifacts.{name}")
        for name in ("inventory", "environment", "domSnapshot", "axTree", "fontUsage", "stateContract", "stateWitness", "stateWitnessPost", "screenshot")
    }
    source_receipt_path = None
    if bundle.get("captureMode") == "read-only-supported-browser-tab":
        source_receipt_path = _resolve_artifact(root, artifacts.get("sourceReceipt"), "bundle.artifacts.sourceReceipt")
    inventory, _, _ = _load_inventory(artifact_paths["inventory"])
    scoped_inventory = _scoped_inventory(inventory, scope_id, root_locator)

    output_resolved = output_path.expanduser().resolve(strict=False)
    try:
        output_resolved.relative_to(root)
    except ValueError as exc:
        raise PipelineError("output_outside_project", "--output must stay inside project-root", EXIT_OUTPUT) from exc
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", scope_id).strip("-.") or _stable_id("scope", scope_id)
    evidence_dir = output_resolved.parent / (stem + "-builder-evidence")
    inventory_path = evidence_dir / "inventory.json"
    spec_path = evidence_dir / "component-spec.json"
    scoped_bundle_path = evidence_dir / "capture-bundle.json"

    _write_json(inventory_path, scoped_inventory)
    inventory_ref = _project_artifact(root, inventory_path)
    scoped_elements = scoped_inventory.get("visibleElements", [])
    root_record = next(
        (element for element in scoped_elements if isinstance(element, Mapping) and element.get("locator") == root_locator),
        None,
    )
    component_spec = {
        "schemaVersion": "web-component-spec/1.0",
        "component_id": scope_id,
        "scope": scoped_inventory["scope"],
        "source_inventory": inventory_ref,
        "viewport": viewport,
        "states": [state],
        "capture_context": dict(context),
        "element_count": len(scoped_elements),
        "external_render_ancestors": list(root_record.get("ancestorLocators", [])) if isinstance(root_record, Mapping) else [],
        "tokens": _component_tokens(scoped_elements),
        "elements": scoped_elements,
    }
    _write_json(spec_path, component_spec)
    spec_ref = _project_artifact(root, spec_path)

    scoped_bundle = copy.deepcopy(dict(bundle))
    scoped_bundle["schemaVersion"] = "web-capture-bundle/2.0"
    scoped_bundle["scope"] = scoped_inventory["scope"]
    scoped_bundle["parentBundle"] = _project_artifact(root, bundle_resolved)
    scoped_bundle["artifacts"] = {
        "inventory": inventory_ref,
        "environment": _project_artifact(root, artifact_paths["environment"]),
        "domSnapshot": _project_artifact(root, artifact_paths["domSnapshot"]),
        "axTree": _project_artifact(root, artifact_paths["axTree"]),
        "fontUsage": _project_artifact(root, artifact_paths["fontUsage"]),
        "stateContract": _project_artifact(root, artifact_paths["stateContract"]),
        "stateWitness": _project_artifact(root, artifact_paths["stateWitness"]),
        "stateWitnessPost": _project_artifact(root, artifact_paths["stateWitnessPost"]),
        "screenshot": _project_artifact(root, artifact_paths["screenshot"]),
    }
    if source_receipt_path is not None:
        scoped_bundle["artifacts"]["sourceReceipt"] = _project_artifact(root, source_receipt_path)
    _write_json(scoped_bundle_path, scoped_bundle)
    bundle_ref = _project_artifact(root, scoped_bundle_path)

    manifest = import_probe(
        inventory_path,
        project_id=project_id,
        page_id=page_id,
        scenario_id=scenario_id,
        baseline_id=baseline_id,
        side="reference",
        viewport=viewport,
        state=state,
        rights=rights,
    )
    reference_artifacts = [
        dict(bundle_ref, kind="capture-bundle"),
        dict(scoped_bundle["artifacts"]["screenshot"], kind="screenshot"),
        dict(inventory_ref, kind="probe"),
        dict(scoped_bundle["artifacts"]["environment"], kind="environment"),
    ]
    width_match = re.search(r"(?<!\d)(\d{2,4})[x×]", viewport)
    viewport_kind = "mobile" if width_match and int(width_match.group(1)) <= 768 else "desktop"
    manifest.update(
        {
            "enforcement_mode": "capture_bundle_v2",
            "capture_bundle": bundle_ref,
            "reference_fingerprint": reference_fingerprint,
            "probe_inventory": inventory_ref,
            "component_specs": spec_ref,
            "scope": scoped_inventory["scope"],
            "required_viewports": [
                {"id": viewport, "kind": viewport_kind, "reference_capture": {"artifacts": reference_artifacts}}
            ],
            "required_states": [
                {"id": state, "reference_capture": {"artifacts": reference_artifacts}}
            ],
        }
    )
    manifest.pop("covered_viewports", None)
    manifest.pop("covered_states", None)
    manifest.pop("critical_diffs", None)
    _apply_resolution_patch(manifest, resolution_patch)
    _write_json(output_resolved, manifest)
    return manifest


def _flatten(values: Sequence[Sequence[str]]) -> List[str]:
    result: List[str] = []
    for group in values:
        for value in group:
            for item in value.split(","):
                item = item.strip()
                if item and item not in result:
                    result.append(item)
    return result


def capture_plan(
    *,
    project_id: str,
    page_id: str,
    scenario_id: str,
    baseline_id: str,
    viewports: Sequence[str],
    states: Sequence[str],
) -> Dict[str, Any]:
    if not viewports or not states:
        raise PipelineError("invalid_arguments", "at least one viewport and state are required", EXIT_ARGUMENT)
    matrix = []
    for viewport in viewports:
        for state in states:
            key = {
                "project_id": project_id,
                "page_id": page_id,
                "scenario_id": scenario_id,
                "baseline_id": baseline_id,
                "viewport": viewport,
                "state": state,
            }
            matrix.append(
                {
                    "capture_id": _stable_id("CAP", key),
                    "viewport": viewport,
                    "state": state,
                    "reference": {"status": "PENDING", "evidence_path": None, "sha256": None},
                    "replica": {"status": "PENDING", "evidence_path": None, "sha256": None},
                    "comparison": {"status": "PENDING", "diff_path": None, "pass": None},
                }
            )
    return {
        "schema_version": OUTPUT_SCHEMA,
        "pipeline": "web_pipeline/capture-plan",
        "fidelity": "pixel",
        "project_id": project_id,
        "page_id": page_id,
        "scenario_id": scenario_id,
        "baseline_id": baseline_id,
        "required_viewports": list(viewports),
        "required_states": list(states),
        "matrix": matrix,
        "summary": {"pair_count": len(matrix), "capture_count": len(matrix) * 2, "comparison_count": len(matrix)},
    }


def _parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(description="Offline Web replica evidence pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--project-id", required=True)
    common.add_argument("--page-id", required=True)
    common.add_argument("--scenario-id", required=True)
    common.add_argument("--baseline-id", required=True)
    common.add_argument("--output", type=Path)

    importer = subparsers.add_parser("import-probe", parents=[common])
    importer.add_argument("--inventory", "--probe", dest="inventory", required=True, type=Path)
    importer.add_argument("--side", required=True, choices=("reference", "replica"))
    importer.add_argument("--viewport", required=True)
    importer.add_argument("--state", required=True)
    importer.add_argument("--rights", required=True)

    planner = subparsers.add_parser("capture-plan", parents=[common])
    planner.add_argument("--viewports", "--viewport", dest="viewports", required=True, nargs="+", action="append")
    planner.add_argument("--states", "--state", dest="states", required=True, nargs="+", action="append")

    compiler = subparsers.add_parser("compile-builder", parents=[common])
    compiler.add_argument("--project-root", required=True, type=Path)
    compiler.add_argument("--bundle", required=True, type=Path)
    compiler.add_argument("--scope-id", required=True)
    compiler.add_argument("--root-locator", required=True)
    compiler.add_argument("--viewport", required=True)
    compiler.add_argument("--state", required=True)
    compiler.add_argument("--rights", required=True)
    compiler.add_argument("--resolution-patch", type=Path)
    return parser


def _write_output(path: Path, result: Mapping[str, Any]) -> None:
    try:
        resolved = path.expanduser().resolve()
        if resolved.exists() and not resolved.is_file():
            raise OSError("output is not a file")
        resolved.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except (OSError, RuntimeError) as error:
        raise PipelineError("output_write_failed", "output path is not writable", EXIT_OUTPUT) from error


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "import-probe":
            result = import_probe(
                args.inventory,
                project_id=args.project_id,
                page_id=args.page_id,
                scenario_id=args.scenario_id,
                baseline_id=args.baseline_id,
                side=args.side,
                viewport=args.viewport,
                state=args.state,
                rights=args.rights,
            )
        elif args.command == "capture-plan":
            result = capture_plan(
                project_id=args.project_id,
                page_id=args.page_id,
                scenario_id=args.scenario_id,
                baseline_id=args.baseline_id,
                viewports=_flatten(args.viewports),
                states=_flatten(args.states),
            )
        else:
            if args.output is None:
                raise PipelineError("invalid_arguments", "compile-builder requires --output", EXIT_ARGUMENT)
            result = compile_builder(
                args.bundle,
                project_root=args.project_root,
                output_path=args.output,
                project_id=args.project_id,
                page_id=args.page_id,
                scenario_id=args.scenario_id,
                baseline_id=args.baseline_id,
                scope_id=args.scope_id,
                root_locator=args.root_locator,
                viewport=args.viewport,
                state=args.state,
                rights=args.rights,
                resolution_patch=args.resolution_patch,
            )
        if args.output is not None:
            _write_output(args.output, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return EXIT_OK
    except PipelineError as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "pipeline": "web_pipeline",
                    "error": {"code": error.code, "message": error.message},
                    "exit_code": error.exit_code,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
