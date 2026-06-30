"""Convert persisted STIX-lite records into validated STIX 2.1 bundles."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from stix2 import parse

from .store import Store


def _timestamp(value: str, fallback: str | None = None) -> str:
    candidate = (value or fallback or "").strip()
    if not candidate:
        parsed = datetime.now(timezone.utc)
    else:
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            parsed = parsedate_to_datetime(candidate)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _pattern(ioc_type: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    paths = {
        "domain-name": "domain-name:value",
        "ipv4-addr": "ipv4-addr:value",
        "url": "url:value",
        "file:hashes.'SHA-256'": "file:hashes.'SHA-256'",
        "file:hashes.MD5": "file:hashes.'MD5'",
    }
    path = paths.get(ioc_type)
    if path is None:
        raise ValueError(f"unsupported IOC type for STIX export: {ioc_type}")
    return f"[{path} = '{escaped}']"


def _common(item: dict[str, Any]) -> dict[str, Any]:
    created = _timestamp(str(item.get("created", "")))
    return {
        "type": item["type"],
        "spec_version": "2.1",
        "id": item["id"],
        "created": created,
        "modified": _timestamp(str(item.get("modified", "")), created),
    }


def _labels(item: dict[str, Any], target: dict[str, Any]) -> None:
    labels = [str(label) for label in item.get("labels", []) if str(label)]
    if labels:
        target["labels"] = labels


def _external_reference(item: dict[str, Any], target: dict[str, Any]) -> None:
    source = str(item.get("source", "")).strip()
    url = str(item.get("url", "")).strip()
    if source or url:
        reference: dict[str, str] = {"source_name": source or "UNC Finder"}
        if url:
            reference["url"] = url
        else:
            reference["description"] = f"Collected by the {source} agent."
        target["external_references"] = [reference]


def _convert_indicator(item: dict[str, Any]) -> dict[str, Any]:
    target = _common(item)
    target.update(
        {
            "pattern": _pattern(str(item["ioc_type"]), str(item["value"])),
            "pattern_type": "stix",
            "valid_from": _timestamp(
                str(item.get("valid_from", "")), str(item.get("created", ""))
            ),
            "indicator_types": ["malicious-activity"],
        }
    )
    _labels(item, target)
    _external_reference(item, target)
    return target


def _convert_actor(item: dict[str, Any]) -> dict[str, Any]:
    target = _common(item)
    target["name"] = str(item["name"])
    aliases = [str(alias) for alias in item.get("aliases", []) if str(alias)]
    if aliases:
        target["aliases"] = aliases
    _labels(item, target)
    _external_reference(item, target)
    return target


def _convert_report(
    item: dict[str, Any], related_refs: set[str], actor_ids: dict[str, str]
) -> dict[str, Any]:
    target = _common(item)
    refs = {str(ref) for ref in item.get("object_refs", []) if str(ref)}
    refs.update(related_refs)
    refs.update(actor_ids[label] for label in item.get("labels", []) if label in actor_ids)
    if not refs:
        raise ValueError(f"report {item['id']} has no STIX object references")
    target.update(
        {
            "name": str(item["name"]),
            "published": _timestamp(
                str(item.get("published", "")), str(item.get("created", ""))
            ),
            "report_types": ["threat-report"],
            "object_refs": sorted(refs),
        }
    )
    description = str(item.get("description", "")).strip()
    if description:
        target["description"] = description
    _labels(item, target)
    _external_reference(item, target)
    return target


def _convert_relationship(item: dict[str, Any]) -> dict[str, Any]:
    target = _common(item)
    target.update(
        {
            "relationship_type": str(item["relationship_type"]),
            "source_ref": str(item["source_ref"]),
            "target_ref": str(item["target_ref"]),
        }
    )
    _labels(item, target)
    _external_reference(item, target)
    return target


def _convert_note(item: dict[str, Any]) -> dict[str, Any]:
    target = _common(item)
    target.update(
        {
            "content": str(item["content"]),
            "object_refs": [str(ref) for ref in item.get("object_refs", [])],
        }
    )
    abstract = str(item.get("abstract", "")).strip()
    if abstract:
        target["abstract"] = abstract
    _labels(item, target)
    _external_reference(item, target)
    return target


def build_bundle(store: Store) -> dict[str, Any]:
    """Build and validate a STIX 2.1 bundle from every persisted object."""
    items = store.all()
    actor_ids = {
        str(item["name"]): str(item["id"])
        for item in items
        if item.get("type") == "threat-actor"
    }
    report_refs: dict[str, set[str]] = {}
    for item in items:
        if item.get("type") != "relationship":
            continue
        source_ref = str(item.get("source_ref", ""))
        target_ref = str(item.get("target_ref", ""))
        if source_ref.startswith("report--"):
            report_refs.setdefault(source_ref, set()).add(target_ref)
        if target_ref.startswith("report--"):
            report_refs.setdefault(target_ref, set()).add(source_ref)

    converted: list[dict[str, Any]] = []
    for item in items:
        item_type = item.get("type")
        if item_type == "indicator":
            converted.append(_convert_indicator(item))
        elif item_type == "threat-actor":
            converted.append(_convert_actor(item))
        elif item_type == "report":
            converted.append(
                _convert_report(item, report_refs.get(str(item["id"]), set()), actor_ids)
            )
        elif item_type == "relationship":
            converted.append(_convert_relationship(item))
        elif item_type == "note":
            converted.append(_convert_note(item))

    bundle: dict[str, Any] = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
    }
    if converted:
        bundle["objects"] = converted
    parse(bundle, allow_custom=False, version="2.1")
    return bundle


def write_bundle(store: Store, output: str, pretty: bool = False) -> int:
    """Write a validated bundle to a file or stdout and return object count."""
    bundle = build_bundle(store)
    rendered = json.dumps(bundle, indent=2 if pretty else None, sort_keys=pretty)
    if output == "-":
        print(rendered)
    else:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    return len(bundle.get("objects", []))
