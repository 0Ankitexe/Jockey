"""Narrow host/guest identity linkage for the isolated Debian lab VM."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import Any


def verify_domain_xml(raw: bytes, inventory: dict[str, str]) -> None:
    if len(raw) > 262144:
        raise ValueError("oversize libvirt definition")
    try:
        domain = ET.fromstring(raw)
    except ET.ParseError as error:
        raise ValueError("invalid libvirt definition") from error
    disk_sources = [
        source.get("file")
        for disk in domain.findall("./devices/disk")
        if disk.get("device") == "disk"
        for source in disk.findall("source")
    ]
    if (
        domain.tag != "domain"
        or domain.findtext("name") != inventory["vm_name"]
        or domain.findtext("uuid", "").lower() != inventory["vm_product_uuid"]
        or disk_sources != [inventory["disk_image_path"]]
        or domain.findall("./devices/interface")
    ):
        raise ValueError("wrong or networked lab VM")


def load_host_preflight(raw: bytes, inventory: dict[str, str], *, now: str) -> dict[str, Any]:
    if len(raw) > 4096:
        raise ValueError("oversize host preflight")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate preflight field")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid host preflight") from error
    fields = {
        "inventory_id",
        "vm_name",
        "vm_product_uuid",
        "machine_id",
        "disk_sha256_before_boot",
        "verified_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("host preflight shape")
    for key in fields - {"verified_at"}:
        if value[key] != inventory[key]:
            raise ValueError("host preflight identity mismatch")
    try:
        verified = datetime.fromisoformat(value["verified_at"].replace("Z", "+00:00"))
        current = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("invalid preflight time") from error
    if (
        not value["verified_at"].endswith("Z")
        or verified.tzinfo != UTC
        or current.tzinfo != UTC
        or not verified <= current < verified + timedelta(hours=1)
    ):
        raise ValueError("host preflight expired")
    return value
