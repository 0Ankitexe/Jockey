"""Offline host/guest identity admission and fail-closed negative cases."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from .host_preflight import verify_host_vm
from .vm_attestation import load_host_preflight


def inventory(disk: Path) -> dict[str, str]:
    return {
        "inventory_id": "10000000-0000-4000-8000-000000000014",
        "vm_name": "jocky-v5-debian-13-7",
        "vm_product_uuid": "10000000-0000-4000-8000-000000000099",
        "machine_id": "a" * 32,
        "disk_image_path": str(disk),
        "disk_sha256_before_boot": hashlib.sha256(b"owned qcow2 stand-in").hexdigest(),
    }


def domain(value: dict[str, str], network: str = "") -> bytes:
    return (
        f"<domain><name>{value['vm_name']}</name>"
        f"<uuid>{value['vm_product_uuid']}</uuid><devices>"
        f"<disk device='disk'><source file='{value['disk_image_path']}'/></disk>"
        f"{network}</devices></domain>"
    ).encode()


def test_host_preflight_binds_shut_off_unnnetworked_domain_and_disk(
    tmp_path: Path,
) -> None:
    disk = tmp_path / "debian.qcow2"
    disk.write_bytes(b"owned qcow2 stand-in")
    value = inventory(disk)
    verify_host_vm(value, domain(value), "shut off")
    for xml, state in (
        (domain(value), "running"),
        (domain(value, "<interface type='network'/>"), "shut off"),
        (
            domain(value).replace(value["vm_product_uuid"].encode(), b"wrong"),
            "shut off",
        ),
    ):
        with pytest.raises(ValueError):
            verify_host_vm(value, xml, state)
    disk.write_bytes(b"changed disk")
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_host_vm(value, domain(value), "shut off")


def test_guest_preflight_rejects_stale_or_wrong_identity(tmp_path: Path) -> None:
    value = inventory(tmp_path / "debian.qcow2")
    record = {
        key: value[key]
        for key in (
            "inventory_id",
            "vm_name",
            "vm_product_uuid",
            "machine_id",
            "disk_sha256_before_boot",
        )
    }
    record["verified_at"] = "2020-01-01T00:00:00Z"
    raw = json.dumps(record).encode()
    assert load_host_preflight(raw, value, now="2020-01-01T00:59:59Z") == record
    for changed, now in (
        (record, "2020-01-01T01:00:00Z"),
        (record | {"machine_id": "b" * 32}, "2020-01-01T00:30:00Z"),
        (record | {"extra": "bad"}, "2020-01-01T00:30:00Z"),
    ):
        with pytest.raises(ValueError):
            load_host_preflight(json.dumps(changed).encode(), value, now=now)
