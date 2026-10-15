"""Explicit host-side VM identity check before a Debian checkpoint boot.

Run only on the owner host while the named qemu:///session guest is shut off.
This module never starts a VM or invokes a collector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .approval import load_vm_inventory
from .run_scenario import _owner_file
from .vm_attestation import verify_domain_xml


def _disk_sha256(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid():
            raise ValueError("unsafe VM disk image")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("VM disk changed during preflight")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def verify_host_vm(inventory: dict[str, str], domain_xml: bytes, state: str) -> None:
    if state.strip() != "shut off":
        raise ValueError("VM must be shut off during host preflight")
    verify_domain_xml(domain_xml, inventory)
    if _disk_sha256(Path(inventory["disk_image_path"])) != inventory["disk_sha256_before_boot"]:
        raise ValueError("VM disk snapshot digest mismatch")


def _virsh(*args: str) -> bytes:
    result = subprocess.run(
        ["virsh", "-c", "qemu:///session", *args],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > 262144:
        raise ValueError("libvirt VM query failed")
    return result.stdout


def preflight(inventory_path: Path, output_path: Path) -> dict[str, Any]:
    raw = _owner_file(inventory_path)
    value = json.loads(raw)
    inventory = load_vm_inventory(
        raw,
        inventory_id=value["inventory_id"],
        endpoint_id=value["endpoint_id"],
        product_uuid=value["vm_product_uuid"],
        machine_id=value["machine_id"],
    )
    name = inventory["vm_name"]
    verify_host_vm(
        inventory,
        _virsh("dumpxml", name),
        _virsh("domstate", name).decode("ascii"),
    )
    record = {
        key: inventory[key]
        for key in (
            "inventory_id",
            "vm_name",
            "vm_product_uuid",
            "machine_id",
            "disk_sha256_before_boot",
        )
    }
    record["verified_at"] = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as opened:
        opened.write(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
        opened.flush()
        os.fsync(opened.fileno())
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        record = preflight(Path(args.inventory), Path(args.output))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.TimeoutExpired,
    ) as error:
        reason = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f"host preflight rejected: {reason}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
