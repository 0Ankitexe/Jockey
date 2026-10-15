"""Offline, exact approval checks before any scenario-owned object is created."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from controller.tests.contracts.collection_decode_support import strict_decode


@dataclass(frozen=True)
class Approval:
    case_id: str
    operator_id: str
    endpoint_id: str
    vm_id: str
    binary_sha256: str
    valid_from: str
    valid_until: str
    owned_root: str
    approval_ref: str


_SCENARIO_KEYS = frozenset(
    {
        "schema_version",
        "approval_id",
        "inventory_id",
        "designation_id",
        "authorisation_id",
        "endpoint_id",
        "case_id",
        "operator_id",
        "valid_from",
        "valid_until",
        "scenario",
        "collector_sha256",
        "owned_scratch_root",
        "output_root",
        "allowed_actions",
        "cold_preparation_reference",
    }
)
_CHECKPOINT_ACTIONS = frozenset(
    {
        "create_benign_processes",
        "bind_loopback_tcp",
        "create_sample_files",
        "cleanup_owned_objects",
    }
)
_LAB_SMALL_ACTIONS = _CHECKPOINT_ACTIONS | {"emit_benign_log_markers"}
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate scenario field")
        result[key] = value
    return result


def _safe_root(value: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "//" in value
        or "\0" in value
        or any(part in (".", "..") for part in value.split("/"))
    ):
        raise ValueError("unsafe scenario root")
    root = PurePosixPath(value)
    if str(root) in ("/", "/tmp", "/home", "/srv"):
        raise ValueError("unsafe scenario root")
    return root


def load_checkpoint_scenario(
    raw: bytes, *, vm_endpoint_id: str, binary_sha256: str, now: str, opt_in: bool
) -> dict[str, Any]:
    """Admit the exact v1 checkpoint declaration before any harness action.

    This checks declaration shape and linkage; the runner must separately
    check owner-controlled files and guest identity before creating objects.
    """
    return _load_scenario(
        raw,
        vm_endpoint_id=vm_endpoint_id,
        binary_sha256=binary_sha256,
        now=now,
        opt_in=opt_in,
        kind="checkpoint",
        actions=_CHECKPOINT_ACTIONS,
    )


def load_lab_small_scenario(
    raw: bytes, *, vm_endpoint_id: str, binary_sha256: str, now: str, opt_in: bool
) -> dict[str, Any]:
    """Admit an owner-approved full LAB-SMALL run, never a checkpoint alias."""
    return _load_scenario(
        raw,
        vm_endpoint_id=vm_endpoint_id,
        binary_sha256=binary_sha256,
        now=now,
        opt_in=opt_in,
        kind="lab-small",
        actions=_LAB_SMALL_ACTIONS,
    )


def _load_scenario(
    raw: bytes,
    *,
    vm_endpoint_id: str,
    binary_sha256: str,
    now: str,
    opt_in: bool,
    kind: str,
    actions: frozenset[str],
) -> dict[str, Any]:
    if not opt_in or len(raw) > 65536:
        raise ValueError("scenario opt-in or size")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid scenario JSON") from error
    if not isinstance(value, dict) or frozenset(value) != _SCENARIO_KEYS:
        raise ValueError("scenario shape")
    strict_decode("lab-scenario", raw)
    if value["schema_version"] != "1.0.0" or value["scenario"] != kind:
        raise ValueError("scenario version or kind")
    for key in (
        "approval_id",
        "inventory_id",
        "designation_id",
        "authorisation_id",
        "endpoint_id",
        "case_id",
        "operator_id",
    ):
        if not isinstance(value[key], str) or not _UUID.fullmatch(value[key]):
            raise ValueError("invalid scenario identifier")
    if value["endpoint_id"] != vm_endpoint_id:
        raise ValueError("wrong VM endpoint")
    digest = value["collector_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid binary digest")
    if digest != binary_sha256:
        raise ValueError("wrong binary")
    if (
        not isinstance(value["allowed_actions"], list)
        or not all(isinstance(action, str) for action in value["allowed_actions"])
        or (
            len(value["allowed_actions"]) != len(actions)
            or frozenset(value["allowed_actions"]) != actions
        )
    ):
        raise ValueError("unsafe scenario actions")
    scratch = _safe_root(value["owned_scratch_root"])
    output = _safe_root(value["output_root"])
    if scratch == output or scratch in output.parents or output in scratch.parents:
        raise ValueError("overlapping scenario roots")
    if (
        not isinstance(value["cold_preparation_reference"], str)
        or not 1 <= len(value["cold_preparation_reference"]) <= 256
    ):
        raise ValueError("missing cold preparation")
    if not isinstance(value["valid_from"], str) or not isinstance(value["valid_until"], str):
        raise TypeError("invalid scenario time")
    start, end, current = map(_utc, (value["valid_from"], value["valid_until"], now))
    if start >= end or not start <= current < end:
        raise ValueError("scenario expired")
    return value


def _utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("non-UTC approval time")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC:
        raise ValueError("non-UTC approval time")
    return parsed


def admit(approval: Approval, vm_id: str, binary_sha256: str, now: str, opt_in: bool) -> bool:
    if not opt_in or not all(
        (
            approval.case_id,
            approval.operator_id,
            approval.endpoint_id,
            approval.vm_id,
            approval.approval_ref,
        )
    ):
        raise ValueError("missing approval")
    if approval.vm_id != vm_id or approval.endpoint_id != vm_id:
        raise ValueError("wrong VM")
    if not re.fullmatch(r"[0-9a-f]{64}", approval.binary_sha256):
        raise ValueError("invalid binary digest")
    if approval.binary_sha256 != binary_sha256:
        raise ValueError("wrong binary")
    root = PurePosixPath(approval.owned_root)
    if (
        not root.is_absolute()
        or str(root) in ("/", "/home", "/tmp")
        or ".." in approval.owned_root.split("/")
    ):
        raise ValueError("unsafe owned root")
    start, end, current = map(_utc, (approval.valid_from, approval.valid_until, now))
    if start >= end or not start <= current < end:
        raise ValueError("approval expired")
    return True


def loopback_only(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError as error:
        raise ValueError("invalid address") from error


def load_vm_inventory(
    raw: bytes,
    *,
    inventory_id: str,
    endpoint_id: str,
    product_uuid: str,
    machine_id: str,
) -> dict[str, str]:
    """Bind the owner-recorded guest identity to the approved scenario."""
    if len(raw) > 65536:
        raise ValueError("inventory size")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid inventory JSON") from error
    if not isinstance(value, dict) or frozenset(value) != {
        "inventory_id",
        "endpoint_id",
        "vm_product_uuid",
        "machine_id",
        "vm_name",
        "disk_image_path",
        "disk_sha256_before_boot",
        "kind",
        "distribution_id",
        "architecture",
    }:
        raise ValueError("inventory shape")
    if (
        value["inventory_id"] != inventory_id
        or value["endpoint_id"] != endpoint_id
        or value["vm_product_uuid"] != product_uuid.lower()
        or value["machine_id"] != machine_id.lower()
        or value["kind"] != "isolated_vm"
        or value["distribution_id"] != "debian"
        or value["architecture"] != "x86_64"
        or not all(
            isinstance(value[key], str) and _UUID.fullmatch(value[key])
            for key in ("inventory_id", "endpoint_id", "vm_product_uuid")
        )
    ):
        raise ValueError("wrong VM inventory")
    if (
        not isinstance(value["machine_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", value["machine_id"])
        or not isinstance(value["vm_name"], str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", value["vm_name"])
        or not isinstance(value["disk_image_path"], str)
        or not value["disk_image_path"].startswith("/")
        or not isinstance(value["disk_sha256_before_boot"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["disk_sha256_before_boot"])
    ):
        raise ValueError("invalid VM inventory fields")
    return value
