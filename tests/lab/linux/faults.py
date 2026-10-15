"""Closed, owner-scoped fault actions for a separately approved native VM run.

Offline tests construct only temporary ledger objects; importing this module is inert.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approval import load_checkpoint_scenario
from .owned_objects import OwnedLedger
from .run_scenario import _owner_file

_ACTIONS = frozenset(
    {"mutate_owned_file", "remove_owned_file", "cancel_owned_child", "output_collision"}
)


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate fault field")
        value[key] = item
    return value


@dataclass(frozen=True)
class FaultPlan:
    approval_id: str
    action: str
    target: str
    owned_scratch_root: str
    output_root: str
    isolated_quota_root: str | None


def admit_fault_plan(
    scenario_raw: bytes,
    plan_raw: bytes,
    *,
    vm_endpoint_id: str,
    binary_sha256: str,
    now: str,
    opt_in: bool,
) -> FaultPlan:
    scenario = load_checkpoint_scenario(
        scenario_raw,
        vm_endpoint_id=vm_endpoint_id,
        binary_sha256=binary_sha256,
        now=now,
        opt_in=opt_in,
    )
    if len(plan_raw) > 4096:
        raise ValueError("fault plan too large")
    try:
        plan: Any = json.loads(plan_raw, object_pairs_hook=_unique_fields)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid fault plan") from error
    if not isinstance(plan, dict) or frozenset(plan) != {
        "approval_id",
        "action",
        "target",
        "owned_scratch_root",
        "output_root",
        "isolated_quota_root",
    }:
        raise ValueError("fault plan shape")
    if (
        plan["approval_id"] != scenario["approval_id"]
        or not isinstance(plan["action"], str)
        or plan["action"] not in _ACTIONS
    ):
        raise ValueError("unapproved fault action")
    if (
        plan["owned_scratch_root"] != scenario["owned_scratch_root"]
        or plan["output_root"] != scenario["output_root"]
    ):
        raise ValueError("fault roots differ from approval")
    if not isinstance(plan["target"], str) or plan["target"] not in (
        "sample.txt",
        "owned-child",
        "report.json",
    ):
        raise ValueError("fault target outside closed owned set")
    if (
        plan["action"] in ("mutate_owned_file", "remove_owned_file")
        and plan["target"] != "sample.txt"
    ):
        raise ValueError("wrong file fault target")
    if plan["action"] == "cancel_owned_child" and plan["target"] != "owned-child":
        raise ValueError("wrong process fault target")
    if plan["action"] == "output_collision" and plan["target"] != "report.json":
        raise ValueError("wrong output fault target")
    quota_root = plan["isolated_quota_root"]
    if quota_root is not None:
        if not isinstance(quota_root, str):
            raise ValueError("invalid isolated quota root")
        # No disk-filling action exists here. A later quota campaign needs a
        # separately approved isolated volume, outside these two roots.
        quota = Path(quota_root)
        if (
            not quota.is_absolute()
            or quota_root in ("/", "/tmp", "/home")
            or quota in (Path(scenario["owned_scratch_root"]), Path(scenario["output_root"]))
        ):
            raise ValueError("unsafe isolated quota root")
        # No quota operation is implemented. Do not let an apparently approved
        # path resolve through a symlink or overlap either live scenario root.
        if quota.exists():
            info = quota.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError("unsafe isolated quota root")
            resolved = quota.resolve(strict=True)
            roots = [
                Path(scenario["owned_scratch_root"]).resolve(strict=True),
                Path(scenario["output_root"]).resolve(strict=True),
            ]
            if any(
                root == resolved or root in resolved.parents or resolved in root.parents
                for root in roots
            ):
                raise ValueError("quota root overlaps approved roots")
    return FaultPlan(**plan)


def apply_owned_file_fault(plan: FaultPlan, ledger: OwnedLedger) -> None:
    if ledger.directory.parent != Path(plan.owned_scratch_root) or plan.target != "sample.txt":
        raise ValueError("fault ledger outside approved root")
    if plan.action == "mutate_owned_file":
        ledger.mutate_file(plan.target, b"changed only in owned sample\n")
    elif plan.action == "remove_owned_file":
        ledger.remove_file(plan.target)
    else:
        raise ValueError("fault action requires a different owned handle")


def apply_owned_child_fault(plan: FaultPlan, ledger: OwnedLedger) -> None:
    if (
        plan.action != "cancel_owned_child"
        or plan.target != "owned-child"
        or ledger.directory.parent != Path(plan.owned_scratch_root)
        or len(ledger.children) != 1
    ):
        raise ValueError("fault child outside approved owned set")
    ledger.cancel_child(ledger.children[0][1])


def apply_output_collision(plan: FaultPlan) -> tuple[Path, tuple[int, int]]:
    if plan.action != "output_collision" or plan.target != "report.json":
        raise ValueError("unapproved output collision")
    root = Path(plan.output_root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("unsafe approved output root")
    path = root / plan.target
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as opened:
        opened.write(b"owned output collision\n")
        opened.flush()
        os.fsync(opened.fileno())
        file_info = os.fstat(opened.fileno())
    return path, (file_info.st_dev, file_info.st_ino)


def remove_output_collision(path: Path, identity: tuple[int, int]) -> None:
    info = path.lstat()
    if (info.st_dev, info.st_ino) != identity or not stat.S_ISREG(info.st_mode):
        raise ValueError("owned output collision replaced")
    path.unlink()


def load_owner_fault_plan(
    scenario_path: Path,
    plan_path: Path,
    *,
    vm_endpoint_id: str,
    binary_sha256: str,
    now: str,
    opt_in: bool,
) -> FaultPlan:
    """Read both separate owner-controlled declarations before any action."""
    return admit_fault_plan(
        _owner_file(scenario_path),
        _owner_file(plan_path, 4096),
        vm_endpoint_id=vm_endpoint_id,
        binary_sha256=binary_sha256,
        now=now,
        opt_in=opt_in,
    )
