"""Offline-only fault approval and exact owned-file action tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from .faults import (
    FaultPlan,
    admit_fault_plan,
    apply_output_collision,
    apply_owned_child_fault,
    apply_owned_file_fault,
    remove_output_collision,
)
from .owned_objects import OwnedLedger


def scenario_and_plan(
    tmp_path: Path,
) -> tuple[bytes, dict[str, object], dict[str, object]]:
    scenario = json.loads(Path("fixtures/valid/collection/lab-scenario.json").read_bytes())
    scenario["owned_scratch_root"] = str(tmp_path / "owned")
    scenario["output_root"] = str(tmp_path / "output")
    plan = {
        "approval_id": scenario["approval_id"],
        "action": "mutate_owned_file",
        "target": "sample.txt",
        "owned_scratch_root": scenario["owned_scratch_root"],
        "output_root": scenario["output_root"],
        "isolated_quota_root": None,
    }
    return json.dumps(scenario).encode(), scenario, plan


def admit(raw: bytes, scenario: dict[str, object], plan: dict[str, object]) -> FaultPlan:
    return admit_fault_plan(
        raw,
        json.dumps(plan).encode(),
        vm_endpoint_id=str(scenario["endpoint_id"]),
        binary_sha256=str(scenario["collector_sha256"]),
        now="2020-01-01T00:30:00Z",
        opt_in=True,
    )


def test_owned_mutation_and_disappearance_are_exact(tmp_path: Path) -> None:
    raw, scenario, plan = scenario_and_plan(tmp_path)
    root = Path(str(scenario["owned_scratch_root"]))
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    sample = ledger.add_file("sample.txt", b"original")
    sibling = ledger.add_file("unrelated.txt", b"preserve")
    apply_owned_file_fault(admit(raw, scenario, plan), ledger)
    assert sample.read_bytes() == b"changed only in owned sample\n"
    assert sibling.read_bytes() == b"preserve"
    plan["action"] = "remove_owned_file"
    apply_owned_file_fault(admit(raw, scenario, plan), ledger)
    assert not sample.exists() and sibling.read_bytes() == b"preserve"
    ledger.cleanup()


def test_wrong_approval_target_root_and_expiry_fail_before_action(
    tmp_path: Path,
) -> None:
    raw, scenario, plan = scenario_and_plan(tmp_path)
    changes: list[dict[str, object]] = [
        {"approval_id": "10000000-0000-4000-8000-000000000099"},
        {"target": "../outside"},
        {"action": "fill_root_volume"},
        {"owned_scratch_root": "/tmp"},
        {"isolated_quota_root": "/"},
        {"action": []},
        {"target": []},
        {"isolated_quota_root": []},
    ]
    for change in changes:
        with pytest.raises(ValueError):
            admit(raw, scenario, plan | change)
    with pytest.raises(ValueError):
        admit_fault_plan(
            raw,
            json.dumps(plan).encode(),
            vm_endpoint_id=str(scenario["endpoint_id"]),
            binary_sha256=str(scenario["collector_sha256"]),
            now="2020-01-01T01:00:00Z",
            opt_in=True,
        )


def test_only_exact_owned_child_can_be_cancelled(tmp_path: Path) -> None:
    raw, scenario, plan = scenario_and_plan(tmp_path)
    root = Path(str(scenario["owned_scratch_root"]))
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    expected = ledger.add_process()
    plan["action"] = "cancel_owned_child"
    plan["target"] = "owned-child"
    apply_owned_child_fault(admit(raw, scenario, plan), ledger)
    assert ledger.children[0][0].poll() is not None
    with pytest.raises(ValueError, match="already exited"):
        apply_owned_child_fault(admit(raw, scenario, plan), ledger)
    assert expected == ledger.children[0][1]
    ledger.cleanup()


def test_output_collision_is_exclusive_and_identity_checked(tmp_path: Path) -> None:
    raw, scenario, plan = scenario_and_plan(tmp_path)
    root = Path(str(scenario["output_root"]))
    root.mkdir(mode=0o700)
    plan["action"] = "output_collision"
    plan["target"] = "report.json"
    approved = admit(raw, scenario, plan)
    path, identity = apply_output_collision(approved)
    assert path.read_bytes() == b"owned output collision\n"
    with pytest.raises(FileExistsError):
        apply_output_collision(approved)
    assert path.read_bytes() == b"owned output collision\n"
    with pytest.raises(ValueError, match="replaced"):
        remove_output_collision(path, (identity[0], identity[1] + 1))
    remove_output_collision(path, identity)
    assert not path.exists()


def test_fault_plan_rejects_duplicate_fields_missing_opt_in_and_quota_alias(
    tmp_path: Path,
) -> None:
    raw, scenario, plan = scenario_and_plan(tmp_path)
    with pytest.raises(ValueError, match="duplicate"):
        admit_fault_plan(
            raw,
            json.dumps(plan).encode()[:-1] + b',"action":"remove_owned_file"}',
            vm_endpoint_id=str(scenario["endpoint_id"]),
            binary_sha256=str(scenario["collector_sha256"]),
            now="2020-01-01T00:30:00Z",
            opt_in=True,
        )
    with pytest.raises(ValueError):
        admit_fault_plan(
            raw,
            json.dumps(plan).encode(),
            vm_endpoint_id=str(scenario["endpoint_id"]),
            binary_sha256=str(scenario["collector_sha256"]),
            now="2020-01-01T00:30:00Z",
            opt_in=False,
        )
    for key in ("owned_scratch_root", "output_root"):
        Path(str(scenario[key])).mkdir(mode=0o700)
    alias = tmp_path / "quota-alias"
    alias.symlink_to(Path(str(scenario["owned_scratch_root"])), target_is_directory=True)
    with pytest.raises(ValueError, match="quota"):
        admit(raw, scenario, plan | {"isolated_quota_root": str(alias)})
