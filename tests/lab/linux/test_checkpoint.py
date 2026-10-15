"""Offline tests for a separately approved, owner-scoped checkpoint harness."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from argparse import Namespace
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from .approval import (
    Approval,
    admit,
    load_checkpoint_scenario,
    load_vm_inventory,
    loopback_only,
)
from .ground_truth import ConnectionExpectation, ProcessExpectation, file_expectation
from .owned_objects import OwnedLedger
from .report_oracle import verify_report
from .run_scenario import (
    _collector_failure,
    _owner_file,
    _pinned_binary,
    _run,
    admit_inputs,
    dispatch,
    main,
)


def test_missing_report_diagnostic_is_bounded_to_typed_status() -> None:
    result = CompletedProcess(
        args=[],
        returncode=3,
        stdout=b"",
        stderr=b'{"code":"InvalidInput","stage":"finalization"}\n',
    )
    assert _collector_failure(result) == (
        "collector did not publish a report: exit=3 code=InvalidInput stage=finalization"
    )
    for stderr in (
        b"secret material\n",
        b'{"code":"InvalidInput\\nsecret","stage":"finalization"}\n',
        b"",
    ):
        assert "secret" not in _collector_failure(
            CompletedProcess(args=[], returncode=3, stdout=b"", stderr=stderr)
        )


def test_approval_binds_vm_binary_and_short_validity_window() -> None:
    approval = Approval(
        case_id="case-1",
        operator_id="operator-1",
        endpoint_id="debian-vm-1",
        vm_id="debian-vm-1",
        binary_sha256="a" * 64,
        valid_from="2026-10-14T07:00:00Z",
        valid_until="2026-10-14T08:00:00Z",
        owned_root="/lab/owned",
        approval_ref="approval-1",
    )
    assert admit(approval, "debian-vm-1", "a" * 64, "2026-10-14T07:30:00Z", True)
    for vm, digest, now, opt_in in [
        ("other-vm", "a" * 64, "2026-10-14T07:30:00Z", True),
        ("debian-vm-1", "b" * 64, "2026-10-14T07:30:00Z", True),
        ("debian-vm-1", "a" * 64, "2026-10-14T08:01:00Z", True),
        ("debian-vm-1", "a" * 64, "2026-10-14T07:30:00Z", False),
    ]:
        with pytest.raises(ValueError):
            admit(approval, vm, digest, now, opt_in)


def test_checkpoint_scenario_exact_shape_vm_digest_roots_actions_and_expiry() -> None:
    value = json.loads(Path("fixtures/valid/collection/lab-scenario.json").read_text())
    raw = json.dumps(value).encode()
    endpoint = value["endpoint_id"]
    digest = value["collector_sha256"]
    now = "2020-01-01T00:30:00Z"
    assert (
        load_checkpoint_scenario(
            raw, vm_endpoint_id=endpoint, binary_sha256=digest, now=now, opt_in=True
        )
        == value
    )
    for change in (
        {"endpoint_id": "10000000-0000-4000-8000-000000000099"},
        {"collector_sha256": "f" * 64},
        {"owned_scratch_root": "/tmp"},
        {"output_root": value["owned_scratch_root"] + "/output"},
        {"allowed_actions": ["create_sample_files"]},
        {"valid_until": "2020-01-01T00:15:00Z"},
        {"unexpected": "field"},
    ):
        altered = value | change
        with pytest.raises(ValueError):
            load_checkpoint_scenario(
                json.dumps(altered).encode(),
                vm_endpoint_id=endpoint,
                binary_sha256=digest,
                now=now,
                opt_in=True,
            )
    with pytest.raises(ValueError):
        load_checkpoint_scenario(
            raw, vm_endpoint_id=endpoint, binary_sha256=digest, now=now, opt_in=False
        )
    duplicate = raw.replace(
        b'"scenario": "checkpoint"',
        b'"scenario": "checkpoint", "scenario": "checkpoint"',
    )
    with pytest.raises(ValueError):
        load_checkpoint_scenario(
            duplicate,
            vm_endpoint_id=endpoint,
            binary_sha256=digest,
            now=now,
            opt_in=True,
        )


def test_owner_inventory_binds_scenario_endpoint_and_guest_product_uuid() -> None:
    value = {
        "inventory_id": "10000000-0000-4000-8000-000000000014",
        "endpoint_id": "10000000-0000-4000-8000-000000000002",
        "vm_product_uuid": "10000000-0000-4000-8000-000000000099",
        "machine_id": "a" * 32,
        "vm_name": "jocky-v5-debian-13-7",
        "disk_image_path": "/home/lab/debian.qcow2",
        "disk_sha256_before_boot": "b" * 64,
        "kind": "isolated_vm",
        "distribution_id": "debian",
        "architecture": "x86_64",
    }
    raw = json.dumps(value).encode()
    assert (
        load_vm_inventory(
            raw,
            inventory_id=value["inventory_id"],
            endpoint_id=value["endpoint_id"],
            product_uuid=value["vm_product_uuid"],
            machine_id=value["machine_id"],
        )
        == value
    )
    for change in (
        {"endpoint_id": "10000000-0000-4000-8000-000000000098"},
        {"vm_product_uuid": "10000000-0000-4000-8000-000000000098"},
        {"machine_id": "c" * 32},
        {"distribution_id": "fedora"},
        {"unknown": "field"},
    ):
        with pytest.raises(ValueError):
            load_vm_inventory(
                json.dumps(value | change).encode(),
                inventory_id=value["inventory_id"],
                endpoint_id=value["endpoint_id"],
                product_uuid=value["vm_product_uuid"],
                machine_id=value["machine_id"],
            )
    duplicate = raw.replace(
        b'"kind": "isolated_vm"', b'"kind": "isolated_vm", "kind": "isolated_vm"'
    )
    with pytest.raises(ValueError):
        load_vm_inventory(
            duplicate,
            inventory_id=value["inventory_id"],
            endpoint_id=value["endpoint_id"],
            product_uuid=value["vm_product_uuid"],
            machine_id=value["machine_id"],
        )


def test_expectations_are_captured_from_owned_bytes_before_invocation() -> None:
    content = b"independent fact\n"
    expected = file_expectation("sample-1", content)
    assert expected.sha256 == hashlib.sha256(content).hexdigest()
    assert expected.size_bytes == len(content)


def test_only_literal_loopback_addresses_are_allowed() -> None:
    assert loopback_only("127.0.0.1")
    assert loopback_only("::1")
    assert not loopback_only("192.0.2.1")
    assert not loopback_only("0.0.0.0")
    with pytest.raises(ValueError):
        loopback_only("example.org")
    for address in ("::", "::ffff:192.0.2.1", "8.8.8.8"):
        assert not loopback_only(address)


def test_unsafe_root_owner_and_replacement_are_rejected_before_use(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir(mode=0o777)
    with pytest.raises(ValueError, match="unsafe owned root"):
        OwnedLedger.create(root)
    root.chmod(0o700)
    ledger = OwnedLedger.create(root)
    file = ledger.add_file("sample", b"known")
    file.unlink()
    file.symlink_to(root / "outside")
    with pytest.raises(ValueError, match="replaced"):
        ledger.cleanup()
    assert file.is_symlink()


def test_owned_file_creation_rejects_escape_and_duplicate(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    for name in ("", ".", "..", "../escape", "nested/file"):
        with pytest.raises(ValueError):
            ledger.add_file(name, b"x")
    ledger.add_file("one", b"first")
    with pytest.raises(FileExistsError):
        ledger.add_file("one", b"second")
    ledger.cleanup()


def test_owned_cleanup_checks_exact_inode_and_never_removes_untracked_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    own = ledger.add_file("sample", b"known")
    assert own.read_bytes() == b"known"
    untracked = ledger.directory / "other"
    untracked.write_bytes(b"preserve")
    with pytest.raises(ValueError):
        ledger.cleanup()
    assert own.exists() and untracked.exists()
    untracked.unlink()
    ledger.cleanup()
    assert not ledger.directory.exists()


def test_report_oracle_rejects_mismatched_independent_file_facts() -> None:
    from pathlib import Path

    raw = Path("fixtures/valid/collection/report.json").read_bytes()
    with pytest.raises(ValueError):
        verify_report(raw, [file_expectation("sample", b"known")])


def test_owned_process_and_loopback_socket_have_independent_live_facts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    try:
        process = ledger.add_process()
        connection = ledger.add_loopback_connection()
        assert process.pid > 0 and process.start_ticks.isdigit()
        assert connection.local_address == connection.remote_address == "127.0.0.1"
        assert connection.local_port > 0 and connection.remote_port > 0
        assert connection.socket_inode.isdigit()
        with pytest.raises(ValueError):
            ledger.add_loopback_connection("0.0.0.0")
    finally:
        ledger.cleanup()
    assert not ledger.directory.exists()


def test_scenario_cli_requires_every_approved_input_before_action(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as rejected:
        main([])
    assert rejected.value.code == 2


def test_runner_denies_bad_binary_before_creating_owned_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def forbidden(_root: Path) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(OwnedLedger, "create", forbidden)
    args = Namespace(binary=str(tmp_path / "missing"))
    with pytest.raises(FileNotFoundError):
        dispatch(args, now="2020-01-01T00:30:00Z")
    assert not called


def test_owner_input_rejects_symlink_and_group_writable_file(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.write_bytes(b"known")
    source.chmod(0o660)
    with pytest.raises(ValueError):
        _owner_file(source)
    source.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(source)
    with pytest.raises(ValueError):
        _owner_file(alias)
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    with pytest.raises(ValueError):
        _owner_file(pipe)


def test_independent_process_and_connection_oracles_reject_absent_facts() -> None:
    from controller.tests.contracts.collection_canonical_support import finalize

    raw = finalize(json.loads(Path("fixtures/valid/collection/report.json").read_bytes()))
    with pytest.raises(ValueError, match="process"):
        verify_report(raw, [], [ProcessExpectation(12345, "boot", "42")])
    with pytest.raises(ValueError, match="connection"):
        verify_report(raw, [], [], [ConnectionExpectation("127.0.0.1", 1, "127.0.0.1", 2, "3")])


def test_binary_execution_stays_on_hashed_inode_after_path_replacement(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "collector"
    replacement = tmp_path / "replacement"
    shutil.copyfile("/bin/true", binary)
    shutil.copyfile("/bin/false", replacement)
    binary.chmod(0o700)
    replacement.chmod(0o700)
    with _pinned_binary(binary) as (fd, digest):
        assert digest == hashlib.sha256(binary.read_bytes()).hexdigest()
        replacement.replace(binary)
        assert _run([str(binary)], fd).returncode == 0
    assert binary.exists()


def test_runner_cross_document_admission_and_output_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = json.loads(Path("fixtures/valid/collection/lab-scenario.json").read_bytes())
    inventory = {
        "inventory_id": scenario["inventory_id"],
        "endpoint_id": scenario["endpoint_id"],
        "vm_product_uuid": "10000000-0000-4000-8000-000000000099",
        "machine_id": "a" * 32,
        "vm_name": "jocky-v5-debian-13-7",
        "disk_image_path": "/home/lab/debian.qcow2",
        "disk_sha256_before_boot": "b" * 64,
        "kind": "isolated_vm",
        "distribution_id": "debian",
        "architecture": "x86_64",
    }
    scratch, output, config = (tmp_path / name for name in ("scratch", "output", "config"))
    for directory in (scratch, output, config):
        directory.mkdir(mode=0o700)
    scenario["owned_scratch_root"] = str(scratch)
    scenario["output_root"] = str(output)
    root_id = "10000000-0000-4000-8000-000000000090"
    root = {"root_id": root_id, "absolute_path": str(scratch), "purposes": ["files"]}
    names = ("endpoint-designation", "authorisation", "policy", "request")
    docs = {
        name: json.loads(Path(f"fixtures/valid/collection/{name}.json").read_bytes())
        for name in names
    }
    for name in ("authorisation", "policy"):
        docs[name]["scope"]["roots"] = [root]
        docs[name]["scope"]["capabilities"] = [
            "system",
            "processes",
            "network",
            "files",
        ]
        docs[name]["scope"]["source_groups"] = [
            "kernel_profile",
            "proc_processes",
            "proc_net",
        ]
    sources = [
        {"source_id": f"10000000-0000-4000-8000-{number:012d}", "kind": kind}
        for number, kind in (
            (8, "kernel_profile"),
            (9, "proc_processes"),
            (10, "proc_net"),
        )
    ]
    docs["policy"]["sources"] = sources
    docs["request"]["collectors"] = ["system", "processes", "connections", "files"]
    docs["request"]["capabilities"] = ["system", "processes", "network", "files"]
    docs["request"]["source_ids"] = [source["source_id"] for source in sources]
    docs["request"]["paths"] = [{"root_id": root_id, "relative_path": "existing.txt"}]
    files = {name.replace("-", "_"): config / f"{name}.json" for name in names}
    files.update(
        {
            "scenario": config / "scenario.json",
            "inventory": config / "inventory.json",
            "host_preflight": config / "host-preflight.json",
        }
    )
    values = {
        **{name.replace("-", "_"): value for name, value in docs.items()},
        "scenario": scenario,
        "inventory": inventory,
        "host_preflight": {
            **{
                key: inventory[key]
                for key in (
                    "inventory_id",
                    "vm_name",
                    "vm_product_uuid",
                    "machine_id",
                    "disk_sha256_before_boot",
                )
            },
            "verified_at": "2020-01-01T00:29:00Z",
        },
    }
    for name, value in values.items():
        files[name].write_text(json.dumps(value))
        files[name].chmod(0o600)
    binary = config / "collector"
    binary.write_bytes(b"\x7fELFsynthetic")
    binary.chmod(0o700)
    report = output / "report.json"
    args = Namespace(
        binary=str(binary),
        scenario=str(files["scenario"]),
        inventory=str(files["inventory"]),
        host_preflight=str(files["host_preflight"]),
        vm_endpoint_id=scenario["endpoint_id"],
        inventory_id=scenario["inventory_id"],
        vm_product_uuid=inventory["vm_product_uuid"],
        allow_live_lab=True,
        report=str(report),
        **{
            name: str(path)
            for name, path in files.items()
            if name not in ("scenario", "inventory", "host_preflight")
        },
    )
    original_read_text = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **kw: (
            inventory["vm_product_uuid"]
            if str(path) == "/sys/class/dmi/id/product_uuid"
            else inventory["machine_id"]
            if str(path) == "/etc/machine-id"
            else original_read_text(path, *a, **kw)
        ),
    )
    admitted, resolved = admit_inputs(args, "2020-01-01T00:30:00Z", scenario["collector_sha256"])
    assert admitted["approval_id"] == scenario["approval_id"]
    assert resolved["sample_root_id"] == root_id
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **kw: (
            (_ for _ in ()).throw(PermissionError("root-only DMI"))
            if str(path) == "/sys/class/dmi/id/product_uuid"
            else inventory["machine_id"]
            if str(path) == "/etc/machine-id"
            else original_read_text(path, *a, **kw)
        ),
    )
    assert (
        admit_inputs(args, "2020-01-01T00:30:00Z", scenario["collector_sha256"])[0]["approval_id"]
        == scenario["approval_id"]
    )
    values["host_preflight"]["machine_id"] = "c" * 32
    files["host_preflight"].write_text(json.dumps(values["host_preflight"]))
    with pytest.raises(ValueError, match="identity mismatch"):
        admit_inputs(args, "2020-01-01T00:30:00Z", scenario["collector_sha256"])
    values["host_preflight"]["machine_id"] = inventory["machine_id"]
    files["host_preflight"].write_text(json.dumps(values["host_preflight"]))
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **kw: (
            inventory["vm_product_uuid"]
            if str(path) == "/sys/class/dmi/id/product_uuid"
            else inventory["machine_id"]
            if str(path) == "/etc/machine-id"
            else original_read_text(path, *a, **kw)
        ),
    )
    report.write_bytes(b"pre-existing")
    with pytest.raises(ValueError, match="fresh"):
        admit_inputs(args, "2020-01-01T00:30:00Z", scenario["collector_sha256"])
