"""Explicit, local-guest-only Version 5 checkpoint dispatcher.

This module is inert on import. It never provisions a VM or expands an authority.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from controller.tests.contracts.collection_decode_support import strict_decode

from .approval import (
    load_checkpoint_scenario,
    load_lab_small_scenario,
    load_vm_inventory,
)
from .ground_truth import file_expectation
from .owned_objects import OwnedLedger
from .report_oracle import verify_report
from .vm_attestation import load_host_preflight


def _owner_file(path: Path, maximum: int = 65536) -> bytes:
    with _pinned_file(path, maximum) as fd:
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        if len(chunks) > maximum:
            raise ValueError("oversize owner-controlled input")
        return bytes(chunks)


@contextmanager
def _pinned_file(path: Path, maximum: int) -> Iterator[int]:
    if not path.is_absolute():
        raise ValueError("owner-controlled path must be absolute")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("symlinked owner-controlled input") from error
        raise
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or info.st_size > maximum
        ):
            raise ValueError("unsafe owner-controlled input")
        yield fd
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
        ):
            raise ValueError("owner-controlled input changed")
    finally:
        os.close(fd)


@contextmanager
def _pinned_binary(path: Path) -> Iterator[tuple[int, str]]:
    with _pinned_file(path, 128 * 1024 * 1024) as fd:
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        if os.read(fd, 4) != b"\x7fELF":
            raise ValueError("collector is not an ELF binary")
        yield fd, digest.hexdigest()


def _owned_dir(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("unsafe owner-controlled directory")


def _identity(value: dict[str, Any], key: str, expected: str) -> None:
    if value.get(key) != expected:
        raise ValueError(f"{key} does not match scenario")


def admit_inputs(
    args: argparse.Namespace, now: str, binary_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Complete all static checks before making a scenario object."""
    machine_id = Path("/etc/machine-id").read_text().strip().lower()
    if not machine_id:
        raise ValueError("missing guest machine ID")
    try:
        guest_uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower()
    except PermissionError:
        guest_uuid = None
    if guest_uuid is not None and guest_uuid != args.vm_product_uuid.lower():
        raise ValueError("wrong native VM product UUID")
    loader = (
        load_lab_small_scenario
        if getattr(args, "profile", "checkpoint") == "lab-small-v1"
        else load_checkpoint_scenario
    )
    scenario = loader(
        _owner_file(Path(args.scenario)),
        vm_endpoint_id=args.vm_endpoint_id,
        binary_sha256=binary_sha256,
        now=now,
        opt_in=args.allow_live_lab,
    )
    if args.inventory_id != scenario["inventory_id"]:
        raise ValueError("wrong inventory")
    inventory = load_vm_inventory(
        _owner_file(Path(args.inventory)),
        inventory_id=scenario["inventory_id"],
        endpoint_id=scenario["endpoint_id"],
        product_uuid=args.vm_product_uuid,
        machine_id=machine_id,
    )
    load_host_preflight(_owner_file(Path(args.host_preflight), 4096), inventory, now=now)
    documents = {
        name: strict_decode(name.replace("_", "-"), _owner_file(Path(getattr(args, name))))
        for name in ("endpoint_designation", "authorisation", "policy", "request")
    }
    designation = documents["endpoint_designation"]
    authority = documents["authorisation"]
    policy = documents["policy"]
    request = documents["request"]
    for value, key, expected in (
        (designation, "designation_id", scenario["designation_id"]),
        (designation, "endpoint_id", scenario["endpoint_id"]),
        (authority, "authorisation_id", scenario["authorisation_id"]),
        (authority, "case_id", scenario["case_id"]),
        (authority, "operator_id", scenario["operator_id"]),
        (authority, "endpoint_id", scenario["endpoint_id"]),
        (policy, "endpoint_id", scenario["endpoint_id"]),
        (request, "case_id", scenario["case_id"]),
        (request, "operator_id", scenario["operator_id"]),
        (request, "endpoint_id", scenario["endpoint_id"]),
        (request, "designation_id", scenario["designation_id"]),
        (request, "authorisation_id", scenario["authorisation_id"]),
        (request, "policy_id", policy["policy_id"]),
    ):
        _identity(value, key, expected)
    for value in (designation, authority, policy):
        if not value["valid_from"] <= now < value["valid_until"]:
            raise ValueError("expired collection document")
    if not request["event_window"]["start"] <= now < request["event_window"]["end"]:
        raise ValueError("expired request window")
    required_collectors = {"system", "processes", "connections", "files"}
    if getattr(args, "profile", "checkpoint") == "lab-small-v1":
        required_collectors |= {"events", "indicators"}
        if request["indicator_set_id"] is None:
            raise ValueError("LAB-SMALL indicator set missing")
    if not required_collectors.issubset(request["collectors"]):
        raise ValueError("checkpoint collectors missing")
    scratch = Path(scenario["owned_scratch_root"])
    output = Path(scenario["output_root"])
    _owned_dir(scratch)
    _owned_dir(output)
    scratch_real = scratch.resolve(strict=True)
    output_real = output.resolve(strict=True)
    if (
        scratch_real == output_real
        or scratch_real in output_real.parents
        or output_real in scratch_real.parents
    ):
        raise ValueError("scenario roots overlap physically")
    for name in (
        "scenario",
        "inventory",
        "host_preflight",
        "endpoint_designation",
        "authorisation",
        "policy",
        "request",
        "binary",
    ):
        admitted = Path(getattr(args, name)).resolve(strict=True)
        if (
            admitted == scratch_real
            or admitted == output_real
            or scratch_real in admitted.parents
            or output_real in admitted.parents
        ):
            raise ValueError("approved roots contain input or binary")
    if Path(args.report).parent != output or Path(args.report).exists():
        raise ValueError("output must be fresh inside approved output root")
    roots = [root for root in authority["scope"]["roots"] if root["absolute_path"] == str(scratch)]
    if len(roots) != 1 or roots != [
        root for root in policy["scope"]["roots"] if root["absolute_path"] == str(scratch)
    ]:
        raise ValueError("owned scratch root missing from trusted scope")
    if getattr(args, "profile", "checkpoint") == "lab-small-v1" and request["paths"] != [
        {"root_id": roots[0]["root_id"], "relative_path": "lab-small-template-only"}
    ]:
        raise ValueError("LAB-SMALL request template path differs")
    return scenario, {**documents, "sample_root_id": roots[0]["root_id"]}


def _run(command: list[str], binary_fd: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [f"/proc/self/fd/{binary_fd}", *command[1:]],
        input=b"",
        capture_output=True,
        timeout=90,
        check=False,
        pass_fds=(binary_fd,),
    )


def _collector_failure(result: subprocess.CompletedProcess[bytes]) -> str:
    try:
        status = json.loads(result.stderr.splitlines()[-1])
        code = status["code"]
        stage = status["stage"]
        if not all(
            isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", value)
            for value in (code, stage)
        ):
            raise ValueError("invalid status fields")
    except (
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
    ):
        code, stage = "invalid-status", "unknown"
    return f"collector did not publish a report: exit={result.returncode} code={code} stage={stage}"


def dispatch(args: argparse.Namespace, *, now: str | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    with _pinned_binary(Path(args.binary)) as (binary_fd, digest):
        scenario, values = admit_inputs(args, now, digest)
        if getattr(args, "profile", "checkpoint") == "lab-small-v1":
            from .lab_campaign import run_campaign

            return run_campaign(args, scenario, values, binary_fd, digest)
        return _dispatch_admitted(args, scenario, values, binary_fd)


def _dispatch_admitted(
    args: argparse.Namespace,
    scenario: dict[str, Any],
    values: dict[str, Any],
    binary_fd: int,
) -> dict[str, Any]:
    ledger = OwnedLedger.create(Path(scenario["owned_scratch_root"]))
    try:
        sample = b"JOCKY Version 5 checkpoint sample\n"
        sample_path = ledger.add_file("sample.txt", sample)
        expected_file = file_expectation(
            f"{ledger.directory.name}/{sample_path.name}",
            sample,
            values["sample_root_id"],
        )
        expected_process = ledger.add_process()
        expected_connection = ledger.add_loopback_connection()
        request = dict(values["request"])
        request["paths"] = [
            *request["paths"],
            {"root_id": values["sample_root_id"], "relative_path": expected_file.label},
        ]
        request_raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        strict_decode("request", request_raw)
        request_path = ledger.add_file("request.json", request_raw)
        common = [
            "--designation",
            args.endpoint_designation,
            "--authorisation",
            args.authorisation,
            "--policy",
            args.policy,
            "--request",
            str(request_path),
        ]
        validated = _run([args.binary, "validate-inputs", *common], binary_fd)
        if validated.returncode != 0:
            raise ValueError("collector rejected checkpoint inputs")
        collected = _run(
            [
                args.binary,
                "collect",
                "--allow-live-lab",
                *common,
                "--output",
                args.report,
            ],
            binary_fd,
        )
        report_path = Path(args.report)
        if not report_path.is_file():
            raise ValueError(_collector_failure(collected))
        raw = _owner_file(report_path, 10_485_760)
        report = verify_report(raw, [expected_file], [expected_process], [expected_connection])
        if (
            report["report_kind"] != "live_lab"
            or any(
                report["context"].get(key) != scenario[key]
                for key in (
                    "case_id",
                    "operator_id",
                    "endpoint_id",
                    "designation_id",
                    "authorisation_id",
                )
            )
            or report["context"]["collection_id"] != request["collection_id"]
        ):
            raise ValueError("published report has wrong scenario context")
        if collected.returncode not in (0, 2) or report["summary"]["status"] not in (
            "complete",
            "partial",
        ):
            raise ValueError("checkpoint did not publish a successful or partial report")
        verified = _run([args.binary, "verify-report", args.report], binary_fd)
        if verified.returncode != 0:
            raise ValueError("collector did not verify its published report")
        if _owner_file(report_path, 10_485_760) != raw:
            raise ValueError("published report changed during verification")
        return {
            "scenario_approval_id": scenario["approval_id"],
            "report": args.report,
            "report_sha256": hashlib.sha256(raw).hexdigest(),
            "collector_exit": collected.returncode,
            "summary": report["summary"],
            "independent_file": expected_file.__dict__,
            "independent_process": expected_process.__dict__,
            "independent_connection": expected_connection.__dict__,
        }
    finally:
        ledger.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-live-lab", action="store_true", required=True)
    parser.add_argument("--profile", choices=("checkpoint", "lab-small-v1"), default="checkpoint")
    for name in (
        "scenario",
        "inventory",
        "host-preflight",
        "binary",
        "vm-endpoint-id",
        "vm-product-uuid",
        "inventory-id",
        "endpoint-designation",
        "authorisation",
        "policy",
        "request",
        "report",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = dispatch(args)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f"checkpoint rejected: {reason}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get("passed") is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
