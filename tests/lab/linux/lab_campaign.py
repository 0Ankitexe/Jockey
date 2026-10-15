"""Explicitly approved Debian LAB-SMALL campaign; inert until dispatched."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from controller.tests.contracts.collection_decode_support import strict_decode

from .facilities import emit_approved_journal_markers, prepare_owned_samples
from .indicators import build_indicator_plan, evaluate_indicator_report
from .lab_small import prepare_dataset
from .measurements import Sample, SampleRecorder, capture_invocation, summarize_recorded
from .owned_objects import OwnedLedger
from .report_oracle import normalized_input_sha256, verify_report


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _owner_hostname() -> str:
    # A provisioning fact, not DNS or a collector-derived value.
    name = Path("/proc/sys/kernel/hostname").read_text().strip().lower()
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.invalid", name):
        raise ValueError("owner-provisioned .invalid FQDN is missing")
    return name


def _emit_journal(marker: str) -> None:
    done = subprocess.run(
        ["/usr/bin/systemd-cat", "-t", "jocky-lab-small"],
        input=(marker + "\n").encode("ascii"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )
    if done.returncode != 0:
        raise ValueError("approved journal marker emission failed")


def _publish_json(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as opened:
        opened.write(data)
        opened.flush()
        os.fsync(opened.fileno())


def _failed_before_collection(
    scenario: dict[str, Any],
    index: int,
    reason: str,
    started_at: str,
    elapsed_ms: int,
    binary_sha256: str,
) -> Sample:
    """Preserve a rejected attempt without inventing a collector observation."""
    return Sample(
        run_id=f"{scenario['approval_id']}-{index:02}",
        classification="cold" if index == 0 else "warm",
        elapsed_ms=elapsed_ms,
        parent_peak_rss_bytes=0,
        worker_peaks_bytes=(),
        workers_sequential=False,
        output_bytes=0,
        accepted_records=0,
        source_bytes=0,
        exit_code=None,
        seeded_facts_ok=False,
        report_status=None,
        failure=reason,
        started_at=started_at,
        finished_at=_utc_now(),
        inventory_id=scenario["inventory_id"],
        binary_sha256=binary_sha256,
    )


def run_campaign(
    args: argparse.Namespace,
    scenario: dict[str, Any],
    values: dict[str, Any],
    binary_fd: int,
    binary_sha256: str,
) -> dict[str, Any]:
    """Run one cold then ten warm samples without editing approved policy/limits."""
    if scenario["scenario"] != "lab-small" or args.profile != "lab-small-v1":
        raise ValueError("LAB-SMALL approval is required")
    if not {
        "system",
        "processes",
        "connections",
        "files",
        "events",
        "indicators",
    }.issubset(values["request"]["collectors"]):
        raise ValueError("LAB-SMALL collectors missing")
    hostname = _owner_hostname()
    cold_reference = scenario["cold_preparation_reference"]
    if not isinstance(cold_reference, str) or not cold_reference:
        raise ValueError("owner cold preparation reference is missing")
    guest_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", guest_boot_id):
        raise ValueError("guest boot identity is missing")
    scratch = Path(scenario["owned_scratch_root"])
    output = Path(scenario["output_root"])
    ledger = OwnedLedger.create(scratch)
    try:
        dataset = prepare_dataset(ledger, root_id=values["sample_root_id"], owner_fqdn=hostname)
        plan = build_indicator_plan(
            dataset.labels,
            case_id=scenario["case_id"],
            set_id=values["request"]["indicator_set_id"],
        )
        indicator_file = ledger.add_file("lab-small-indicators.json", plan.document)
        run_token = uuid4().hex[:16]
        facilities = prepare_owned_samples(
            ledger, scenario["allowed_actions"], run_token, datetime.now(UTC)
        )
        emit_approved_journal_markers(facilities, scenario["allowed_actions"], _emit_journal)
        rows_path = output / "samples.jsonl"
        with SampleRecorder(rows_path) as recorder:
            for index in range(11):
                # The preflight and every owner document must remain valid for
                # each new dispatch. No expiry or scope extension is attempted.
                from .run_scenario import _owner_file, _run, admit_inputs

                report_path = output / f"lab-small-{index:02}.json"
                current_args = argparse.Namespace(**vars(args))
                current_args.report = str(report_path)
                started_at = _utc_now()
                begin = time.monotonic_ns()
                try:
                    admit_inputs(current_args, started_at, binary_sha256)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    recorder.append(
                        _failed_before_collection(
                            scenario,
                            index,
                            f"admission: {type(error).__name__}",
                            started_at,
                            (time.monotonic_ns() - begin + 999_999) // 1_000_000,
                            binary_sha256,
                        )
                    )
                    break
                try:
                    request = dict(values["request"])
                    request["collection_id"] = str(uuid4())
                    request["paths"] = [
                        {"root_id": item.root_id, "relative_path": item.label}
                        for item in dataset.files
                    ]
                    request_raw = json.dumps(
                        request, sort_keys=True, separators=(",", ":")
                    ).encode()
                    strict_decode("request", request_raw)
                    request_path = ledger.add_file(f"request-{index:02}.json", request_raw)
                    input_digests = {
                        role: normalized_input_sha256(role, _owner_file(Path(getattr(args, field))))
                        for role, field in (
                            ("designation", "endpoint_designation"),
                            ("authorisation", "authorisation"),
                            ("policy", "policy"),
                        )
                    }
                    input_digests["request"] = normalized_input_sha256("request", request_raw)
                    input_digests["indicators"] = normalized_input_sha256(
                        "indicators", plan.document
                    )
                    common = [
                        "--designation",
                        args.endpoint_designation,
                        "--authorisation",
                        args.authorisation,
                        "--policy",
                        args.policy,
                        "--request",
                        str(request_path),
                        "--indicators",
                        str(indicator_file),
                    ]
                except (OSError, ValueError, KeyError, TypeError) as error:
                    recorder.append(
                        _failed_before_collection(
                            scenario,
                            index,
                            f"request preparation: {type(error).__name__}",
                            started_at,
                            (time.monotonic_ns() - begin + 999_999) // 1_000_000,
                            binary_sha256,
                        )
                    )
                    break
                try:
                    validation = _run([args.binary, "validate-inputs", *common], binary_fd)
                except (OSError, subprocess.TimeoutExpired) as error:
                    recorder.append(
                        _failed_before_collection(
                            scenario,
                            index,
                            f"input validation: {type(error).__name__}",
                            started_at,
                            (time.monotonic_ns() - begin + 999_999) // 1_000_000,
                            binary_sha256,
                        )
                    )
                    break
                if validation.returncode != 0:
                    recorder.append(
                        _failed_before_collection(
                            scenario,
                            index,
                            "input validation failed",
                            started_at,
                            (time.monotonic_ns() - begin + 999_999) // 1_000_000,
                            binary_sha256,
                        )
                    )
                    break
                try:
                    invocation = capture_invocation(
                        [
                            f"/proc/self/fd/{binary_fd}",
                            "collect",
                            "--allow-live-lab",
                            *common,
                            "--output",
                            str(report_path),
                        ],
                        output,
                        f"collector-{index:02}",
                        pass_fds=(binary_fd,),
                        timeout_seconds=65,
                    )
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    recorder.append(
                        _failed_before_collection(
                            scenario,
                            index,
                            f"invocation: {type(error).__name__}",
                            started_at,
                            (time.monotonic_ns() - begin + 999_999) // 1_000_000,
                            binary_sha256,
                        )
                    )
                    break
                elapsed_ms = (time.monotonic_ns() - begin + 999_999) // 1_000_000
                finished_at = _utc_now()
                raw = b""
                report: dict[str, Any] | None = None
                failure: str | None = None
                confusion: dict[str, int] | None = None
                try:
                    raw = _owner_file(report_path, 10_485_760)
                    report = verify_report(
                        raw,
                        list(dataset.files),
                        dataset.processes,
                        dataset.connections,
                        expected_context={
                            "mode": "local_lab",
                            **{
                                key: scenario[key]
                                for key in (
                                    "case_id",
                                    "operator_id",
                                    "endpoint_id",
                                    "designation_id",
                                    "authorisation_id",
                                )
                            },
                            "policy_id": values["policy"]["policy_id"],
                            "collection_id": request["collection_id"],
                        },
                        expected_input_digests=input_digests,
                    )
                    confusion = evaluate_indicator_report(
                        plan, report, eligible_kinds=set(dataset.labels.by_kind)
                    )
                    if confusion != {
                        "tp": 51,
                        "fp": 0,
                        "tn": 949,
                        "fn": 0,
                        "unevaluated": 0,
                    }:
                        raise ValueError("frozen indicator labels did not match")
                    messages = [
                        row["payload"]["message"]
                        for row in report["records"]
                        if row["record_type"] == "log"
                    ]
                    if any(
                        sum(marker in message for message in messages) != 1
                        for marker in facilities.journal_markers
                    ):
                        raise ValueError("controlled journal markers missing or repeated")
                    verified = _run([args.binary, "verify-report", str(report_path)], binary_fd)
                    if verified.returncode != 0 or _owner_file(report_path, 10_485_760) != raw:
                        raise ValueError("published report changed or failed verification")
                except (OSError, ValueError, KeyError, TypeError) as error:
                    failure = (
                        type(error).__name__ if not isinstance(error, ValueError) else str(error)
                    )
                sample = Sample(
                    run_id=f"{scenario['approval_id']}-{index:02}",
                    classification="cold" if index == 0 else "warm",
                    elapsed_ms=elapsed_ms,
                    parent_peak_rss_bytes=invocation.parent.peak_rss_bytes,
                    worker_peaks_bytes=tuple(row.peak_rss_bytes for row in invocation.workers),
                    workers_sequential=invocation.workers_sequential,
                    output_bytes=len(raw),
                    accepted_records=report["summary"]["accepted_records"] if report else 0,
                    source_bytes=report["summary"]["source_bytes"] if report else 0,
                    exit_code=invocation.exit_code,
                    seeded_facts_ok=report is not None and failure is None,
                    report_status=report["summary"]["status"] if report else None,
                    failure=failure or ("timeout" if invocation.timed_out else None),
                    collection_id=request["collection_id"],
                    started_at=started_at,
                    finished_at=finished_at,
                    report_sha256=hashlib.sha256(raw).hexdigest() if raw else None,
                    report_path=str(report_path) if raw else None,
                    worker_trace=invocation.workers,
                    parent_wait4=invocation.parent,
                    oracle=confusion,
                    input_sha256=input_digests,
                    omitted_known=report["summary"]["omitted_known"] if report else 0,
                    omitted_unknown=report["summary"]["omitted_unknown"] if report else False,
                    errors=report["summary"]["errors"] if report else 0,
                    stop_reason=report["summary"]["stop_reason"] if report else None,
                    worker_cleanup=report["summary"]["worker_cleanup"] if report else None,
                    inventory_id=scenario["inventory_id"],
                    binary_sha256=binary_sha256,
                    expected_owned_workers=len(request["collectors"]) + 1,
                )
                recorder.append(sample)
            if len(recorder.samples) == 11:
                summary = summarize_recorded(recorder.samples)
            else:
                summary = {
                    "profile": "lab-small-v1",
                    "raw_samples": len(recorder.samples),
                    "passed": False,
                    "failures": [
                        {
                            "run_id": item.run_id,
                            "reason": item.failure or "campaign incomplete",
                        }
                        for item in recorder.samples
                        if item.failure is not None
                    ],
                    "reason": "campaign stopped before eleven samples",
                }
        summary.update(
            {
                "scenario_approval_id": scenario["approval_id"],
                "binary_sha256": binary_sha256,
                "indicator_set_sha256": hashlib.sha256(plan.document).hexdigest(),
                "raw_samples_path": str(rows_path),
                "owner_fqdn": hostname,
                "cold_preparation_reference": cold_reference,
                "guest_boot_id": guest_boot_id,
            }
        )
        _publish_json(output / "summary.json", summary)
        return summary
    finally:
        ledger.cleanup()
