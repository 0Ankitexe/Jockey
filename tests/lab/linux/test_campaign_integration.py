"""Offline full-loop LAB-SMALL exercise with inert collection seams."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch

from . import lab_campaign, run_scenario
from .measurements import Invocation, ProcessPeak


@pytest.mark.parametrize("markers_present", [True, False])
def test_eleven_attempts_create_distinct_requests_and_raw_rows(
    tmp_path: Path, monkeypatch: MonkeyPatch, markers_present: bool
) -> None:
    scratch, output = tmp_path / "scratch", tmp_path / "output"
    scratch.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    scenario: dict[str, Any] = {
        "scenario": "lab-small",
        "approval_id": "10000000-0000-4000-8000-000000000001",
        "inventory_id": "10000000-0000-4000-8000-000000000002",
        "case_id": "10000000-0000-4000-8000-000000000003",
        "operator_id": "10000000-0000-4000-8000-000000000004",
        "endpoint_id": "10000000-0000-4000-8000-000000000005",
        "designation_id": "10000000-0000-4000-8000-000000000006",
        "authorisation_id": "10000000-0000-4000-8000-000000000007",
        "cold_preparation_reference": "approved-shutoff-snapshot-and-cold-boot",
        "owned_scratch_root": str(scratch),
        "output_root": str(output),
        "allowed_actions": [
            "create_benign_processes",
            "bind_loopback_tcp",
            "create_sample_files",
            "cleanup_owned_objects",
            "emit_benign_log_markers",
        ],
    }
    request: dict[str, Any] = json.loads(
        Path("fixtures/valid/collection/request.json").read_bytes()
    )
    request["collectors"] = [
        "system",
        "processes",
        "connections",
        "files",
        "events",
        "indicators",
    ]
    request["capabilities"] = [
        "system",
        "processes",
        "network",
        "files",
        "events",
        "indicators",
    ]
    request["indicator_set_id"] = "10000000-0000-4000-8000-000000000008"
    values: dict[str, Any] = {
        "request": request,
        "policy": {"policy_id": request["policy_id"]},
        "sample_root_id": "10000000-0000-4000-8000-000000000009",
    }
    args = argparse.Namespace(
        profile="lab-small-v1",
        binary="/fake/binary",
        endpoint_designation="/fake/designation",
        authorisation="/fake/authorisation",
        policy="/fake/policy",
        request="/fake/request",
        report=str(output / "initial.json"),
    )
    monkeypatch.setattr(lab_campaign, "_owner_hostname", lambda: "owned.invalid")
    markers: list[str] = []
    monkeypatch.setattr(lab_campaign, "_emit_journal", markers.append)
    monkeypatch.setattr(run_scenario, "admit_inputs", lambda *_: (scenario, values))
    monkeypatch.setattr(run_scenario, "_owner_file", lambda *_: b"bounded")
    monkeypatch.setattr(lab_campaign, "normalized_input_sha256", lambda *_: "a" * 64)
    monkeypatch.setattr(
        run_scenario, "_run", lambda *_: subprocess.CompletedProcess([], 0, b"", b"")
    )
    workers = tuple(ProcessPeak(index + 10, str(index + 1), 1024) for index in range(7))
    monkeypatch.setattr(
        lab_campaign,
        "capture_invocation",
        lambda *_args, **_kwargs: Invocation(
            10,
            0,
            ProcessPeak(1, "1", 1024),
            workers,
            True,
            False,
            output / "stdout",
            output / "stderr",
        ),
    )
    monkeypatch.setattr(
        lab_campaign,
        "verify_report",
        lambda *_args, **_kwargs: {
            "records": [
                {"record_type": "log", "payload": {"message": marker}}
                for marker in (markers if markers_present else [])
            ],
            "summary": {
                "accepted_records": 0,
                "source_bytes": 0,
                "status": "complete",
                "omitted_known": 0,
                "omitted_unknown": False,
                "errors": 0,
                "stop_reason": None,
                "worker_cleanup": "complete",
            },
        },
    )
    monkeypatch.setattr(
        lab_campaign,
        "evaluate_indicator_report",
        lambda *_args, **_kwargs: {
            "tp": 51,
            "fp": 0,
            "tn": 949,
            "fn": 0,
            "unevaluated": 0,
        },
    )
    result = lab_campaign.run_campaign(args, scenario, values, 3, "a" * 64)
    rows = [json.loads(line) for line in (output / "samples.jsonl").read_text().splitlines()]
    assert len(rows) == 11 and len({row["collection_id"] for row in rows}) == 11
    assert rows[0]["classification"] == "cold"
    assert all(row["classification"] == "warm" for row in rows[1:])
    assert result["raw_samples"] == 11
    assert result["passed"] is markers_present
    assert result["cold_preparation_reference"] == scenario["cold_preparation_reference"]
    assert not list(scratch.iterdir())
