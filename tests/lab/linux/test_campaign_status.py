"""Negative campaign status and raw attempt preservation."""

from __future__ import annotations

import json
from pathlib import Path

from _pytest.capture import CaptureFixture
from _pytest.monkeypatch import MonkeyPatch

from . import run_scenario
from .lab_campaign import _failed_before_collection
from .measurements import SampleRecorder


def test_failed_admission_keeps_a_typed_raw_attempt(tmp_path: Path) -> None:
    scenario = {"approval_id": "approval", "inventory_id": "inventory"}
    failure = _failed_before_collection(scenario, 0, "admission: ValueError", "start", 7, "a" * 64)
    with SampleRecorder(tmp_path / "samples.jsonl") as recorder:
        recorder.append(failure)
    [row] = [json.loads(line) for line in (tmp_path / "samples.jsonl").read_text().splitlines()]
    assert row["classification"] == "cold"
    assert row["failure"] == "admission: ValueError"
    assert row["seeded_facts_ok"] is False
    assert row["aggregate_peak_rss_bytes"] is None


def test_failed_campaign_returns_nonzero(
    monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    monkeypatch.setattr(run_scenario, "dispatch", lambda _: {"passed": False, "raw_samples": 1})
    names = (
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
    )
    arguments = [argument for name in names for argument in (f"--{name}", "x")]
    assert run_scenario.main(["--allow-live-lab", *arguments]) == 1
    assert json.loads(capsys.readouterr().out)["raw_samples"] == 1
