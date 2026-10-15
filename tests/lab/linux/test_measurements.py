"""Unit, integration and negative measurement rules for LAB-SMALL."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from .measurements import (
    Sample,
    SampleRecorder,
    aggregate_rss_bytes,
    capture_invocation,
    summarize,
    summarize_recorded,
    validate_sample,
    wait4_maxrss_bytes,
)


def sample(**changes: object) -> Sample:
    base: dict[str, object] = {
        "run_id": "one",
        "classification": "cold",
        "elapsed_ms": 60_000,
        "parent_peak_rss_bytes": 128 * 1024 * 1024,
        "worker_peaks_bytes": (128 * 1024 * 1024,),
        "workers_sequential": True,
        "output_bytes": 10_485_760,
        "accepted_records": 10_000,
        "source_bytes": 20 * 65_536,
        "exit_code": 0,
        "seeded_facts_ok": True,
        "report_status": "complete",
        "failure": None,
        "worker_cleanup": "complete",
    }
    return Sample(**(base | changes))  # type: ignore[arg-type]


def test_wait4_units_identity_and_nonoverlapping_peak_formula() -> None:
    assert wait4_maxrss_bytes(1024, platform="linux") == 1_048_576
    assert aggregate_rss_bytes(10, (3, 7, 4), sequential=True) == 17
    with pytest.raises(ValueError):
        aggregate_rss_bytes(10, (3, 7), sequential=False)
    with pytest.raises(ValueError):
        wait4_maxrss_bytes(-1, platform="linux")


def test_every_ceiling_accepts_boundary_and_rejects_plus_one() -> None:
    validate_sample(sample())
    for changes in (
        {"elapsed_ms": 60_001},
        {"parent_peak_rss_bytes": 128 * 1024 * 1024 + 1},
        {"output_bytes": 10_485_761},
        {"accepted_records": 10_001},
        {"seeded_facts_ok": False},
        {"exit_code": 3, "failure": "collector-failed"},
    ):
        with pytest.raises(ValueError):
            validate_sample(sample(**changes))
    with pytest.raises(ValueError, match="RSS trace"):
        validate_sample(sample(expected_owned_workers=10))


def test_raw_failure_retention_and_nearest_rank_warm_statistics(tmp_path: Path) -> None:
    cold = sample(run_id="cold")
    warm = [
        sample(run_id=f"warm-{i}", classification="warm", elapsed_ms=i * 100) for i in range(1, 11)
    ]
    warm[4] = sample(
        run_id="warm-5",
        classification="warm",
        elapsed_ms=500,
        exit_code=3,
        failure="typed-failure",
    )
    result = summarize([cold, *warm], tmp_path / "samples.jsonl")
    raw = [json.loads(line) for line in (tmp_path / "samples.jsonl").read_text().splitlines()]
    assert len(raw) == 11 and raw[5]["failure"] == "typed-failure"
    assert result["warm"]["median_ms"] == 550
    assert result["warm"]["p95_ms"] == 1000
    assert result["warm"]["max_ms"] == 1000
    assert result["passed"] is False


def test_invalid_repetition_or_duplicate_ids_never_summarize(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        summarize([sample()], tmp_path / "raw.jsonl")
    assert not (tmp_path / "raw.jsonl").exists()


def test_actual_wait4_child_identity_and_full_invocation_output(tmp_path: Path) -> None:
    observation = capture_invocation(
        [sys.executable, "-c", "print('bounded')"], tmp_path, "owned-direct-child"
    )
    assert observation.exit_code == 0
    assert observation.parent.pid > 0
    assert observation.parent.start_ticks.isdigit()
    assert observation.parent.peak_rss_bytes > 0
    assert observation.elapsed_ms > 0
    assert observation.stdout_path.read_bytes() == b"bounded\n"
    assert observation.stderr_path.read_bytes() == b""
    with pytest.raises(FileExistsError):
        capture_invocation([sys.executable, "-c", "pass"], tmp_path, "owned-direct-child")


def test_raw_attempt_is_retained_before_campaign_finishes(tmp_path: Path) -> None:
    path = tmp_path / "raw.jsonl"
    with SampleRecorder(path) as recorder:
        recorder.append(sample(run_id="cold", exit_code=3, failure="timeout"))
        with pytest.raises(ValueError):
            summarize_recorded(recorder.samples)
    assert len(path.read_text().splitlines()) == 1
    with pytest.raises(FileExistsError):
        SampleRecorder(path)
