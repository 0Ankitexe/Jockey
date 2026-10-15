"""Fixed dataset labels and deliberate missing-data classification."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

from .approval import load_lab_small_scenario
from .indicators import build_indicator_plan, evaluate_indicator_report
from .lab_campaign import run_campaign
from .lab_small import build_labels, prepare_dataset, validate_dataset
from .owned_objects import OwnedLedger


def test_lab_small_needs_explicit_approved_kind_actions_and_fresh_time() -> None:
    value = json.loads(Path("fixtures/valid/collection/lab-scenario.json").read_bytes())
    value["scenario"] = "lab-small"
    value["allowed_actions"].append("emit_benign_log_markers")

    def admit(document: dict[str, object], at: str = "2020-01-01T00:30:00Z") -> dict[str, object]:
        return load_lab_small_scenario(
            json.dumps(document).encode(),
            vm_endpoint_id=str(value["endpoint_id"]),
            binary_sha256=str(value["collector_sha256"]),
            now=at,
            opt_in=True,
        )

    assert admit(value)["scenario"] == "lab-small"
    for change in (
        {"scenario": "checkpoint"},
        {"allowed_actions": value["allowed_actions"][:-1]},
        {"valid_until": "2020-01-01T00:20:00Z"},
        {"cold_preparation_reference": ""},
        {"extra": "scope-widening"},
    ):
        with pytest.raises(ValueError):
            admit(value | change)


def test_five_five_twenty_and_exact_indicator_labels() -> None:
    labels = build_labels(
        hashes=[f"{i:064x}" for i in range(20)],
        paths=[
            {
                "root_id": "10000000-0000-4000-8000-000000000001",
                "relative_path": f"file-{i}",
            }
            for i in range(20)
        ],
        addresses=[f"127.0.0.{i}" for i in range(1, 11)],
        owner_fqdn="lab-owned.invalid",
    )
    assert {kind: len(values) for kind, values in labels.by_kind.items()} == {
        "sha256": 250,
        "path": 250,
        "ip_address": 250,
        "domain": 250,
    }
    assert labels.expected_confusion == {"tp": 51, "fp": 0, "tn": 949, "fn": 0}
    validate_dataset(
        labels,
        process_count=5,
        connection_count=5,
        file_sizes=[65_536] * 20,
        event_markers=10,
    )


def test_missing_positive_is_unevaluated_not_true_negative() -> None:
    labels = build_labels(
        hashes=[f"{i:064x}" for i in range(20)],
        paths=[
            {
                "root_id": "10000000-0000-4000-8000-000000000001",
                "relative_path": f"file-{i}",
            }
            for i in range(20)
        ],
        addresses=[f"127.0.0.{i}" for i in range(1, 11)],
        owner_fqdn="lab-owned.invalid",
    )
    result = labels.classify(observed=set(), eligible_kinds={"sha256", "path", "ip_address"})
    assert result["unevaluated"] == 250
    assert result["fn"] == 50
    assert result["tn"] == 700


def test_unapproved_hostname_counts_or_post_hoc_control_removal_fail() -> None:
    with pytest.raises(ValueError):
        build_labels(
            hashes=["0" * 64] * 20,
            paths=[],
            addresses=[],
            owner_fqdn="host.example.com",
        )
    labels = build_labels(
        hashes=[f"{i:064x}" for i in range(20)],
        paths=[
            {
                "root_id": "10000000-0000-4000-8000-000000000001",
                "relative_path": f"file-{i}",
            }
            for i in range(20)
        ],
        addresses=[f"127.0.0.{i}" for i in range(1, 11)],
        owner_fqdn="lab-owned.invalid",
    )
    with pytest.raises(ValueError):
        labels.classify(
            observed=set(),
            eligible_kinds=set(labels.by_kind),
            excluded_controls={next(iter(labels.controls))},
        )
    with pytest.raises(ValueError):
        validate_dataset(
            labels,
            process_count=5,
            connection_count=5,
            file_sizes=[65_536] * 20,
            event_markers=9,
        )


def test_frozen_indicator_document_and_report_linkage() -> None:
    labels = build_labels(
        hashes=[f"{i:064x}" for i in range(20)],
        paths=[
            {
                "root_id": "10000000-0000-4000-8000-000000000001",
                "relative_path": f"file-{i}",
            }
            for i in range(20)
        ],
        addresses=[f"127.0.0.{i}" for i in range(1, 11)],
        owner_fqdn="lab-owned.invalid",
    )
    plan = build_indicator_plan(
        labels,
        case_id="10000000-0000-4000-8000-000000000005",
        set_id="10000000-0000-4000-8000-000000000010",
    )
    assert len(json.loads(plan.document)["indicators"]) == 1000
    result = evaluate_indicator_report(plan, {"records": []}, eligible_kinds=set(labels.by_kind))
    assert result == {"tp": 0, "fp": 0, "tn": 949, "fn": 51, "unevaluated": 0}
    control_id = next(
        key
        for key, value in plan.by_id.items()
        if value in labels.controls and value[0] == "sha256"
    )
    report: dict[str, Any] = {
        "records": [
            {
                "record_id": "10000000-0000-4000-8000-000000000002",
                "record_type": "profile",
                "payload": {"hostname": {"state": "available", "value": "genuine.invalid"}},
            },
            {
                "record_id": "10000000-0000-4000-8000-000000000003",
                "record_type": "match",
                "payload": {
                    "indicator_id": control_id,
                    "indicator_set_id": plan.set_id,
                    "kind": plan.by_id[control_id][0],
                    "matched_record_id": "10000000-0000-4000-8000-000000000002",
                    "field_path": "/payload/hostname",
                },
            },
        ]
    }
    with pytest.raises(ValueError, match="observed source fact"):
        evaluate_indicator_report(plan, report, eligible_kinds=set(labels.by_kind))
    report["records"][1]["payload"]["matched_record_id"] = "10000000-0000-4000-8000-000000000099"
    with pytest.raises(ValueError):
        evaluate_indicator_report(plan, report, eligible_kinds=set(labels.by_kind))
    positive_id = next(key for key, value in plan.by_id.items() if value == ("sha256", "0" * 64))
    source = json.loads(
        Path("fixtures/valid/collection/forensic-record--metadata.json").read_bytes()
    )
    match: dict[str, Any] = {
        "record_id": "10000000-0000-4000-8000-000000000099",
        "record_type": "match",
        "payload": {
            "indicator_id": positive_id,
            "indicator_set_id": plan.set_id,
            "kind": "sha256",
            "matched_record_id": source["record_id"],
            "field_path": "/payload/sha256",
        },
    }
    observed = evaluate_indicator_report(
        plan, {"records": [source, match]}, eligible_kinds=set(labels.by_kind)
    )
    assert observed["tp"] == 1 and observed["fp"] == 0
    match["payload"]["indicator_id"] = control_id
    with pytest.raises(ValueError, match="observed source fact"):
        evaluate_indicator_report(
            plan, {"records": [source, match]}, eligible_kinds=set(labels.by_kind)
        )


def test_owned_dataset_prepares_independent_facts_and_cleans_exactly(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    try:
        dataset = prepare_dataset(
            ledger,
            root_id="10000000-0000-4000-8000-000000000001",
            owner_fqdn="lab-owned.invalid",
        )
        assert len(dataset.processes) == 5
        assert len(dataset.connections) == 5
        assert len(dataset.files) == 20
        assert all(file.size_bytes == 65_536 for file in dataset.files)
        assert (
            len(
                {c.local_address for c in dataset.connections}
                | {c.remote_address for c in dataset.connections}
            )
            == 10
        )
        assert len(dataset.labels.positives) == 51
    finally:
        ledger.cleanup()
    assert not list(root.iterdir())


def test_campaign_rejects_wrong_approval_before_object_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(_root: Path) -> None:
        raise AssertionError("objects created before approval")

    monkeypatch.setattr(OwnedLedger, "create", forbidden)
    with pytest.raises(ValueError, match="approval"):
        run_campaign(
            Namespace(profile="lab-small-v1"),
            {"scenario": "checkpoint"},
            {},
            3,
            "a" * 64,
        )
