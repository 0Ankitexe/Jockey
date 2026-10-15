"""Independent report-integrity and pre-recorded fact checks."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
from typing import Any

from controller.tests.contracts.collection_canonical_support import (
    canonical,
    verify_integrity,
)
from controller.tests.contracts.collection_decode_support import strict_decode

from .ground_truth import ConnectionExpectation, FileExpectation, ProcessExpectation


def normalized_input_sha256(role: str, raw: bytes) -> str:
    """Independently reproduce the documented V5 typed-input normalization."""
    kind = (
        "endpoint-designation"
        if role == "designation"
        else ("indicator-set" if role == "indicators" else role)
    )
    value = copy.deepcopy(strict_decode(kind, raw))
    if role == "designation":
        value["approved_operator_ids"].sort()
    if role in ("authorisation", "policy"):
        scope = value["scope"]
        scope["capabilities"].sort()
        scope["source_groups"].sort()
        scope["roots"].sort(key=lambda root: root["root_id"])
        for root in scope["roots"]:
            root["purposes"].sort()
    if role == "policy":
        value["sources"].sort(key=lambda source: source["source_id"])
    if role == "request":
        value["capabilities"].sort()
        value["source_ids"].sort()
        value["paths"].sort(key=lambda path: (path["root_id"], path["relative_path"]))
    if role == "indicators":
        for indicator in value["indicators"]:
            if indicator["kind"] == "ip_address":
                indicator["value"] = str(ipaddress.ip_address(indicator["value"]))
            elif indicator["kind"] == "domain":
                indicator["value"] = indicator["value"].removesuffix(".").lower()
        value["indicators"].sort(key=lambda indicator: indicator["indicator_id"])
    return hashlib.sha256(canonical(value, 524288)).hexdigest()


def verify_report(
    raw: bytes,
    expected_files: list[FileExpectation],
    expected_processes: tuple[ProcessExpectation, ...] | list[ProcessExpectation] = (),
    expected_connections: tuple[ConnectionExpectation, ...] | list[ConnectionExpectation] = (),
    *,
    expected_context: dict[str, Any] | None = None,
    expected_input_digests: dict[str, str] | None = None,
) -> dict[str, Any]:
    report = verify_integrity(raw)
    if expected_context is not None and report["context"] != expected_context:
        raise ValueError("report context differs from approved context")
    if expected_input_digests is not None and any(
        report["inputs"][role] is None or report["inputs"][role]["sha256"] != digest
        for role, digest in expected_input_digests.items()
    ):
        raise ValueError("report input provenance differs from approved bytes")
    if report["manifest"]["context"] != report["context"]:
        raise ValueError("manifest context differs from report context")
    if any(record["context"] != report["context"] for record in report["records"]):
        raise ValueError("record context differs from report context")
    outcomes = report["collectors"]
    summary = report["summary"]
    outcome_names = [item["collector"] for item in outcomes]
    if len(outcome_names) != len(set(outcome_names)):
        raise ValueError("duplicate collector outcome")
    if (
        sum(item["accepted_records"] for item in outcomes) != summary["accepted_records"]
        or sum(item["errors"] for item in outcomes) != summary["errors"]
    ):
        raise ValueError("collector totals differ from summary")
    records = report["records"]
    if any(
        sum(record["collector"]["name"] == item["collector"] for record in records)
        != item["accepted_records"]
        for item in outcomes
    ) or any(record["collector"]["name"] not in outcome_names for record in records):
        raise ValueError("record attribution differs from collector outcomes")
    prior_ids: set[str] = set()
    for record in records:
        if (
            record["record_type"] == "match"
            and record["payload"]["matched_record_id"] not in prior_ids
        ):
            raise ValueError("indicator source record is missing or out of order")
        prior_ids.add(record["record_id"])
    for expected_process in expected_processes:
        matching = [
            r
            for r in records
            if r["record_type"] == "process" and r["payload"]["pid"] == expected_process.pid
        ]
        if len(matching) != 1 or matching[0]["payload"]["start_identity"] != {
            "state": "available",
            "value": {
                "boot_id": expected_process.boot_id,
                "pid": expected_process.pid,
                "start_ticks": expected_process.start_ticks,
            },
        }:
            raise ValueError("process differs from independent child identity")
    for expected_connection in expected_connections:
        matching = [
            r
            for r in records
            if r["record_type"] == "connection"
            and all(
                r["payload"].get(key) == value
                for key, value in (
                    ("local_address", expected_connection.local_address),
                    ("local_port", expected_connection.local_port),
                    ("remote_address", expected_connection.remote_address),
                    ("remote_port", expected_connection.remote_port),
                    ("socket_inode", expected_connection.socket_inode),
                )
            )
        ]
        if len(matching) != 1:
            raise ValueError("connection differs from independent socket tuple")
    for expected_file in expected_files:
        matching = [
            record
            for record in records
            if record["record_type"] == "metadata"
            and record["payload"].get("location", {}).get("relative_path") == expected_file.label
            and (
                expected_file.root_id is None
                or record["payload"].get("location", {}).get("root_id") == expected_file.root_id
            )
        ]
        if len(matching) != 1:
            raise ValueError("missing or duplicate independent file fact")
        payload = matching[0]["payload"]
        if payload["size_bytes"] != {
            "state": "available",
            "value": expected_file.size_bytes,
        }:
            raise ValueError("file size differs from independent fact")
        if payload["sha256"] != {"state": "available", "value": expected_file.sha256}:
            raise ValueError("file digest differs from independent fact")
    return report
