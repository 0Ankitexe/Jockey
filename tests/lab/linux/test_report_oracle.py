"""Independent bounded report oracle: valid, tampered and private cases."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from controller.tests.contracts.collection_canonical_support import (
    canonical,
    finalize,
    identity,
)

from .report_oracle import normalized_input_sha256, verify_report


def fixture() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(Path("fixtures/valid/collection/report.json").read_bytes()),
    )


def test_normalized_input_digest_ignores_json_layout_but_rejects_extra_field() -> None:
    value = json.loads(Path("fixtures/valid/collection/request.json").read_bytes())
    compact = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    spaced = json.dumps(value, indent=2).encode()
    assert normalized_input_sha256("request", compact) == normalized_input_sha256("request", spaced)
    value["unexpected"] = True
    with pytest.raises((ValueError, TypeError)):
        normalized_input_sha256("request", json.dumps(value).encode())


def test_cross_language_report_golden_and_context() -> None:
    value = fixture()
    raw = finalize(value)
    report = verify_report(raw, [], expected_context=value["context"])
    assert report["summary"]["accepted_records"] == 1


def test_cross_language_canonical_and_report_golden_vectors() -> None:
    vectors = json.loads(Path("fixtures/valid/collection/canonical-vectors.json").read_bytes())
    for row in vectors["values"]:
        encoded = canonical(row["value"])
        assert encoded.decode() == row["canonical"]
        assert hashlib.sha256(encoded).hexdigest() == row["sha256"]
    for kind in ("record", "error", "manifest"):
        assert identity(kind, vectors["collection_id"], 0) == vectors["ids"][kind]
    for vector in vectors["reports"]:
        candidate = fixture()
        for pointer, replacement in vector["changes"]:
            parts = pointer.lstrip("/").split("/")
            target: Any = candidate
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            last = parts[-1]
            target[int(last) if isinstance(target, list) else last] = replacement
        raw = finalize(candidate)
        result = verify_report(raw, [], expected_context=fixture()["context"])
        assert len(raw) == vector["report_bytes"]
        assert result["content_sha256"] == vector["sha256"]
        assert result["manifest"]["content_sha256"] == vector["manifest_sha256"]


def test_schema_context_counts_order_identity_digest_length_and_truncation() -> None:
    value = fixture()
    raw = finalize(value)
    changes: list[Callable[[dict[str, Any]], None]] = [
        lambda d: d.update(schema_version="9.0.0"),
        lambda d: d["context"].update(endpoint_id="10000000-0000-4000-8000-000000000099"),
        lambda d: d["summary"].update(accepted_records=2),
        lambda d: d["records"][0].update(sequence=1),
        lambda d: d["records"][0].update(record_id="10000000-0000-4000-8000-000000000099"),
        lambda d: d["records"][0].update(content_sha256="0" * 64),
        lambda d: d["summary"].update(report_bytes=1),
    ]
    for change in changes:
        altered = copy.deepcopy(value)
        change(altered)
        with pytest.raises(ValueError):
            verify_report(json.dumps(altered).encode(), [], expected_context=value["context"])
    with pytest.raises(ValueError):
        verify_report(raw[:-1], [], expected_context=value["context"])
    with pytest.raises(ValueError):
        verify_report(raw + b"private source path /owned/secret", [])


def test_resealed_wrong_context_and_privacy_safe_diagnostic() -> None:
    value = fixture()
    altered = copy.deepcopy(value)
    altered["context"]["case_id"] = "10000000-0000-4000-8000-000000000099"
    with pytest.raises(ValueError) as error:
        verify_report(finalize(altered), [], expected_context=value["context"])
    assert "/owned/secret" not in str(error.value)
    assert "context" in str(error.value).lower()


def test_resealed_wrong_input_digest_rejected_against_external_bytes() -> None:
    value = fixture()
    expected = value["inputs"]["request"]["sha256"]
    altered = copy.deepcopy(value)
    altered["inputs"]["request"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="provenance"):
        verify_report(
            finalize(altered),
            [],
            expected_input_digests={"request": expected},
        )


def test_resealed_record_attribution_mismatch_is_rejected() -> None:
    candidate = fixture()
    candidate["collectors"][0]["collector"] = "files"
    with pytest.raises(ValueError, match="attribution"):
        verify_report(finalize(candidate), [])


@pytest.mark.parametrize(
    "record_name",
    (
        "forensic-record.json",
        "forensic-record--process.json",
        "forensic-record--service.json",
        "forensic-record--connection.json",
        "forensic-record--entry.json",
        "forensic-record--metadata.json",
        "forensic-record--log.json",
        "forensic-record--module.json",
        "forensic-record--match.json",
    ),
)
def test_all_nine_payload_shapes_in_sealed_report(record_name: str) -> None:
    record = json.loads(Path("fixtures/valid/collection", record_name).read_bytes())
    candidate = fixture()
    collection_id = candidate["context"]["collection_id"]
    if record["record_type"] == "match":
        source = json.loads(
            Path("fixtures/valid/collection/forensic-record--metadata.json").read_bytes()
        )
        source["sequence"] = 0
        source["record_id"] = identity("record", collection_id, 0)
        record["sequence"] = 1
        record["record_id"] = identity("record", collection_id, 1)
        record["payload"]["matched_record_id"] = source["record_id"]
        candidate["records"] = [source, record]
        file_outcome = copy.deepcopy(candidate["collectors"][0])
        file_outcome["collector"] = "files"
        candidate["collectors"] = [file_outcome]
    else:
        record["sequence"] = 0
        record["record_id"] = identity("record", collection_id, 0)
        candidate["records"] = [record]
        candidate["collectors"][0]["collector"] = record["collector"]["name"]
    if record["record_type"] == "match":
        indicator_outcome = copy.deepcopy(candidate["collectors"][0])
        indicator_outcome["collector"] = "indicators"
        candidate["collectors"].append(indicator_outcome)
    candidate["summary"]["accepted_records"] = len(candidate["records"])
    raw = finalize(candidate)
    assert len(verify_report(raw, [])["records"]) == len(candidate["records"])
