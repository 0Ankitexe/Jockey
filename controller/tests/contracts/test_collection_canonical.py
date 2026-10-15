"""Independent canonical byte/digest vectors, not a controller ingestion API."""

import copy
import json
from typing import Any

import pytest

from .collection_canonical_support import canonical, finalize, identity, verify_integrity
from .test_collection_contracts import ROOT, load_object

VECTORS = ROOT / "fixtures/valid/collection/canonical-vectors.json"
REPORT = ROOT / "fixtures/valid/collection/report.json"


def changed_report(vector: dict[str, Any]) -> dict[str, Any]:
    report = load_object(REPORT)
    for path, replacement in vector["changes"]:
        components = path.removeprefix("/").split("/")
        current: Any = report
        for key in components[:-1]:
            current = current[int(key)] if isinstance(current, list) else current[key]
        key = components[-1]
        current[int(key) if isinstance(current, list) else key] = copy.deepcopy(replacement)
    return report


def test_canonical_values_and_hard_coded_digests() -> None:
    from hashlib import sha256

    data = load_object(VECTORS)
    assert data["format"] == "JOCKY-CJSON-1"
    for vector in data["values"]:
        expected = vector["canonical"].encode("utf-8")
        actual = canonical(vector["value"], len(expected))
        assert actual == expected
        assert sha256(actual).hexdigest() == vector["sha256"]
        with pytest.raises(ValueError, match="Size"):
            canonical(vector["value"], len(expected) - 1)
    for vector in data["invalid_values"]:
        with pytest.raises(ValueError, match="Value"):
            canonical(vector["value"])


def test_report_goldens_have_independent_integrity_and_lengths() -> None:
    for vector in load_object(VECTORS)["reports"]:
        raw = finalize(changed_report(vector))
        report = verify_integrity(raw)
        assert len(raw) == vector["report_bytes"]
        assert report["content_sha256"] == vector["sha256"]
        assert report["manifest"]["content_sha256"] == vector["manifest_sha256"]
        assert report["summary"]["status"] == vector["status"]
        assert report["report_kind"] == "synthetic_test"


@pytest.mark.parametrize("domain", ["record", "error", "manifest"])
def test_identity_domains_agree_with_rust(domain: str) -> None:
    data = load_object(VECTORS)
    assert identity(domain, data["collection_id"], 0) == data["ids"][domain]


@pytest.mark.parametrize(
    "path",
    [
        ("content_sha256",),
        ("manifest", "content_sha256"),
        ("records", 0, "content_sha256"),
        ("manifest", "entries", 0, "sha256"),
        ("context", "case_id"),
        ("summary", "report_bytes"),
    ],
)
def test_corruption_is_rejected_without_rust_or_source_access(path: tuple[str | int, ...]) -> None:
    report = load_object(REPORT)
    current: Any = report
    for key in path[:-1]:
        current = current[key]
    key = path[-1]
    value = current[key]
    current[key] = value + 1 if isinstance(value, int) else value.replace(value[0], "f", 1)
    with pytest.raises(ValueError):
        verify_integrity(canonical(report) + b"\n")


@pytest.mark.parametrize("suffix", [b"", b"\n\n", b" \n"])
def test_noncanonical_report_bytes_are_rejected(suffix: bytes) -> None:
    raw = finalize(load_object(REPORT))
    with pytest.raises(ValueError, match="Canonical"):
        verify_integrity(raw[:-1] + suffix)


def test_pretty_json_is_not_canonical_evidence() -> None:
    with pytest.raises(ValueError, match="Canonical"):
        verify_integrity(json.dumps(load_object(REPORT), indent=2).encode())


def test_canonical_oracle_rejects_depth_nodes_and_non_json_python_values() -> None:
    nested: Any = True
    for _ in range(16):
        nested = [nested]
    canonical(nested)
    with pytest.raises(ValueError, match="Depth"):
        canonical([nested])
    canonical([None] * 131071)
    with pytest.raises(ValueError, match="Nodes"):
        canonical([None] * 131072)
    for value in [object(), {1: "value"}, "\ud800", float("nan")]:
        with pytest.raises(ValueError, match="Value"):
            canonical(value)
