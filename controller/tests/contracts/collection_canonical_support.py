"""Test-only CJSON/integrity oracle. Never imports Rust or opens evidence sources.

This checks bytes, identity, digests and counts, not authority, live truth or the
full Rust collector-specific verifier. Only repo fixtures are supplied by tests.
"""

import copy
import json
from hashlib import sha256
from typing import Any
from uuid import UUID

from .collection_decode_support import strict_decode

MAXIMUM = 10_485_760


def canonical(value: Any, maximum: int = MAXIMUM) -> bytes:
    remaining = 131072

    def check(node: Any, depth: int) -> None:
        nonlocal remaining
        remaining -= 1
        if isinstance(node, dict):
            remaining -= len(node)
        if remaining < 0:
            raise ValueError("Nodes")
        if isinstance(node, (dict, list)) and depth >= 16:
            raise ValueError("Depth")
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str) or not key.isascii():
                    raise ValueError("Value")
                check(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                check(item, depth + 1)
        elif node is None or isinstance(node, bool):
            return
        elif isinstance(node, int):
            if abs(node) > 9007199254740991:
                raise ValueError("Value")
        elif isinstance(node, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in node):
                raise ValueError("Value")
        else:
            raise ValueError("Value")

    check(value, 0)
    result = bytearray()
    encoder = json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    for text in encoder.iterencode(value):
        chunk = text.encode("utf-8")
        if len(result) + len(chunk) > min(maximum, MAXIMUM):
            raise ValueError("Size")
        result.extend(chunk)
    return bytes(result)


def body_digest(value: dict[str, Any]) -> str:
    return sha256(
        canonical({key: item for key, item in value.items() if key != "content_sha256"})
    ).hexdigest()


def identity(domain: str, collection: str, ordinal: int) -> str:
    tags = {
        "record": b"JOCKY-V5-RECORD-ID\0",
        "error": b"JOCKY-V5-ERROR-ID\0",
        "manifest": b"JOCKY-V5-MANIFEST-ID\0",
    }
    if domain not in tags or not 0 <= ordinal < 2**64 or (domain == "manifest" and ordinal != 0):
        raise ValueError("Identity")
    framed = tags[domain] + UUID(collection).bytes
    if domain != "manifest":
        framed += ordinal.to_bytes(8, "big")
    raw = bytearray(sha256(framed).digest()[:16])
    raw[6] = (raw[6] & 15) | 0x80
    raw[8] = (raw[8] & 63) | 0x80
    return str(UUID(bytes=bytes(raw)))


def finalize(value: dict[str, Any]) -> bytes:
    report = copy.deepcopy(value)
    manifest = report["manifest"]
    manifest["entries"] = []
    manifest["manifest_id"] = identity("manifest", report["context"]["collection_id"], 0)
    for record in report["records"]:
        record["content_sha256"] = body_digest(record)
        encoded = canonical(record)
        manifest["entries"].append(
            {
                "record_id": record["record_id"],
                "sequence": record["sequence"],
                "byte_length": len(encoded),
                "sha256": sha256(encoded).hexdigest(),
            }
        )
    manifest["content_sha256"] = body_digest(manifest)
    for _ in range(8):
        report["content_sha256"] = body_digest(report)
        raw = canonical(report, MAXIMUM - 1) + b"\n"
        if report["summary"]["report_bytes"] == len(raw):
            return raw
        report["summary"]["report_bytes"] = len(raw)
    raise ValueError("Length")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def verify_integrity(raw: bytes) -> dict[str, Any]:
    report = strict_decode("report", raw)
    require(raw == canonical(report) + b"\n", "Canonical")
    require(report["summary"]["report_bytes"] == len(raw), "Length")
    require(body_digest(report) == report["content_sha256"], "Digest")
    manifest = report["manifest"]
    collection = report["context"]["collection_id"]
    require(manifest["manifest_id"] == identity("manifest", collection, 0), "Identity")
    require(body_digest(manifest) == manifest["content_sha256"], "Digest")
    require(len(manifest["entries"]) == len(report["records"]), "Count")
    require(report["summary"]["accepted_records"] == len(report["records"]), "Count")
    require(report["summary"]["errors"] == len(report["errors"]), "Count")
    for ordinal, record in enumerate(report["records"]):
        require(record["sequence"] == ordinal, "Identity")
        require(record["record_id"] == identity("record", collection, ordinal), "Identity")
        require(body_digest(record) == record["content_sha256"], "Digest")
        entry = manifest["entries"][ordinal]
        encoded = canonical(record)
        require(
            entry
            == {
                "record_id": record["record_id"],
                "sequence": ordinal,
                "byte_length": len(encoded),
                "sha256": sha256(encoded).hexdigest(),
            },
            "Manifest",
        )
    for ordinal, error in enumerate(report["errors"]):
        require(error["error_id"] == identity("error", collection, ordinal), "Identity")
    return report
