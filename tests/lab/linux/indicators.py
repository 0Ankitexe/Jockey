"""Frozen owner-supplied indicator document and independent match reconciliation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid5

from controller.tests.contracts.collection_decode_support import strict_decode

from .lab_small import KINDS, KindValue, Labels


@dataclass(frozen=True)
class IndicatorPlan:
    document: bytes
    by_id: dict[str, KindValue]
    labels: Labels
    set_id: str


def build_indicator_plan(labels: Labels, *, case_id: str, set_id: str) -> IndicatorPlan:
    namespace = UUID(set_id)
    rows: list[dict[str, Any]] = []
    by_id: dict[str, KindValue] = {}
    for kind in KINDS:
        for value in sorted(labels.by_kind[kind]):
            indicator_id = str(uuid5(namespace, f"{kind}:{value}"))
            by_id[indicator_id] = (kind, value)
            rows.append(
                {
                    "indicator_id": indicator_id,
                    "kind": kind,
                    "value": json.loads(value) if kind == "path" else value,
                }
            )
    document = json.dumps(
        {
            "schema_version": "1.0.0",
            "indicator_set_id": set_id,
            "case_id": case_id,
            "revision": "lab-small-v1-frozen",
            "rules_version": "exact-v1",
            "indicators": rows,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    strict_decode("indicator-set", document)
    if len(rows) != 1000 or len(by_id) != 1000:
        raise ValueError("indicator plan is not exact")
    return IndicatorPlan(document, by_id, labels, set_id)


def evaluate_indicator_report(
    plan: IndicatorPlan, report: dict[str, Any], *, eligible_kinds: set[str]
) -> dict[str, int]:
    records = {record["record_id"]: record for record in report["records"]}
    observed: set[KindValue] = set()
    for record in report["records"]:
        if record["record_type"] != "match":
            continue
        payload = record["payload"]
        indicator_id = payload["indicator_id"]
        if (
            indicator_id not in plan.by_id
            or payload["indicator_set_id"] != plan.set_id
            or payload["kind"] != plan.by_id[indicator_id][0]
            or payload["matched_record_id"] not in records
        ):
            raise ValueError("indicator result is not linked to frozen inputs")
        criterion = plan.by_id[indicator_id]
        source = records[payload["matched_record_id"]]
        field = payload["field_path"]
        candidate: str | None = None
        source_payload = source["payload"]
        if (
            criterion[0] == "sha256"
            and source["record_type"] == "metadata"
            and field == "/payload/sha256"
        ):
            observed_hash = source_payload["sha256"]
            if (
                observed_hash["state"] == "available"
                and source_payload["read_stability"] == "stable_observed"
            ):
                candidate = observed_hash["value"]
        elif (
            criterion[0] == "path"
            and source["record_type"] in ("metadata", "entry")
            and field == "/payload/location"
        ):
            candidate = json.dumps(
                source_payload["location"], sort_keys=True, separators=(",", ":")
            )
        elif (
            criterion[0] == "ip_address"
            and source["record_type"] == "connection"
            and field in ("/payload/local_address", "/payload/remote_address")
        ):
            candidate = source_payload[field.removeprefix("/payload/")]
        elif criterion[0] == "domain" and field in (
            "/payload/hostname",
            "/payload/domain",
        ):
            key = field.removeprefix("/payload/")
            if (source["record_type"], key) in (
                ("profile", "hostname"),
                ("log", "domain"),
            ):
                observed_domain = source_payload[key]
                if observed_domain["state"] == "available":
                    candidate = observed_domain["value"].removesuffix(".")
        if candidate != criterion[1] or source["record_type"] == "match":
            raise ValueError("indicator match differs from observed source fact")
        observed.add(criterion)
    return plan.labels.classify(observed=observed, eligible_kinds=eligible_kinds)
