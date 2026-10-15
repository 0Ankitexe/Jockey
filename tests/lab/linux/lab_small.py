"""Frozen LAB-SMALL exact labels; no report data is used to build expectations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .ground_truth import (
    ConnectionExpectation,
    FileExpectation,
    ProcessExpectation,
    file_expectation,
)

if TYPE_CHECKING:
    from .owned_objects import OwnedLedger

KindValue = tuple[str, str]
KINDS = ("sha256", "path", "ip_address", "domain")


def path_token(value: dict[str, str]) -> str:
    if set(value) != {"root_id", "relative_path"} or not value["relative_path"]:
        raise ValueError("invalid approved path reference")
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Labels:
    by_kind: dict[str, frozenset[str]]
    positives: frozenset[KindValue]
    controls: frozenset[KindValue]

    @property
    def expected_confusion(self) -> dict[str, int]:
        return {"tp": 51, "fp": 0, "tn": 949, "fn": 0}

    def classify(
        self,
        *,
        observed: set[KindValue],
        eligible_kinds: set[str],
        excluded_controls: set[KindValue] | None = None,
    ) -> dict[str, int]:
        if (
            not eligible_kinds.issubset(KINDS)
            or excluded_controls
            or not observed.issubset(self.positives | self.controls)
        ):
            raise ValueError("unrecorded or post-hoc label change")
        tp = fp = tn = fn = unevaluated = 0
        for kind, value in self.positives | self.controls:
            if kind not in eligible_kinds:
                unevaluated += 1
            elif (kind, value) in self.positives:
                if (kind, value) in observed:
                    tp += 1
                else:
                    fn += 1
            elif (kind, value) in observed:
                fp += 1
            else:
                tn += 1
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "unevaluated": unevaluated}


@dataclass(frozen=True)
class Dataset:
    files: tuple[FileExpectation, ...]
    processes: tuple[ProcessExpectation, ...]
    connections: tuple[ConnectionExpectation, ...]
    labels: Labels


def prepare_dataset(ledger: OwnedLedger, *, root_id: str, owner_fqdn: str) -> Dataset:
    """Create fixed benign objects under the admitted ledger, then freeze facts."""
    processes = tuple(ledger.add_process() for _ in range(5))
    connections = tuple(
        ledger.add_loopback_connection(
            f"127.0.0.{index + 1}", client_address=f"127.0.0.{index + 6}"
        )
        for index in range(5)
    )
    files: list[FileExpectation] = []
    paths: list[dict[str, str]] = []
    for index in range(20):
        seed = hashlib.sha256(f"jocky-lab-small-v1-file-{index:02}".encode()).digest()
        content = (seed * 2048)[:65_536]
        name = f"lab-small-file-{index:02}.bin"
        path = ledger.add_file(name, content)
        label = f"{ledger.directory.name}/{path.name}"
        files.append(file_expectation(label, content, root_id))
        paths.append({"root_id": root_id, "relative_path": label})
    addresses = sorted(
        {address for item in connections for address in (item.local_address, item.remote_address)}
    )
    labels = build_labels(
        hashes=[item.sha256 for item in files],
        paths=paths,
        addresses=addresses,
        owner_fqdn=owner_fqdn,
    )
    validate_dataset(
        labels,
        process_count=len(processes),
        connection_count=len(connections),
        file_sizes=[item.size_bytes for item in files],
        event_markers=10,
    )
    return Dataset(tuple(files), processes, connections, labels)


def build_labels(
    *,
    hashes: list[str],
    paths: list[dict[str, str]],
    addresses: list[str],
    owner_fqdn: str,
) -> Labels:
    if (
        len(hashes) != 20
        or len(set(hashes)) != 20
        or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
        or len(paths) != 20
        or len(addresses) != 10
        or len(set(addresses)) != 10
        or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.invalid", owner_fqdn)
    ):
        raise ValueError("invalid independent positive labels")
    positives: dict[str, set[str]] = {
        "sha256": set(hashes),
        "path": {path_token(value) for value in paths},
        "ip_address": set(addresses),
        "domain": {owner_fqdn},
    }
    if any(
        len(positives[kind]) != count
        for kind, count in (
            ("sha256", 20),
            ("path", 20),
            ("ip_address", 10),
            ("domain", 1),
        )
    ) or any(not ipaddress.ip_address(value).is_loopback for value in addresses):
        raise ValueError("duplicate, unapproved or non-loopback positive")
    candidates: dict[str, list[str]] = {
        "sha256": [f"{i + 1_000_000:064x}" for i in range(300)],
        "path": [
            path_token(
                {
                    "root_id": paths[0]["root_id"],
                    "relative_path": f"absent-control-{i:03}",
                }
            )
            for i in range(300)
        ],
        "ip_address": [f"198.18.{i // 256}.{i % 256}" for i in range(300)],
        "domain": [f"absent-{i:03}.invalid" for i in range(300)],
    }
    controls: dict[str, set[str]] = {}
    for kind in KINDS:
        controls[kind] = set()
        for value in candidates[kind]:
            if value not in positives[kind]:
                controls[kind].add(value)
            if len(controls[kind]) == 250 - len(positives[kind]):
                break
        if len(controls[kind]) != 250 - len(positives[kind]):
            raise ValueError("insufficient absent controls")
    by_kind = {kind: frozenset(positives[kind] | controls[kind]) for kind in KINDS}
    return Labels(
        by_kind,
        frozenset((kind, value) for kind in KINDS for value in positives[kind]),
        frozenset((kind, value) for kind in KINDS for value in controls[kind]),
    )


def validate_dataset(
    labels: Labels,
    *,
    process_count: int,
    connection_count: int,
    file_sizes: list[int],
    event_markers: int,
) -> None:
    if (
        process_count != 5
        or connection_count != 5
        or file_sizes != [65_536] * 20
        or event_markers != 10
        or len(labels.positives) != 51
        or len(labels.controls) != 949
        or any(len(labels.by_kind[kind]) != 250 for kind in KINDS)
    ):
        raise ValueError("LAB-SMALL dataset or pre-recorded labels differ")
