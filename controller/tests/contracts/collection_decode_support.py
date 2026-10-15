"""Independent offline wire decoder oracle, not controller ingestion or authority."""

import json
from datetime import UTC, datetime
from typing import Any, NoReturn, cast

from .test_collection_contracts import validator

CAPS = {
    "indicator-set": 524288,
    "report": 10485760,
    "evidence-manifest": 10485760,
    "forensic-record": 98304,
    "worker": 131072,
    "status": 16384,
}


class DecodeFailure(ValueError):
    """Only a closed reason is exposed, never input data."""


def fail(reason: str) -> NoReturn:
    raise DecodeFailure(reason)


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            fail("DuplicateKey")
        if not key.isascii() or "\0" in key:
            fail("Json")
        result[key] = value
    return result


def integer(token: str) -> int:
    if token == "-0":
        fail("Number")
    if len(token.lstrip("-")) > 16:
        fail("Number")
    value = int(token)
    if abs(value) > 9007199254740991:
        fail("Number")
    return value


def floating(_: str) -> NoReturn:
    fail("Number")


def invalid_constant(_: str) -> NoReturn:
    fail("Json")


def utc_nanos(value: str) -> int:
    # JSON Schema already enforces UTC spelling, calendar and 1–9 fractional digits.
    stem, _, fraction = value.removesuffix("Z").partition(".")
    date = datetime.fromisoformat(stem).replace(tzinfo=UTC)
    delta = date - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(fraction.ljust(9, "0") or "0")


def interval(start: str, end: str, bounded: bool) -> None:
    duration = utc_nanos(end) - utc_nanos(start)
    if duration <= 0 or (bounded and duration > 86400 * 1_000_000_000):
        fail("Timestamp")


def under(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent + "/")


def scope(value: dict[str, Any]) -> None:
    interval(value["event_window"]["start"], value["event_window"]["end"], True)
    seen: set[str] = set()
    roots = value["roots"]
    for index, root in enumerate(roots):
        if root["root_id"] in seen or any(
            under(root["absolute_path"], prior["absolute_path"])
            or under(prior["absolute_path"], root["absolute_path"])
            for prior in roots[:index]
        ):
            fail("Path")
        seen.add(root["root_id"])


def cross_fields(name: str, value: dict[str, Any]) -> None:
    if name in {"endpoint-designation", "authorisation", "policy", "lab-scenario"}:
        interval(
            value["valid_from"], value["valid_until"], name in {"authorisation", "lab-scenario"}
        )
    if name in {"authorisation", "policy"}:
        scope(value["scope"])
    if name == "policy":
        ids: set[str] = set()
        for source in value["sources"]:
            if source["source_id"] in ids or source["kind"] not in value["scope"]["source_groups"]:
                fail("Context")
            ids.add(source["source_id"])
            if "path" in source:
                purpose = {
                    "journal_file": "journal",
                    "text_log": "logs",
                    "startup_directory": "persistence",
                }[source["kind"]]
                if not any(
                    root["root_id"] == source["path"]["root_id"] and purpose in root["purposes"]
                    for root in value["scope"]["roots"]
                ):
                    fail("Context")
    if name == "request":
        interval(value["event_window"]["start"], value["event_window"]["end"], True)
        order = [
            "system",
            "processes",
            "services",
            "connections",
            "persistence",
            "files",
            "events",
            "drivers",
            "indicators",
        ]
        collectors = value["collectors"]
        if collectors != sorted(set(collectors), key=order.index):
            fail("Context")
        for collector in collectors:
            capability = {"services": "system", "connections": "network"}.get(collector, collector)
            if capability not in value["capabilities"]:
                fail("Context")
        if "events" in collectors and not value["source_ids"]:
            fail("Context")
    if name == "indicator-set":
        indicator_ids = [i["indicator_id"] for i in value["indicators"]]
        if len(indicator_ids) != len(set(indicator_ids)):
            fail("Identifier")
    if name == "lab-scenario" and (
        under(value["owned_scratch_root"], value["output_root"])
        or under(value["output_root"], value["owned_scratch_root"])
    ):
        fail("Path")
    if name == "report":
        context = value["context"]
        if value["manifest"]["context"] != context or any(
            r["context"] != context for r in value["records"]
        ):
            fail("Context")
        if (
            value["endpoint"] is not None
            and value["endpoint"]["endpoint_id"] != context["endpoint_id"]
        ):
            fail("Context")
        for role, key in [
            ("designation", "designation_id"),
            ("authorisation", "authorisation_id"),
            ("policy", "policy_id"),
            ("request", "collection_id"),
        ]:
            if value["inputs"][role]["id"] != context[key]:
                fail("Context")


def read_bounded_json(raw: bytes, maximum: int) -> Any:
    """Shared test-only lexical checks, independent of Rust and any schema."""
    if len(raw) > maximum:
        fail("Size")
    try:
        text = raw.decode("utf-8")
        # Preflight nesting before Python's recursive JSON decoder allocates containers.
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 16:
                    fail("Depth")
            elif char in "]}":
                depth -= 1
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=floating,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        fail("Json")
    nodes = 0
    pending = [value]
    while pending:
        node = pending.pop()
        nodes += 1
        if isinstance(node, dict):
            nodes += len(node)
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, str):
            try:
                node.encode("utf-8")
            except UnicodeError:
                fail("Json")
        if nodes > 131072:
            fail("Allocation")
    return value


def strict_decode(name: str, raw: bytes) -> dict[str, Any]:
    value = read_bounded_json(raw, CAPS.get(name, 65536))
    if not isinstance(value, dict):
        fail("Schema")
    version = "2.0.0" if name in {"forensic-record", "evidence-manifest"} else "1.0.0"
    if isinstance(value.get("schema_version"), str) and value["schema_version"] != version:
        fail("Version")
    schema_name = f"{'v2' if version == '2.0.0' else 'collection/v1'}/{name}"
    if not validator(schema_name).is_valid(value):
        fail("Schema")
    keyed: list[tuple[str, Any]] = [("", value)]
    while keyed:
        key, item = keyed.pop()
        if (
            key == "details"
            and len(
                json.dumps(item, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                    "utf-8"
                )
            )
            > 4096
        ):
            fail("Size")
        if isinstance(item, dict):
            keyed.extend(item.items())
        elif isinstance(item, list):
            keyed.extend((key, child) for child in item)
        elif isinstance(item, str):
            maximum = (
                4096
                if key in {"relative_path", "absolute_path", "owned_scratch_root", "output_root"}
                else 87384
                if key == "data"
                else 65536
            )
            if len(item.encode("utf-8")) > maximum or "\0" in item:
                fail("Size")
            if key in {"absolute_path", "owned_scratch_root", "output_root"} and any(
                under(item, root) for root in ["/proc", "/sys", "/dev"]
            ):
                fail("Path")
    cross_fields(name, value)
    return cast(dict[str, Any], value)
