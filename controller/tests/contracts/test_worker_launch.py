"""Independent launch-contract agreement; no controller route or endpoint access."""

import copy
import json
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .collection_decode_support import (
    DecodeFailure,
    fail,
    read_bounded_json,
    utc_nanos,
)
from .test_collection_contracts import RESOURCES, ROOT, load_object

NAME = "collection/v1_1/worker-launch"
SCHEMA = load_object(ROOT / "shared/schemas" / f"{NAME}.schema.json")


def decoder(raw: bytes) -> dict[str, Any]:
    value = read_bounded_json(raw, 65536)
    if (
        isinstance(value, dict)
        and isinstance(value.get("schema_version"), str)
        and value["schema_version"] != "1.1.0"
    ):
        fail("Version")
    schemas = [load_object(ROOT / "shared/schemas" / f"{name}.schema.json") for name in RESOURCES]
    registry: Registry[Any] = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in [*schemas, SCHEMA]
    )
    validator = Draft202012Validator(SCHEMA, registry=registry, format_checker=FormatChecker())
    if not validator.is_valid(value):
        fail("Schema")
    v = cast(dict[str, Any], value)
    origin, observed = v["invocation_origin"], v["launch_observed"]
    if observed["monotonic_ms"] < origin["monotonic_ms"] or utc_nanos(observed["utc"]) < utc_nanos(
        origin["utc"]
    ):
        fail("Context")
    limits, allowance = v["global_limits"], v["allowance"]
    maxima = {
        "records": limits["max_records"] - v["record_base"],
        "errors": limits["max_errors"] - v["error_base"],
        "retained_bytes": limits["max_memory_bytes"] - limits["max_memory_bytes"] // 4,
        **{
            key: limits[f"max_{key}"]
            for key in (
                "report_bytes",
                "source_bytes",
                "entries",
                "indicator_comparisons",
                "staging_bytes",
            )
        },
    }
    if any(allowance[key] > maximum for key, maximum in maxima.items()) or (
        limits["operation_timeout_ms"] > limits["timeout_ms"] - 6000
    ):
        fail("Context")
    if int(v["parent"]["start_ticks"]) > 2**64 - 1:
        fail("Number")
    fds, subjects, configs = set(), set(), set()
    for binding in v["descriptors"]:
        obj = binding["object"]
        for counter in obj.values():
            if counter is not None and int(counter) > 2**64 - 1:
                fail("Number")
        subject = (binding["kind"], binding["subject_id"])
        if binding["fd"] in fds or subject in subjects:
            fail("Context")
        fds.add(binding["fd"])
        subjects.add(subject)
        if (binding["kind"] == "output_directory") != (binding["subject_id"] is None):
            fail("Context")
        if binding["kind"] != "systemd_socket" and obj["mount_id"] is None:
            fail("Context")
        if v["job"] == "collect" and binding["kind"] == "output_directory":
            fail("Context")
    for obj in v["config_exclusions"]:
        for counter in obj.values():
            if counter is not None and int(counter) > 2**64 - 1:
                fail("Number")
        identity = (obj["device_id"], obj["inode"])
        if identity in configs or obj["mount_id"] is None:
            fail("Context")
        configs.add(identity)
    if v["job"] == "publish" and (
        len(v["descriptors"]) != 1
        or v["descriptors"][0]["kind"] != "output_directory"
        or any(
            allowance[key] != 0
            for key in ("records", "source_bytes", "errors", "entries", "indicator_comparisons")
        )
    ):
        fail("Context")
    return v


def fixture() -> dict[str, Any]:
    return load_object(ROOT / "fixtures/valid/collection/worker-launch.json")


def check(value: dict[str, Any]) -> dict[str, Any]:
    return decoder(json.dumps(value).encode())


def test_schema_and_fixture_reason_agreement() -> None:
    assert SCHEMA["$id"] == f"https://jocky.dev/schemas/{NAME}.schema.json"
    Draft202012Validator.check_schema(SCHEMA)
    for case in load_object(ROOT / "fixtures/worker-launch-cases.json")["cases"]:
        raw = (ROOT / case["file"]).read_bytes()
        if case["valid"]:
            assert decoder(raw)["schema_version"] == "1.1.0"
        else:
            with pytest.raises(DecodeFailure, match=f"^{case['reason']}$"):
                decoder(raw)


def test_every_required_field_and_unknown_field_reject() -> None:
    for key in fixture():
        value = fixture()
        del value[key]
        with pytest.raises(DecodeFailure, match="^Schema$"):
            check(value)
    value = fixture()
    value["unknown"] = False
    with pytest.raises(DecodeFailure, match="^Schema$"):
        check(value)


@pytest.mark.parametrize("mode", range(10))
def test_intrinsic_clock_quota_and_binding_negatives(mode: int) -> None:
    value = fixture()
    reason = "Context"
    if mode == 0:
        value["launch_observed"]["monotonic_ms"] = 999
    elif mode == 1:
        value["launch_observed"]["utc"] = "2019-12-31T23:59:59Z"
    elif mode == 2:
        value["record_base"] = 10000
    elif mode == 3:
        value["error_base"] = 1000
    elif mode == 4:
        value["global_limits"]["max_source_bytes"] = 1
    elif mode == 5:
        value["allowance"]["retained_bytes"] = 201326593
    elif mode == 6:
        value["descriptors"].append(copy.deepcopy(value["descriptors"][0]))
    elif mode == 7:
        value["descriptors"][0]["object"]["inode"] = "18446744073709551616"
        reason = "Number"
    elif mode == 8:
        value["descriptors"][0]["kind"] = "output_directory"
    else:
        value["descriptors"][0]["subject_id"] = None
    with pytest.raises(DecodeFailure, match=f"^{reason}$"):
        check(value)


def test_duplicate_keys_size_publisher_and_legacy_separation() -> None:
    raw = json.dumps(fixture()).replace("{", '{"schema_version":"1.1.0",', 1)
    with pytest.raises(DecodeFailure, match="^DuplicateKey$"):
        decoder(raw.encode())
    with pytest.raises(DecodeFailure, match="^Size$"):
        decoder(b" " * 65537)
    value = fixture()
    value["job"] = "publish"
    value["descriptors"][0]["kind"] = "output_directory"
    value["descriptors"][0]["subject_id"] = None
    for key in ("records", "source_bytes", "errors", "entries", "indicator_comparisons"):
        value["allowance"][key] = 0
    assert check(value)["job"] == "publish"
    value["allowance"]["source_bytes"] = 1
    with pytest.raises(DecodeFailure, match="^Context$"):
        check(value)


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b"[" * 17 + b"0" + b"]" * 17, "Depth"),
        (b"1.0", "Number"),
        (b"-0", "Number"),
        (b"\xff", "Json"),
        (b'"\\ud800"', "Json"),
    ],
)
def test_bounded_lexical_checks_preserve_existing_decoder_rules(raw: bytes, reason: str) -> None:
    with pytest.raises(DecodeFailure, match=f"^{reason}$"):
        decoder(raw)
