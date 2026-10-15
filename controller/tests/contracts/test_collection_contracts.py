"""Collection resource/schema agreement; no endpoint access or remote references."""

import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).resolve().parents[3]
PREFIX = "https://jocky.dev/schemas/"
RESOURCES = (
    "collection/v1/types",
    "collection/v1/endpoint-designation",
    "collection/v1/authorisation",
    "collection/v1/policy",
    "collection/v1/request",
    "collection/v1/indicator-set",
    "collection/v1/endpoint-observation",
    "collection/v1/report",
    "collection/v1/status",
    "collection/v1/worker",
    "collection/v1/lab-scenario",
    "v2/forensic-record",
    "v2/evidence-manifest",
)


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def validator(name: str) -> Draft202012Validator:
    schemas = {
        name: load_object(ROOT / "shared/schemas" / f"{name}.schema.json") for name in RESOURCES
    }
    # Registry's default retriever raises NoSuchResource; never enable dynamic retrieval.
    registry: Registry[Any] = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry, format_checker=FormatChecker())


@pytest.mark.parametrize("name", RESOURCES)
def test_resource_identity_and_meta_schema(name: str) -> None:
    schema = load_object(ROOT / "shared/schemas" / f"{name}.schema.json")
    assert schema["$id"] == f"{PREFIX}{name}.schema.json"
    Draft202012Validator.check_schema(schema)


def test_remote_retrieval_fails_closed() -> None:
    with pytest.raises(NoSuchResource):
        Registry().get_or_retrieve("https://example.invalid/schema")


def test_declared_resources_have_no_missing_or_external_references() -> None:
    known = {f"{PREFIX}{name}.schema.json" for name in RESOURCES}
    for name in RESOURCES:
        schema = load_object(ROOT / "shared/schemas" / f"{name}.schema.json")
        pending: list[Any] = [schema]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                if "$ref" in node:
                    ref = node["$ref"]
                    assert ref.startswith("#") or ref.split("#")[0] in known
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)
        # Constructing validators must not need an Internet resolver.
        validator(name)


def error_keywords(error: ValidationError) -> set[str]:
    found = {str(error.validator)}
    for child in error.context:
        found.update(error_keywords(child))
    return found


def test_fixture_manifest_covers_every_resource_and_expected_failure() -> None:
    cases = load_object(ROOT / "fixtures/collection-cases.json")["cases"]
    validators = {name: validator(name) for name in RESOURCES}
    valid_seen: set[str] = set()
    invalid_seen: set[str] = set()
    for case in cases:
        if case["stage"] != "schema":
            continue  # Strict decoder cases have their own independent test suite.
        name = case["schema"].removeprefix(PREFIX).removesuffix(".schema.json")
        instance = load_object(ROOT / case["file"])
        errors = list(validators[name].iter_errors(instance))
        if case["valid"]:
            assert not errors, case["file"]
            valid_seen.add(name)
        else:
            assert errors, case["file"]
            assert case["keyword"] in set().union(*(error_keywords(e) for e in errors)), case[
                "file"
            ]
            invalid_seen.add(name)
    assert valid_seen == invalid_seen == set(RESOURCES)


@pytest.mark.parametrize("name", ["forensic-record", "evidence-manifest"])
def test_local_evidence_and_task_bound_evidence_cannot_be_interchanged(name: str) -> None:
    old_schema = load_object(ROOT / "shared/schemas" / f"{name}.schema.json")
    old_validator = Draft202012Validator(old_schema, format_checker=FormatChecker())
    old_fixture = load_object(ROOT / "fixtures/valid" / f"{name}.json")
    new_fixture = load_object(ROOT / "fixtures/valid/collection" / f"{name}.json")
    assert not old_validator.is_valid(new_fixture)
    assert not validator(f"v2/{name}").is_valid(old_fixture)
