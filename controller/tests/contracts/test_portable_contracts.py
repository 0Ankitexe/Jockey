"""Offline, closed portable compiler contract compatibility cases."""

import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).resolve().parents[3]
NAMES = (
    "ast-v1",
    "profile-ast",
    "compiler-types",
    "module-registry",
    "check-report",
    "ir",
    "fixture-values",
    "portable-ast",
    "compiler-types-v2",
    "module-registry-v2",
    "check-report-v2",
    "ir-v2",
)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def validators() -> dict[str, Draft202012Validator]:
    schemas = {
        name: load(ROOT / "shared/compiler-contracts" / f"{name}.schema.json") for name in NAMES
    }
    registry: Registry[Any] = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    return {
        name: Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        for name, schema in schemas.items()
    }


def test_portable_cases_and_legacy_rejection() -> None:
    all_validators = validators()
    manifest = load(ROOT / "fixtures/compiler-v2-cases.json")
    cases = manifest["cases"]
    assert len(cases) >= 20
    for case in cases:
        instance = load(ROOT / case["file"])
        errors = list(all_validators[case["schema"]].iter_errors(instance))
        if case["valid"]:
            assert not errors, (case["file"], errors)
        else:
            assert errors, case["file"]
            assert any(
                case["reason"] in str(error) or case["reason"] in str(error.schema_path)
                for error in errors
            ), (case["file"], errors)
    for name, old, file in (
        ("portable-ast", "profile-ast", "portable-ast-linux"),
        ("module-registry-v2", "module-registry", "module-registry-v2-portable"),
        ("check-report-v2", "check-report", "check-report-v2-valid"),
        ("ir-v2", "ir", "ir-v2-structural"),
    ):
        instance = load(ROOT / "fixtures/valid/compiler-v2" / f"{file}.json")
        assert all_validators[name].is_valid(instance)
        assert not all_validators[old].is_valid(instance)
    for old, fixture in (
        ("profile-ast", "language/tests/fixtures/profile/valid.ast.json"),
        ("module-registry", "forensic-lib/contracts/catalogue.v1.json"),
        ("check-report", "language/tests/fixtures/reports/valid/valid.json"),
        ("ir", "language/tests/fixtures/ir/golden/branches.ir.json"),
    ):
        assert all_validators[old].is_valid(load(ROOT / fixture)), fixture
    assert not all_validators["compiler-types"].is_valid({"kind": "named", "name": "indicator_set"})


def test_portable_references_are_local_and_closed() -> None:
    schemas = [load(ROOT / "shared/compiler-contracts" / f"{name}.schema.json") for name in NAMES]
    known = {schema["$id"] for schema in schemas}
    pending: list[Any] = schemas.copy()
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                assert ref.split("#", 1)[0] in known
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    with pytest.raises(NoSuchResource):
        Registry().get_or_retrieve("https://example.invalid/schema")
