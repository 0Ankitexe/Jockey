"""Offline unit/integration/negative checks for the native dependency fence."""

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from ci.check_native_boundary import BoundaryError, validate_metadata

ROOT = Path(__file__).resolve().parents[1]


def metadata() -> dict[str, Any]:
    names = ["shared", "forensic", "ir", "language", "native-linux"]
    return {
        "packages": [{"id": name, "name": f"jocky-{name}"} for name in names],
        "workspace_members": names,
        "resolve": {
            "nodes": [
                {"id": "shared", "dependencies": []},
                {"id": "forensic", "dependencies": ["shared"]},
                {"id": "ir", "dependencies": ["forensic"]},
                {"id": "language", "dependencies": ["ir"]},
                {"id": "native-linux", "dependencies": ["forensic", "shared"]},
            ]
        },
    }


def test_valid_one_way_graph() -> None:
    value = metadata()
    before = copy.deepcopy(value)
    assert validate_metadata(value) == ()
    assert value == before


def test_transitive_dependency_on_native_rejects_all_affected_roots() -> None:
    value = metadata()
    value["resolve"]["nodes"][0]["dependencies"].append("native-linux")
    assert validate_metadata(value) == (
        "jocky-forensic:NativeDependency",
        "jocky-ir:NativeDependency",
        "jocky-language:NativeDependency",
        "jocky-shared:NativeDependency",
    )


def test_renamed_native_dependency_still_rejects() -> None:
    value = metadata()
    value["packages"][-1]["id"] = "renamed-native-id"
    value["workspace_members"][-1] = "renamed-native-id"
    value["resolve"]["nodes"][-1]["id"] = "renamed-native-id"
    value["resolve"]["nodes"][3]["dependencies"].append("renamed-native-id")
    assert validate_metadata(value) == ("jocky-language:NativeDependency",)


@pytest.mark.parametrize("part", ["packages", "workspace_members", "resolve"])
def test_missing_graph_section_fails(part: str) -> None:
    value = metadata()
    del value[part]
    with pytest.raises(BoundaryError, match="InvalidMetadata"):
        validate_metadata(value)


def test_missing_or_duplicate_node_fails() -> None:
    value = metadata()
    value["resolve"]["nodes"].append(value["resolve"]["nodes"][0])
    with pytest.raises(BoundaryError):
        validate_metadata(value)
    value = metadata()
    value["resolve"]["nodes"][0]["dependencies"].append("missing")
    with pytest.raises(BoundaryError):
        validate_metadata(value)


def test_unrelated_cycles_terminate() -> None:
    value = metadata()
    value["resolve"]["nodes"][0]["dependencies"].append("forensic")
    assert validate_metadata(value) == ()


@pytest.mark.parametrize("missing", ["shared", "native-linux"])
def test_missing_required_workspace_package_fails(missing: str) -> None:
    value = metadata()
    value["workspace_members"].remove(missing)
    with pytest.raises(BoundaryError):
        validate_metadata(value)


@pytest.mark.parametrize("invalid", [b"not json", b"[]", b'{"packages":[],"packages":[]}'])
def test_cli_rejects_invalid_metadata_without_echo(invalid: bytes) -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "ci/check_native_boundary.py")],
        input=invalid,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"InvalidMetadata\n"


def test_cli_accepts_valid_graph_and_rejects_native_edge() -> None:
    value = metadata()
    for expected in (0, 1):
        result = subprocess.run(
            [sys.executable, str(ROOT / "ci/check_native_boundary.py")],
            input=json.dumps(value).encode(),
            capture_output=True,
            check=False,
        )
        assert result.returncode == expected
        if expected == 0:
            assert result.stdout == b"NativeBoundaryVerified\n"
            assert result.stderr == b""
        else:
            assert result.stdout == b""
            assert result.stderr == b"jocky-language:NativeDependency\n"
        value["resolve"]["nodes"][3]["dependencies"].append("native-linux")
