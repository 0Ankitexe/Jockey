"""Check Cargo's resolved graph; consume metadata on stdin, never collect host data."""

import json
import sys
from typing import Any

REQUIRED = {"jocky-shared", "jocky-forensic", "jocky-ir", "jocky-language"}
PROTECTED = REQUIRED | {"jocky-codegen", "jocky-transforms"}
MAX_METADATA_BYTES = 8 * 1024 * 1024


class BoundaryError(ValueError):
    """Invalid or incomplete dependency evidence, never a successful check."""


def _invalid() -> BoundaryError:
    return BoundaryError("InvalidMetadata")


def _names(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 16384:
        raise _invalid()
    if any(not isinstance(item, str) or not item or len(item) > 4096 for item in value):
        raise _invalid()
    if len(set(value)) != len(value):
        raise _invalid()
    return value


def _graph(metadata: Any) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
    if not isinstance(metadata, dict):
        raise _invalid()
    packages, resolve = metadata.get("packages"), metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        raise _invalid()
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list) or max(len(packages), len(nodes)) > 16384:
        raise _invalid()
    names: dict[str, str] = {}
    edges: dict[str, list[str]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise _invalid()
        identity, name = package.get("id"), package.get("name")
        if not isinstance(identity, str) or not isinstance(name, str) or identity in names:
            raise _invalid()
        if not identity or not name or len(identity) > 4096 or len(name) > 256:
            raise _invalid()
        names[identity] = name
    for node in nodes:
        if not isinstance(node, dict):
            raise _invalid()
        identity = node.get("id")
        if not isinstance(identity, str) or identity not in names or identity in edges:
            raise _invalid()
        dependencies = _names(node.get("dependencies"))
        if any(dependency not in names for dependency in dependencies):
            raise _invalid()
        edges[identity] = dependencies
    members = _names(metadata.get("workspace_members"))
    if set(edges) != set(names) or any(member not in names for member in members):
        raise _invalid()
    workspace_names = [names[member] for member in members]
    if len(set(workspace_names)) != len(workspace_names):
        raise _invalid()
    if not (REQUIRED | {"jocky-native-linux"}).issubset(workspace_names):
        raise _invalid()
    return names, edges, members


def validate_metadata(metadata: Any) -> tuple[str, ...]:
    """Return deterministic forbidden-dependency findings; malformed evidence raises."""
    names, edges, members = _graph(metadata)
    failures: list[str] = []
    for root in members:
        if names[root] not in PROTECTED:
            continue
        pending, visited = [root], set()
        while pending:
            node = pending.pop()
            if node in visited:
                continue
            visited.add(node)
            if names[node].startswith("jocky-native-"):
                failures.append(f"{names[root]}:NativeDependency")
                break
            pending.extend(edges[node])
    return tuple(sorted(failures))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def main() -> int:
    """Exit 0 on proof, 1 on forbidden edges, 2 on malformed input or delivery failure."""
    try:
        if len(sys.argv) != 1:
            raise _invalid()
        raw = sys.stdin.buffer.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise _invalid()
        result = validate_metadata(json.loads(raw, object_pairs_hook=_unique_object))
        if result:
            sys.stderr.write("\n".join(result) + "\n")
            sys.stderr.flush()
            return 1
        sys.stdout.write("NativeBoundaryVerified\n")
        sys.stdout.flush()
        return 0
    except (BoundaryError, ValueError, TypeError, RecursionError, OSError):
        try:
            sys.stderr.write("InvalidMetadata\n")
            sys.stderr.flush()
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
