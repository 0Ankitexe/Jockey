"""Offline setup-script checks with temporary command stubs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/setup.sh"


@pytest.fixture
def checkout(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "checkout"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(SOURCE, scripts / "setup.sh")
    (root / "dashboard").mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    commands = {
        "rustc": 'printf "rustc 1.98.1 (test)\\n"\n',
        "cargo": 'printf "cargo %s\\n" "$*" >> "$SETUP_TEST_LOG"\n',
        "cc": "exit 0\n",
        "python3.12": (
            'if [[ $* == "-m venv --help" ]]; then exit 0; fi\n'
            'if [[ $* == "-m ensurepip --version" ]]; then exit 0; fi\n'
            'mkdir -p "$3/bin"\n'
            "cat > \"$3/bin/python\" <<'STUB'\n"
            "#!/usr/bin/env bash\n"
            'printf \'pip %s\\n\' "$*" >> "$SETUP_TEST_LOG"\n'
            "STUB\n"
            'chmod +x "$3/bin/python"\n'
        ),
        "node": 'printf "v22.22.2\\n"\n',
        "npm": 'printf "npm %s\\n" "$*" >> "$SETUP_TEST_LOG"\n',
    }
    for name, body in commands.items():
        path = bin_dir / name
        path.write_text(f"#!/usr/bin/env bash\n{body}")
        path.chmod(0o755)

    log = tmp_path / "commands.log"
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["SETUP_TEST_LOG"] = str(log)
    return root, env


def run(root: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(root / "scripts/setup.sh"), *args],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_demo_fetches_and_builds_without_optional_install(
    checkout: tuple[Path, dict[str, str]],
) -> None:
    root, env = checkout
    result = run(root, env, "--demo")
    assert result.returncode == 0, result.stderr
    assert Path(env["SETUP_TEST_LOG"]).read_text().splitlines() == [
        "cargo fetch --locked",
        "cargo build --workspace --locked --offline",
    ]


def test_check_is_read_only_and_full_installs_optional_packages(
    checkout: tuple[Path, dict[str, str]],
) -> None:
    root, env = checkout
    log = Path(env["SETUP_TEST_LOG"])
    checked = run(root, env, "--check")
    assert checked.returncode == 0, checked.stderr
    assert not log.exists()

    installed = run(root, env, "--full")
    assert installed.returncode == 0, installed.stderr
    entries = log.read_text().splitlines()
    assert entries[:2] == ["cargo fetch --locked", "cargo build --workspace --locked --offline"]
    assert entries[2].startswith("pip -m pip install -e")
    assert entries[3] == "npm ci"


def test_invalid_arguments_and_old_tool_versions_stop_before_install(
    checkout: tuple[Path, dict[str, str]],
) -> None:
    root, env = checkout
    assert run(root, env, "--unknown").returncode == 2
    assert run(root, env, "--demo", "extra").returncode == 2
    bin_dir = Path(env["PATH"].split(os.pathsep)[0])
    (bin_dir / "rustc").write_text('#!/usr/bin/env bash\nprintf "rustc 1.98.0\\n"\n')
    assert "Rust 1.98.1 or newer" in run(root, env, "--demo").stderr
    (bin_dir / "rustc").write_text('#!/usr/bin/env bash\nprintf "rustc 1.98.1\\n"\n')
    (bin_dir / "node").write_text('#!/usr/bin/env bash\nprintf "v22.19.0\\n"\n')
    assert "Node.js 22.20+" in run(root, env, "--full").stderr
    assert not Path(env["SETUP_TEST_LOG"]).exists()
