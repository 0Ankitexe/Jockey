#!/usr/bin/env bash
# Prepare a cloned checkout for the offline demo or the optional local UI.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:---demo}

if (($# > 1)) || [[ $mode != --demo && $mode != --full && $mode != --check ]]; then
  printf 'Usage: bash scripts/setup.sh [--demo|--full|--check]\n' >&2
  exit 2
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing %s. Install it, then rerun this script.\n' "$2" >&2
    exit 2
  fi
}

version_at_least() {
  local major=$1 minor=$2 patch=$3 minimum_major=$4 minimum_minor=$5 minimum_patch=$6
  (( major > minimum_major ||
     (major == minimum_major && minor > minimum_minor) ||
     (major == minimum_major && minor == minimum_minor && patch >= minimum_patch) ))
}

need rustc 'Rust 1.98.1 or newer'
need cargo Cargo
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
  printf 'Missing a C compiler (cc, gcc or clang).\n' >&2
  exit 2
fi

rust_version=$(rustc --version)
if [[ ! $rust_version =~ ^rustc[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+) ]] ||
   ! version_at_least "${BASH_REMATCH[1]:-0}" "${BASH_REMATCH[2]:-0}" "${BASH_REMATCH[3]:-0}" 1 98 1; then
  printf 'Rust 1.98.1 or newer is required; found: %s\n' "$rust_version" >&2
  exit 2
fi

if [[ $mode == --full || $mode == --check ]]; then
  need python3.12 'Python 3.12 with venv and pip'
  need node 'Node.js 22.20 or newer on the 22.x line'
  need npm npm
  node_version=$(node --version)
  if [[ ! $node_version =~ ^v22\.([0-9]+)\.([0-9]+)$ ]] ||
     ! version_at_least 22 "${BASH_REMATCH[1]:-0}" "${BASH_REMATCH[2]:-0}" 22 20 0; then
    printf 'Node.js 22.20+ on the 22.x line is required; found: %s\n' "$node_version" >&2
    exit 2
  fi
  if ! python3.12 -m venv --help >/dev/null 2>&1; then
    printf 'Python 3.12 venv is unavailable. Install the Python 3.12 venv package.\n' >&2
    exit 2
  fi
  if ! python3.12 -m ensurepip --version >/dev/null 2>&1; then
    printf 'Python 3.12 cannot install pip into a new virtual environment.\n' >&2
    exit 2
  fi
fi

printf 'Prerequisites OK for %s.\n' "$mode"
if [[ $mode == --check ]]; then
  exit 0
fi

cd "$root"
cargo fetch --locked
cargo build --workspace --locked --offline

if [[ $mode == --full ]]; then
  python3.12 -m venv controller/.venv
  controller/.venv/bin/python -m pip install -e './controller[dev]'
  (cd dashboard && npm ci)
fi

printf 'Setup complete. Run the commands in README.md to start the demo.\n'
