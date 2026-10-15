# T148 Python regression — 2026-10-16

Local Python 3.12.13, repository `controller/.venv`; no live scenario invoked.
From the repository root:

```sh
controller/.venv/bin/python -m ruff format --check --config controller/pyproject.toml controller ci tests/lab tests/test_native_boundary.py
controller/.venv/bin/python -m ruff check --config controller/pyproject.toml controller ci tests/lab tests/test_native_boundary.py
controller/.venv/bin/python -m mypy --config-file controller/pyproject.toml controller
PYTHONPATH=. controller/.venv/bin/python -m pytest -q controller/tests tests/lab tests/test_native_boundary.py
```

Result: Ruff format 53 files, lint clean; configured mypy 26 source files clean;
pytest **185 passed**. The 60 lab-harness U/I/N cases also passed independently.
Two CI Python files were formatted to satisfy the current Ruff formatter before
the final clean run. This is local offline evidence, not hosted CI.
