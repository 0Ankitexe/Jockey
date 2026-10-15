"""Unit, integration and negative checks for inert owned facility samples."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from .facilities import emit_approved_journal_markers, prepare_owned_samples
from .owned_objects import OwnedLedger

_ACTIONS = ("create_sample_files", "emit_benign_log_markers")


def test_owned_startup_and_ten_markers_per_log_backend(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    try:
        samples = prepare_owned_samples(
            ledger, _ACTIONS, "run-one", datetime(2020, 1, 1, tzinfo=UTC)
        )
        assert {path.suffix for path in samples.startup} == {
            ".service",
            ".timer",
            ".cron",
            ".desktop",
        }
        for path, backend in ((samples.syslog, "syslog"), (samples.auth, "auth")):
            lines = path.read_text().splitlines()
            assert len(lines) == 10
            assert all(line.startswith("<14>1 2020-01-01T00:00:00Z ") for line in lines)
            assert all(f"jocky-run-one-{backend}-" in line for line in lines)
        observed: list[str] = []
        emit_approved_journal_markers(samples, _ACTIONS, observed.append)
        assert observed == list(samples.journal_markers)
        assert len(set(observed)) == 10
        assert set(ledger.files) == {
            path.name for path in (*samples.startup, samples.syslog, samples.auth)
        }
    finally:
        ledger.cleanup()


def test_no_action_invalid_marker_or_time_creates_nothing(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    try:
        for actions, token, at in (
            (("create_sample_files",), "run-one", datetime.now(UTC)),
            (_ACTIONS, "../escape", datetime.now(UTC)),
            (_ACTIONS, "run-one", datetime(2020, 1, 1)),  # noqa: DTZ001
        ):
            with pytest.raises(ValueError):
                prepare_owned_samples(ledger, actions, token, at)
            assert not ledger.files
    finally:
        ledger.cleanup()


def test_journal_emission_requires_explicit_action(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    ledger = OwnedLedger.create(root)
    try:
        samples = prepare_owned_samples(ledger, _ACTIONS, "run-one", datetime.now(UTC))
        observed: list[str] = []
        with pytest.raises(ValueError):
            emit_approved_journal_markers(samples, (), observed.append)
        assert observed == []
    finally:
        ledger.cleanup()
