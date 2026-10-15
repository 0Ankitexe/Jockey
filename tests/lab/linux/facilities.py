"""Inert, owned facility sample preparation for an approved guest scenario.

No function in this module reads a host facility or changes a system service.
The caller supplies the already admitted action set and an owned ledger.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .owned_objects import OwnedLedger

_TOKEN = re.compile(r"[a-z0-9][a-z0-9-]{0,39}\Z")


@dataclass(frozen=True)
class FacilitySamples:
    startup: tuple[Path, ...]
    syslog: Path
    auth: Path
    journal_markers: tuple[str, ...]
    expected_text_markers: tuple[str, ...]


def _markers(run_id: str, backend: str) -> tuple[str, ...]:
    return tuple(f"jocky-{run_id}-{backend}-{index:02}" for index in range(10))


def prepare_owned_samples(
    ledger: OwnedLedger,
    allowed_actions: Iterable[str],
    run_id: str,
    at: datetime,
) -> FacilitySamples:
    """Create only ledger tracked direct children under the approved scratch root."""
    actions = frozenset(allowed_actions)
    if not {"create_sample_files", "emit_benign_log_markers"}.issubset(actions):
        raise ValueError("facility sample actions are not approved")
    if not _TOKEN.fullmatch(run_id) or at.tzinfo != UTC:
        raise ValueError("invalid facility marker identity or UTC time")
    timestamp = at.isoformat(timespec="seconds").replace("+00:00", "Z")
    startup = (
        ledger.add_file(
            "jocky-demo.service",
            b"[Unit]\nDescription=JOCKY approved demo\n[Service]\nExecStart=/usr/bin/true\n",
        ),
        ledger.add_file(
            "jocky-demo.timer",
            b"[Unit]\nDescription=JOCKY approved timer\n"
            b"[Timer]\nUnit=jocky-demo.service\nOnBootSec=1min\n",
        ),
        ledger.add_file("jocky-demo.cron", b"* * * * * /usr/bin/true\n"),
        ledger.add_file(
            "jocky-demo.desktop",
            b"[Desktop Entry]\nType=Application\nName=JOCKY approved demo\nExec=/usr/bin/true\n",
        ),
    )
    syslog_markers = _markers(run_id, "syslog")
    auth_markers = _markers(run_id, "auth")
    journal_markers = _markers(run_id, "journal")

    def log_lines(markers: tuple[str, ...]) -> bytes:
        return "".join(
            f"<14>1 {timestamp} lab jocky 1 ID47 - {marker}\n" for marker in markers
        ).encode("ascii")

    syslog = ledger.add_file("jocky-demo-syslog.log", log_lines(syslog_markers))
    auth = ledger.add_file("jocky-demo-auth.log", log_lines(auth_markers))
    return FacilitySamples(
        startup=startup,
        syslog=syslog,
        auth=auth,
        journal_markers=journal_markers,
        expected_text_markers=syslog_markers + auth_markers,
    )


def emit_approved_journal_markers(
    samples: FacilitySamples,
    allowed_actions: Iterable[str],
    emit: Callable[[str], None],
) -> None:
    """Explicit callback boundary; a guest runner supplies its approved emitter."""
    if "emit_benign_log_markers" not in frozenset(allowed_actions):
        raise ValueError("journal marker action is not approved")
    if len(samples.journal_markers) != 10 or len(set(samples.journal_markers)) != 10:
        raise ValueError("invalid journal marker set")
    for marker in samples.journal_markers:
        emit(marker)
