"""Independent LAB-SMALL limits, raw retention and exact summary arithmetic."""

from __future__ import annotations

import json
import math
import os
import signal
import stat
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median
from typing import Any, Self

MAX_MS = 60_000
MAX_RSS_BYTES = 268_435_456
MAX_REPORT_BYTES = 10_485_760
MAX_RECORDS = 10_000


@dataclass(frozen=True)
class ProcessPeak:
    pid: int
    start_ticks: str
    peak_rss_bytes: int


@dataclass(frozen=True)
class Invocation:
    elapsed_ms: int
    exit_code: int | None
    parent: ProcessPeak
    workers: tuple[ProcessPeak, ...]
    workers_sequential: bool
    timed_out: bool
    stdout_path: Path
    stderr_path: Path


def _proc_identity(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2 :].split()[19]


def _vm_hwm_bytes(pid: int) -> int:
    raw = Path(f"/proc/{pid}/status").read_text()
    for line in raw.splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) * 1024
    raise ValueError("process peak RSS unavailable")


def capture_invocation(
    command: list[str],
    output_root: Path,
    run_id: str,
    *,
    pass_fds: tuple[int, ...] = (),
    timeout_seconds: float = 65,
) -> Invocation:
    """Time config through exit and reap the exact direct child with wait4.

    Worker VmHWM is sampled from kernel /proc while each owned worker exists.
    The trace is explicitly marked incomplete if a worker cannot be identified.
    """
    if not command or not run_id or "/" in run_id or timeout_seconds <= 0:
        raise ValueError("invalid invocation")
    root = output_root.lstat()
    if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid() or root.st_mode & 0o077:
        raise ValueError("unsafe measurement root")
    stdout_path = output_root / f"{run_id}.stdout"
    stderr_path = output_root / f"{run_id}.stderr"
    begin = time.monotonic_ns()
    out_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        err_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except Exception:
        os.close(out_fd)
        raise
    worker_peaks: dict[tuple[int, str], int] = {}
    simultaneous = False
    timed_out = False
    with os.fdopen(out_fd, "wb") as stdout, os.fdopen(err_fd, "wb") as stderr:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            pass_fds=pass_fds,
            start_new_session=True,
            close_fds=True,
        )
        parent_start = _proc_identity(child.pid)
        deadline = time.monotonic() + timeout_seconds
        status = 0
        while True:
            try:
                children_raw = Path(f"/proc/{child.pid}/task/{child.pid}/children").read_text()
                child_pids = [int(value) for value in children_raw.split()]
                simultaneous |= len(child_pids) > 1
                for pid in child_pids:
                    try:
                        identity = _proc_identity(pid)
                        peak = _vm_hwm_bytes(pid)
                    except (FileNotFoundError, ProcessLookupError, ValueError):
                        continue
                    key = (pid, identity)
                    worker_peaks[key] = max(worker_peaks.get(key, 0), peak)
            except (FileNotFoundError, ProcessLookupError):
                pass
            finished_pid, status, usage = os.wait4(child.pid, os.WNOHANG)
            if finished_pid:
                break
            if time.monotonic() >= deadline:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                grace_deadline = time.monotonic() + 1.0
                while time.monotonic() < grace_deadline:
                    finished_pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                    if finished_pid:
                        break
                    time.sleep(0.01)
                if not finished_pid:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finished_pid, status, usage = os.wait4(child.pid, 0)
                break
            time.sleep(0.001)
        child.returncode = os.waitstatus_to_exitcode(status)
        if finished_pid != child.pid or parent_start == "":
            raise ValueError("wait4 identity mismatch")
        elapsed_ms = math.ceil((time.monotonic_ns() - begin) / 1_000_000)
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
        return Invocation(
            elapsed_ms=elapsed_ms,
            exit_code=child.returncode,
            parent=ProcessPeak(
                child.pid,
                parent_start,
                wait4_maxrss_bytes(usage.ru_maxrss, platform="linux"),
            ),
            workers=tuple(
                ProcessPeak(pid, start, peak) for (pid, start), peak in sorted(worker_peaks.items())
            ),
            workers_sequential=not simultaneous,
            timed_out=timed_out,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


def wait4_maxrss_bytes(ru_maxrss: int, *, platform: str) -> int:
    """Linux wait4 reports KiB. Other platforms need a separate reviewed rule."""
    if platform != "linux" or not isinstance(ru_maxrss, int) or ru_maxrss < 0:
        raise ValueError("unsupported or invalid wait4 peak RSS")
    return ru_maxrss * 1024


def aggregate_rss_bytes(
    parent_peak: int, worker_peaks: tuple[int, ...], *, sequential: bool
) -> int:
    if not sequential or parent_peak < 0 or any(peak < 0 for peak in worker_peaks):
        raise ValueError("worker identity or non-overlap is unverified")
    return parent_peak + max(worker_peaks, default=0)


@dataclass(frozen=True)
class Sample:
    run_id: str
    classification: str
    elapsed_ms: int
    parent_peak_rss_bytes: int
    worker_peaks_bytes: tuple[int, ...]
    workers_sequential: bool
    output_bytes: int
    accepted_records: int
    source_bytes: int
    exit_code: int | None
    seeded_facts_ok: bool
    report_status: str | None
    failure: str | None
    collection_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    report_sha256: str | None = None
    report_path: str | None = None
    worker_trace: tuple[ProcessPeak, ...] = ()
    parent_wait4: ProcessPeak | None = None
    oracle: dict[str, Any] | None = None
    input_sha256: dict[str, str] | None = None
    omitted_known: int = 0
    omitted_unknown: bool = False
    errors: int = 0
    stop_reason: str | None = None
    worker_cleanup: str | None = None
    inventory_id: str = ""
    binary_sha256: str = ""
    profile: str = "lab-small-v1"
    expected_owned_workers: int | None = None

    @property
    def aggregate_peak_rss_bytes(self) -> int:
        return aggregate_rss_bytes(
            self.parent_peak_rss_bytes,
            self.worker_peaks_bytes,
            sequential=self.workers_sequential,
        )


def validate_sample(sample: Sample) -> None:
    if (
        not sample.run_id
        or sample.classification not in ("cold", "warm")
        or sample.elapsed_ms < 0
        or sample.output_bytes < 0
        or sample.accepted_records < 0
        or sample.source_bytes < 0
    ):
        raise ValueError("invalid raw sample")
    if sample.elapsed_ms > MAX_MS:
        raise ValueError("elapsed ceiling exceeded")
    if sample.aggregate_peak_rss_bytes > MAX_RSS_BYTES:
        raise ValueError("aggregate RSS ceiling exceeded")
    if sample.output_bytes > MAX_REPORT_BYTES:
        raise ValueError("report byte ceiling exceeded")
    if sample.accepted_records > MAX_RECORDS:
        raise ValueError("accepted record ceiling exceeded")
    if not sample.seeded_facts_ok:
        raise ValueError("seeded fact missing")
    if sample.omitted_unknown or sample.worker_cleanup != "complete":
        raise ValueError("unknown omission or incomplete owned-worker cleanup")
    if sample.expected_owned_workers is not None and (
        len(sample.worker_trace) != sample.expected_owned_workers
        or len({(worker.pid, worker.start_ticks) for worker in sample.worker_trace})
        != sample.expected_owned_workers
    ):
        raise ValueError("owned-worker RSS trace is incomplete")
    if (
        sample.exit_code not in (0, 2)
        or sample.report_status not in ("complete", "partial")
        or sample.failure is not None
    ):
        raise ValueError("collector failed or did not publish verified evidence")


def _statistics(values: list[int]) -> dict[str, int | float]:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("missing samples")
    return {
        "median_ms": median(ordered),
        "p95_ms": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "max_ms": ordered[-1],
    }


def _raw_row(item: Sample) -> dict[str, Any]:
    row = asdict(item)
    try:
        row["aggregate_peak_rss_bytes"] = item.aggregate_peak_rss_bytes
    except ValueError:
        row["aggregate_peak_rss_bytes"] = None
    return row


def summarize(samples: list[Sample], path: Path) -> dict[str, Any]:
    """Write every raw attempt once; a failing sample remains in the summary."""
    if (
        len(samples) != 11
        or [item.classification for item in samples] != ["cold", *["warm"] * 10]
        or len({item.run_id for item in samples}) != 11
    ):
        raise ValueError("one cold and ten distinct warm samples required")
    failures: list[dict[str, str]] = []
    for item in samples:
        try:
            validate_sample(item)
        except ValueError as error:
            failures.append({"run_id": item.run_id, "reason": str(error)})
    rows = [_raw_row(item) for item in samples]
    # Exclusive creation preserves previous evidence on retry or collision.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as opened:
        for row in rows:
            opened.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        opened.flush()
        os.fsync(opened.fileno())
    return {
        "profile": "lab-small-v1",
        "raw_samples": 11,
        "passed": not failures,
        "failures": failures,
        "cold": {"elapsed_ms": samples[0].elapsed_ms},
        "warm": _statistics([item.elapsed_ms for item in samples[1:]]),
        "maximum_aggregate_peak_rss_bytes": max(
            (row["aggregate_peak_rss_bytes"] or 0) for row in rows
        ),
        "maximum_output_bytes": max(item.output_bytes for item in samples),
        "maximum_accepted_records": max(item.accepted_records for item in samples),
    }


class SampleRecorder:
    """Exclusive append-only raw evidence, fsynced after every attempt."""

    def __init__(self, path: Path) -> None:
        self.path = path
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._file = os.fdopen(descriptor, "w", encoding="utf-8")
        self.samples: list[Sample] = []

    def append(self, sample: Sample) -> None:
        if any(previous.run_id == sample.run_id for previous in self.samples):
            raise ValueError("duplicate raw sample ID")
        row = _raw_row(sample)
        self._file.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())
        self.samples.append(sample)

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def summarize_recorded(samples: list[Sample]) -> dict[str, Any]:
    """Summarize an already fsynced eleven-line campaign without rewriting it."""
    # The temporary path is never used; validation/statistics mirror summarize.
    if (
        len(samples) != 11
        or [item.classification for item in samples] != ["cold", *["warm"] * 10]
        or len({item.run_id for item in samples}) != 11
    ):
        raise ValueError("one cold and ten distinct warm samples required")
    failures: list[dict[str, str]] = []
    for item in samples:
        try:
            validate_sample(item)
        except ValueError as error:
            failures.append({"run_id": item.run_id, "reason": str(error)})
    return {
        "profile": "lab-small-v1",
        "raw_samples": len(samples),
        "passed": not failures,
        "failures": failures,
        "cold": {"elapsed_ms": samples[0].elapsed_ms},
        "warm": _statistics([item.elapsed_ms for item in samples[1:]]),
        "maximum_aggregate_peak_rss_bytes": max(
            (_raw_row(item)["aggregate_peak_rss_bytes"] or 0) for item in samples
        ),
        "maximum_output_bytes": max(item.output_bytes for item in samples),
        "maximum_accepted_records": max(item.accepted_records for item in samples),
    }
