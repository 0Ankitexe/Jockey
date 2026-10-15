"""Independent expectations captured from harness-owned input before invocation."""

from __future__ import annotations

import hashlib
import os
import socket
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileExpectation:
    label: str
    size_bytes: int
    sha256: str
    root_id: str | None = None


def file_expectation(label: str, content: bytes, root_id: str | None = None) -> FileExpectation:
    if not label or len(content) > 16_777_216:
        raise ValueError("invalid sample")
    return FileExpectation(label, len(content), hashlib.sha256(content).hexdigest(), root_id)


@dataclass(frozen=True)
class ProcessExpectation:
    pid: int
    boot_id: str
    start_ticks: str


def process_expectation(pid: int) -> ProcessExpectation:
    # /proc stat's command field is parenthesised and may contain spaces.
    stat = Path(f"/proc/{pid}/stat").read_text()
    fields = stat[stat.rfind(")") + 2 :].split()
    return ProcessExpectation(
        pid, Path("/proc/sys/kernel/random/boot_id").read_text().strip(), fields[19]
    )


@dataclass(frozen=True)
class ConnectionExpectation:
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    socket_inode: str


def connection_expectation(sock: socket.socket) -> ConnectionExpectation:
    local = sock.getsockname()
    remote = sock.getpeername()
    return ConnectionExpectation(
        local[0], local[1], remote[0], remote[1], str(os.fstat(sock.fileno()).st_ino)
    )
