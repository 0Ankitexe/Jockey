"""Exact identity ledger for harness-created files; no recursive cleanup."""

from __future__ import annotations

import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .approval import loopback_only
from .ground_truth import (
    ConnectionExpectation,
    ProcessExpectation,
    connection_expectation,
    process_expectation,
)


def _identity(path: Path) -> tuple[int, int]:
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode):
        raise ValueError("owned object replaced")
    return value.st_dev, value.st_ino


@dataclass
class OwnedLedger:
    directory: Path
    directory_id: tuple[int, int]
    files: dict[str, tuple[int, int]] = field(default_factory=dict)
    children: list[tuple[subprocess.Popen[bytes], ProcessExpectation]] = field(default_factory=list)
    child_pidfds: dict[int, int] = field(default_factory=dict)
    sockets: list[socket.socket] = field(default_factory=list)

    @classmethod
    def create(cls, root: Path) -> OwnedLedger:
        value = root.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or value.st_mode & 0o077:
            raise ValueError("unsafe owned root")
        directory = Path(tempfile.mkdtemp(prefix="jocky-checkpoint-", dir=root))
        return cls(directory, _identity(directory))

    def add_file(self, name: str, content: bytes) -> Path:
        if name in ("", ".", "..") or "/" in name or "\0" in name or len(content) > 16_777_216:
            raise ValueError("invalid owned file")
        if _identity(self.directory) != self.directory_id:
            raise ValueError("owned directory replaced")
        descriptor = os.open(
            self.directory / name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as opened:
            opened.write(content)
            opened.flush()
            os.fsync(opened.fileno())
        path = self.directory / name
        self.files[name] = _identity(path)
        return path

    def mutate_file(self, name: str, content: bytes) -> None:
        if len(content) > 16_777_216 or name not in self.files:
            raise ValueError("untracked owned file")
        if _identity(self.directory) != self.directory_id:
            raise ValueError("owned directory replaced")
        path = self.directory / name
        if _identity(path) != self.files[name] or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("owned file replaced")
        descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "wb") as opened:
            info = os.fstat(opened.fileno())
            if (info.st_dev, info.st_ino) != self.files[name] or not stat.S_ISREG(info.st_mode):
                raise ValueError("owned file replaced")
            opened.write(content)
            opened.truncate()
            opened.flush()
            os.fsync(opened.fileno())

    def remove_file(self, name: str) -> None:
        if name not in self.files or _identity(self.directory) != self.directory_id:
            raise ValueError("untracked owned file")
        path = self.directory / name
        if _identity(path) != self.files[name] or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("owned file replaced")
        path.unlink()
        del self.files[name]

    def add_process(self) -> ProcessExpectation:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        pidfd = os.pidfd_open(child.pid)
        try:
            expected = process_expectation(child.pid)
        except Exception:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            child.wait(timeout=5)
            os.close(pidfd)
            raise
        self.children.append((child, expected))
        self.child_pidfds[child.pid] = pidfd
        return expected

    def cancel_child(self, expected: ProcessExpectation) -> None:
        matches = [(child, recorded) for child, recorded in self.children if recorded == expected]
        if len(matches) != 1:
            raise ValueError("untracked owned process")
        child, recorded = matches[0]
        if child.poll() is not None:
            raise ValueError("owned process already exited")
        if process_expectation(child.pid) != recorded:
            raise ValueError("owned process identity replaced")
        signal.pidfd_send_signal(self.child_pidfds[child.pid], signal.SIGTERM)
        child.wait(timeout=5)

    def add_loopback_connection(
        self, address: str = "127.0.0.1", *, client_address: str | None = None
    ) -> ConnectionExpectation:
        if not loopback_only(address) or not (address == "::1" or address.startswith("127.0.0.")):
            raise ValueError("non-loopback address")
        if client_address is not None and (
            not loopback_only(client_address) or (":" in address) != (":" in client_address)
        ):
            raise ValueError("non-loopback or mixed-family client")
        family = socket.AF_INET6 if address == "::1" else socket.AF_INET
        server = socket.socket(family, socket.SOCK_STREAM)
        client = socket.socket(family, socket.SOCK_STREAM)
        try:
            server.bind((address, 0))
            server.listen(1)
            if client_address is not None:
                client.bind((client_address, 0))
            client.connect(server.getsockname())
            accepted, _ = server.accept()
            expected = connection_expectation(client)
            self.sockets.extend((server, client, accepted))
            return expected
        except Exception:
            server.close()
            client.close()
            raise

    def cleanup(self) -> None:
        for sock in self.sockets:
            sock.close()
        self.sockets.clear()
        for child, child_expected in self.children:
            if child.poll() is None:
                if process_expectation(child.pid) != child_expected:
                    raise ValueError("owned process identity replaced")
                signal.pidfd_send_signal(self.child_pidfds[child.pid], signal.SIGTERM)
                child.wait(timeout=5)
            os.close(self.child_pidfds.pop(child.pid))
        self.children.clear()
        if _identity(self.directory) != self.directory_id:
            raise ValueError("owned directory replaced")
        if {entry.name for entry in self.directory.iterdir()} != set(self.files):
            raise ValueError("untracked or missing owned object")
        for name, file_expected in self.files.items():
            path = self.directory / name
            if _identity(path) != file_expected or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("owned file replaced")
            path.unlink()
        self.directory.rmdir()
