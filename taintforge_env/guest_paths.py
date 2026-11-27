"""Resolve guest pathname arguments from observed cwd and descriptor lifetimes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .strace_parser import SyscallEvent


_AT = {
    "openat",
    "newfstatat",
    "fstatat64",
    "faccessat",
    "faccessat2",
    "mkdirat",
    "unlinkat",
    "readlinkat",
    "execveat",
}
_CWD = {
    "open",
    "creat",
    "stat",
    "stat64",
    "lstat",
    "lstat64",
    "access",
    "mkdir",
    "unlink",
    "readlink",
    "rmdir",
    "chdir",
    "execve",
}
_PATH_CALLS = _CWD | _AT
_STRING = r'"(?:[^"\\]|\\.)*"'
_PATH_ARG = re.compile(r"^\s*(?P<name>" + _STRING + r")\s*(?:,\s*|$)")
_AT_ARG = re.compile(r"^\s*(?P<fd>[^,]+),\s*(?P<name>" + _STRING + r")\s*(?:,\s*|$)")
_FD = re.compile(r"(-?[0-9]{1,20}|0[xX][a-fA-F0-9]{1,16})(?:<[^<>]+>)?\Z")
_READ_FLAGS = {
    "O_RDONLY",
    "O_CLOEXEC",
    "O_LARGEFILE",
    "O_NONBLOCK",
    "O_NOCTTY",
    "O_NOFOLLOW",
    "O_SYNC",
    "O_DSYNC",
    "O_DIRECT",
    "O_NOATIME",
    "O_ASYNC",
}


def _descriptor(argument: str) -> int | None:
    token = argument.strip()
    if token == "AT_FDCWD" or re.fullmatch(r"AT_FDCWD<[^<>]*>", token):
        return -100
    match = _FD.fullmatch(token)
    if not match:
        return None
    value = int(match[1], 16 if match[1].lower().startswith("0x") else 10)
    if value in (0xFFFFFF9C, 0xFFFFFFFFFFFFFF9C):
        return -100
    return value


def open_flags(syscall: str, args: str) -> set[str]:
    if syscall == "creat":
        return {"O_CREAT", "O_WRONLY", "O_TRUNC"}
    if syscall not in {"open", "openat"}:
        return set()
    match = (_AT_ARG if syscall == "openat" else _PATH_ARG).match(args)
    if not match:
        return set()
    return {flag.strip() for flag in args[match.end() :].split(",", 1)[0].split("|")}


def regular_read_flags(flags: set[str]) -> bool:
    return "O_RDONLY" in flags and flags <= _READ_FLAGS


def _join(base: str | None, name: str) -> str | None:
    if not name or len(name) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        return None
    path = PurePosixPath(name)
    if ".." in path.parts or name.startswith("//"):
        return None
    if path.is_absolute():
        return str(path)
    if base is None:
        return None
    full = str(PurePosixPath(base, path))
    return full if len(full) <= 4096 else None


@dataclass
class _Process:
    cwd: str | None
    descriptors: dict[int, str] = field(default_factory=dict)


class GuestPaths:
    def __init__(self, initial_cwd: str | None = None):
        if initial_cwd is not None and (_join(None, initial_cwd) != initial_cwd):
            raise ValueError("initial guest cwd must be a normalized absolute guest path")
        self.initial = initial_cwd
        self.processes: dict[int | None, _Process] = {}
        self.incomplete = False

    def lose_context(self):
        # Incomplete or shared process state can hide an fd replacement or chdir.
        self.incomplete = True
        self.processes.clear()

    def exit(self, pid: int | None):
        self.processes.pop(pid, None)
        self.initial = None

    def observe(self, event: SyscallEvent):
        if event.execution_context != "guest":
            return
        if event.event == "process_exit":
            self.exit(event.pid)
            return
        if event.event != "syscall":
            return
        if self.incomplete:
            if event.path:
                event.path_resolution = "unresolved"
            return
        pid, call, args = event.pid, event.syscall, event.args
        if pid not in self.processes:
            if len(self.processes) >= 1024:
                self.lose_context()
                if event.path:
                    event.path_resolution = "unresolved"
                return
            self.processes[pid] = _Process(self.initial)
            self.initial = None
        state = self.processes[pid]
        first = args.split(",", 1)[0]
        fd = _descriptor(first)
        name = event.path
        resolved = None
        if name and call in _PATH_CALLS:
            token = (_AT_ARG if call in _AT else _PATH_ARG).match(args)
            if token:
                use_fd = call in _AT and fd != -100
                base = state.descriptors.get(fd) if use_fd else state.cwd
                resolved = _join(base, name)
                if resolved and not name.startswith("/"):
                    event.resolved_path = resolved
                    event.path_resolution = f"dirfd:{fd}" if use_fd else "cwd"
        if name and not name.startswith("/") and not resolved:
            event.path_resolution = "unresolved"
        result = event.return_value
        if event.success is not True:
            # Linux may release the descriptor even when close reports an error.
            if call == "close":
                state.descriptors.pop(fd, None)
            elif event.success is None and call in {
                "chdir",
                "fchdir",
                "dup2",
                "dup3",
                "close_range",
                "execve",
                "execveat",
                "fork",
                "vfork",
                "clone",
                "clone3",
                "chroot",
                "pivot_root",
                "setns",
                "rename",
                "renameat",
                "renameat2",
            }:
                self.lose_context()
            return
        if call in {"chdir", "fchdir"}:
            state.cwd = resolved if call == "chdir" else state.descriptors.get(fd)
        elif call in {"open", "openat", "creat", "dup", "dup2", "dup3", "fcntl", "fcntl64"}:
            if call.startswith("fcntl"):
                command = args.split(",")[1:2]
                if not command or command[0].strip() not in {"F_DUPFD", "F_DUPFD_CLOEXEC", "0", "1030"}:
                    return
            location = resolved if call in {"open", "openat", "creat"} else state.descriptors.get(fd)
            state.descriptors.pop(result, None)
            if location and len(state.descriptors) < 4096:
                state.descriptors[result] = location
        elif call == "close":
            state.descriptors.pop(fd, None)
        elif call in {"execve", "execveat", "close_range"}:
            # CLOEXEC flags and close_range arguments can be unavailable in QEMU traces.
            state.descriptors.clear()
        elif call in {"fork", "vfork"} and result > 0:
            if result not in self.processes and len(self.processes) < 1024:
                self.processes[result] = _Process(state.cwd, dict(state.descriptors))
        elif call in {"rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir"}:
            for process in self.processes.values():
                process.cwd = None
                process.descriptors.clear()
        elif call in {
            "chroot",
            "pivot_root",
            "setns",
            "mount",
            "umount",
            "umount2",
            "move_mount",
            "clone",
            "clone3",
            "unshare",
            "io_uring_setup",
            "io_uring_enter",
        }:
            self.lose_context()
