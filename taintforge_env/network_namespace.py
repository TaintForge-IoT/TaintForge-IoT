"""Read owned namespace identities without changing namespace permissions."""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


NETNS_ROOT = Path("/run/netns")


class NamespaceInspectionError(RuntimeError):
    pass


def _validate_name(name):
    if not isinstance(name, str) or re.fullmatch(r"tf-[0-9a-f]{8}", name) is None:
        raise NamespaceInspectionError("invalid owned network namespace name")


def _probe_namespace(name):
    """Inspect a handle through directory/file descriptors, never following links."""
    _validate_name(name)
    directory = handle = None
    try:
        directory = os.open(NETNS_ROOT, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        handle = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        info = os.fstat(handle)
        if stat.S_ISLNK(info.st_mode):
            raise NamespaceInspectionError("network namespace handle is a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise NamespaceInspectionError("network namespace handle is not a regular file")
        return {"name": name, "present": True, "device": info.st_dev, "inode": info.st_ino}
    except FileNotFoundError:
        return {"name": name, "present": False}
    finally:
        if handle is not None:
            os.close(handle)
        if directory is not None:
            os.close(directory)


def _validate_result(value, name):
    if not isinstance(value, dict) or value.get("name") != name or type(value.get("present")) is not bool:
        raise NamespaceInspectionError("invalid namespace inspection response")
    expected = {"name", "present", "device", "inode"} if value["present"] else {"name", "present"}
    if set(value) != expected:
        raise NamespaceInspectionError("unexpected namespace inspection fields")
    if value["present"] and (type(value["device"]) is not int or value["device"] < 0
                             or type(value["inode"]) is not int or value["inode"] <= 0):
        raise NamespaceInspectionError("invalid namespace device or inode")
    return value


def _inspect_namespace(name):
    _validate_name(name)
    try:
        return _probe_namespace(name)
    except PermissionError as denied:
        if os.geteuid() == 0:
            raise
        command = ["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve()), "--probe", name]
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            raise NamespaceInspectionError(f"cannot inspect owned namespace {name} with sudo: {exc}") from denied
        if result.returncode:
            detail = result.stderr[:2000].decode("utf-8", errors="replace").strip()
            raise NamespaceInspectionError(
                f"privileged namespace inspection failed for {name} (exit {result.returncode}): {detail}") from denied
        if len(result.stdout) > 4096:
            raise NamespaceInspectionError("namespace inspection response exceeds 4096 bytes") from denied
        try:
            value = json.loads(result.stdout)
        except (ValueError, UnicodeError) as exc:
            raise NamespaceInspectionError("namespace inspection returned invalid JSON") from exc
        return _validate_result(value, name)


def namespace_identity(name):
    value = _inspect_namespace(name)
    if not value["present"]:
        raise FileNotFoundError(errno.ENOENT, "owned network namespace does not exist", str(NETNS_ROOT / name))
    return {key: value[key] for key in ("name", "device", "inode")}


def namespace_exists(name):
    return _inspect_namespace(name)["present"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    try:
        value = _probe_namespace(args.probe)
    except (OSError, NamespaceInspectionError) as exc:
        print(f"namespace inspection: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
