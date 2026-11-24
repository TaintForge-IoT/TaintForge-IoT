"""Bounded responder output and process-group cleanup."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import shutil
import subprocess
import threading
import time

from .network_runtime import NetworkRuntimeError, network_open, process_start, child_proc_pid


class CapturedNetworkProcess:
    def __init__(self, command, *, cwd, stdout_path, stderr_path, runtime):
        self.command, self.runtime = [str(value) for value in command], runtime
        environment = {**os.environ, "PYTHONPATH": str(cwd)}
        self.process = subprocess.Popen(self.command, cwd=cwd, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, process_group=0)
        try:
            self.proc_pid = child_proc_pid(self.process.pid)
            self.birth = process_start(self.proc_pid)
        except BaseException:
            self.process.kill()
            self.process.communicate(timeout=2)
            raise
        self.threads = []
        for source, path in ((self.process.stdout, stdout_path), (self.process.stderr, stderr_path)):
            thread = threading.Thread(target=self._drain, args=(source, Path(path)),
                                      name="network-service-output", daemon=True)
            self.threads.append(thread)
            thread.start()

    def _drain(self, source, path):
        output = None
        try:
            try:
                output = network_open(path, "wb", runtime=self.runtime.client())
            except (OSError, NetworkRuntimeError):
                self.runtime.fail("network_service_output_failed")
            while True:
                data = source.read(4096)
                if not data:
                    return
                if output is not None:
                    try:
                        output.write(data)
                    except (OSError, NetworkRuntimeError):
                        self.runtime.fail("network_service_output_failed")
                        output.close()
                        output = None
        except OSError:
            self.runtime.fail("network_service_output_failed")
        finally:
            if output is not None:
                output.close()
            source.close()

    def poll(self):
        return self.process.poll()

    def _signal(self, sig, *, timeout=None):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 30):
            raise ValueError("network signal timeout must be in (0, 30] seconds")
        signal_timeout = (min(0.2, self.runtime.limits.shutdown_timeout_ms / 10000) if timeout is None
                          else min(timeout, self.runtime.limits.shutdown_timeout_ms / 1000))
        current = process_start(self.proc_pid)
        if current is not None and self.birth is not None and current != self.birth:
            raise NetworkRuntimeError("network process identity changed before signalling")
        # Namespace workers may run below sudo. Signal their exact owned group
        # with the same privilege; killing only the sudo monitor can orphan root children.
        if Path(self.command[0]).name == "sudo" and self._group_alive():
            kill = shutil.which("kill")
            if kill is None:
                raise NetworkRuntimeError("cannot locate kill for the owned privileged network group")
            completed = subprocess.run(["sudo", "-n", kill, "-s", str(int(sig)), "--", f"-{self.process.pid}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=signal_timeout)
            if completed.returncode and self._group_alive():
                raise NetworkRuntimeError("privileged network process group did not accept its signal")
        try:
            os.killpg(self.process.pid, sig)
        except ProcessLookupError:
            pass

    def terminate(self):
        self._signal(signal.SIGTERM)

    def kill(self, *, timeout=None):
        self._signal(signal.SIGKILL, timeout=timeout)

    def signal_for_cleanup(self, sig, *, timeout):
        """Return an unconfirmed helper timeout for the caller's subsequent wait."""
        try:
            self._signal(sig, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # sudo may exit after kill(2) has already delivered the signal.
            # Only defer this error when wait() can examine the owned group.
            if self.proc_pid is None or self.birth is None:
                raise
            return exc
        return None

    def wait(self, timeout=None):
        deadline = time.monotonic() + timeout if timeout is not None else None
        result = self.process.wait(timeout=timeout)
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()) if deadline is not None else None)
        if any(thread.is_alive() for thread in self.threads):
            raise subprocess.TimeoutExpired(self.command, timeout)
        while self._group_alive():
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.command, timeout)
            time.sleep(0.005)
        return result

    def _group_alive(self):
        if self.proc_pid is None:
            return self.process.poll() is None
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    raw = Path(entry.path, "stat").read_text()
                    fields = raw[raw.rfind(")") + 2:].split()
                    if fields[0] != "Z" and int(fields[2]) == self.proc_pid:
                        return True
                except (OSError, ValueError, IndexError):
                    continue
        return False
