#!/usr/bin/env python3
"""Exercise the real broker, import CLI, replay service and benign C client.

Recording uses ephemeral loopback ports. Replay runs locally and validates a
prepared synthesis iteration. --sandbox additionally executes that iteration
through the privileged prebuilt runner on a Linux x86-64 development VM.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import sys
from pathlib import Path

from taintforge_env.c2_record_broker import C2RecordBroker
from taintforge_env.c2_record_policy import parse_c2_record_policy
from taintforge_env.iteration_controller import IterationController
from taintforge_env.network_policy import NetworkServicePolicy
from taintforge_env.network_replay import TCPReplayService
from taintforge_env.replay_store import ReplayStore, sha256_bytes


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def command(*args: str, expected: int = 0, timeout: float = 30) -> bytes:
    env = dict(os.environ, PYTHONPATH=str(PROJECT_ROOT), PYTHONDONTWRITEBYTECODE="1")
    process = await asyncio.create_subprocess_exec(
        *args, cwd=PROJECT_ROOT, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    check(process.returncode == expected,
          f"command exited {process.returncode}, expected {expected}: {args!r}\n"
          f"{stdout.decode(errors='replace')}{stderr.decode(errors='replace')}")
    return stdout


async def prepare_prebuilt(out: Path, client: Path, *, sandbox: bool) -> dict:
    """Bind a real static test ELF and the imported store to the public runner."""
    template = out / "template"
    rootfs = template / "rootfs"
    config = template / "config"
    for name in ("bin", "proc", "tmp", "dev"):
        (rootfs / name).mkdir(parents=True)
    config.mkdir()
    shutil.copy2(client, rootfs / "bin/unpacked.elf")
    (config / "runtime.json").write_text(json.dumps({
        "arch": "x86_64", "host_binary": str(client), "guest_binary": "/bin/unpacked.elf",
        "qemu_required": False, "rootfs": str(rootfs),
    }, indent=2) + "\n")
    (config / "network_policy.json").write_text(json.dumps({
        "mode": "replay", "allow_internet": False, "catch_all": {"enabled": False},
        "services": [{"service_type": "tcp", "role": "c2", "remote_ip": "198.51.100.10",
                      "remote_port": 48101, "domain": None, "bind_ip": "127.0.0.1",
                      "bind_port": 48101, "protocol_hint": "c2_binary"}],
    }, indent=2) + "\n")
    session = out / "synthesis_session"
    store = out / "replay_store"
    log = await command(
        sys.executable, str(PROJECT_ROOT / "scripts/run_synthesis_loop.py"), "run",
        "--session-dir", str(session), "--template-run-dir", str(template),
        "--project-root", str(PROJECT_ROOT), "--seed-rootfs", str(rootfs),
        "--snapshot-store", str(out / "snapshots"), "--network", "replay",
        "--replay-store", str(store), "--initialize-only")
    (out / "synthesis_initialize.stdout").write_bytes(log)
    binding = json.loads((session / "synthesis_loop.json").read_text())
    check(binding["replay_store_sha256"] == ReplayStore(store).validate()["store_sha256"],
          "synthesis binding does not match imported store")
    IterationController(session).prepare_next()
    runner_args = ("--session-dir", str(session), "--iteration", "0",
                   "--template-run-dir", str(template), "--project-root", str(PROJECT_ROOT),
                   "--network", "replay", "--replay-store", str(store), "--timeout", "15")
    log = await command(sys.executable, str(PROJECT_ROOT / "scripts/run_prebuilt_iteration.py"),
                        "validate", *runner_args)
    (out / "prebuilt_validate.stdout").write_bytes(log)
    if sandbox:
        log = await command(sys.executable, str(PROJECT_ROOT / "scripts/run_prebuilt_iteration.py"),
                            "run", *runner_args, timeout=90)
        (out / "prebuilt_run.stdout").write_bytes(log)
        run_dir = session / "iterations/0000/run"
        execution = json.loads((run_dir / "config/prebuilt_execution.json").read_text())
        check(execution["guest_exit_code"] == 0 and not execution["timed_out"],
              "sandbox client failed or timed out")
        check((run_dir / "logs/runtime_stdout.log").read_bytes() == b"world\n",
              "sandbox replay output mismatch")
        events = [json.loads(line) for path in (run_dir / "logs").rglob("network_events.jsonl")
                  for line in path.read_text().splitlines()]
        check(any(e.get("event") == "replay_hit" for e in events), "sandbox replay hit missing")
        copied = ReplayStore(run_dir / "config/replay_store").validate()
        check(copied["store_sha256"] == binding["replay_store_sha256"], "attempt store digest mismatch")
    verification = json.loads(await command(
        sys.executable, str(PROJECT_ROOT / "scripts/run_synthesis_loop.py"), "verify",
        "--session-dir", str(session)))
    check(verification["binding_verified"], "synthesis verification failed")
    return {"prebuilt_validated": True, "synthesis_binding_verified": True,
            "sandbox_executed": sandbox}


async def run(out: Path, *, sandbox: bool = False) -> dict:
    check(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"),
          "this static C-client scenario requires Linux x86-64")
    out.mkdir(parents=True, exist_ok=False)
    client = out / "c2_record_client"
    await command("gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                  str(PROJECT_ROOT / "samples/c2_record_client.c"), "-o", str(client))
    mock_done = asyncio.get_running_loop().create_future()
    mock_connections = 0

    async def mock(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal mock_connections
        mock_connections += 1
        try:
            request = await asyncio.wait_for(reader.readexactly(5), 5)
            check(request == b"hello", "mock received an unexpected request")
            check(await asyncio.wait_for(reader.read(1), 5) == b"", "request has extra data")
            # Deliberately split the response to exercise short recv() reads.
            writer.write(b"wo")
            await writer.drain()
            # Wait for the broker to record the first chunk instead of assuming
            # that a fixed delay always produces separate reads on a busy host.
            async with asyncio.timeout(2):
                while not list((out / "captures").glob(
                        "*/chunks/000001_server_to_client.bin")):
                    await asyncio.sleep(0.01)
            writer.write(b"rld")
            await writer.drain()
        except Exception as exc:
            if not mock_done.done():
                mock_done.set_exception(exc)
        else:
            if not mock_done.done():
                mock_done.set_result(None)
        finally:
            writer.close()
            await writer.wait_closed()

    upstream = await asyncio.start_server(mock, "127.0.0.1", 0)
    upstream_port = int(upstream.sockets[0].getsockname()[1])
    policy = parse_c2_record_policy({
        "schema_version": 1, "mode": "brokered_record", "capture_kind": "local_test",
        "default_action": "deny", "listen_port": 41000,
        "target": {"original_ip": "198.51.100.10", "original_port": 48101,
                   "upstream_ip": "127.0.0.1", "upstream_port": upstream_port},
        "limits": {"max_connections": 1, "connect_timeout_seconds": 2,
                   "session_timeout_seconds": 10, "idle_timeout_seconds": 2,
                   "max_client_bytes": 1024, "max_server_bytes": 1024},
    })
    broker = C2RecordBroker(policy=policy, bind_ip="127.0.0.1", capture_root=out / "captures",
                            run_id="local-c2-replay-e2e", listen_port_override=0)
    try:
        await broker.start()
        recorded = await command(str(client), "127.0.0.1", str(broker.bound_port))
        check(recorded == b"world\n", "record client output mismatch")
        (out / "record_client.stdout").write_bytes(recorded)
        await asyncio.wait_for(mock_done, 5)
        async with asyncio.timeout(5):
            while broker.active_sessions:
                await asyncio.sleep(0.01)
    finally:
        await broker.close()
        upstream.close()
        await upstream.wait_closed()

    # Prove the source responder is gone before starting replay.
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", upstream_port), 2)
    except ConnectionRefusedError:
        pass
    else:
        writer.close()
        await writer.wait_closed()
        raise RuntimeError("upstream is still accepting connections")

    sessions = list((out / "captures").glob("*/session.json"))
    check(len(sessions) == 1, "expected exactly one captured session")
    session_dir = sessions[0].parent
    summary = json.loads(sessions[0].read_text())
    check(summary["server_to_client"]["chunks"] >= 2, "split response was not captured")
    store_path = out / "replay_store"
    import_args = (sys.executable, str(PROJECT_ROOT / "scripts/replay_store.py"),
                   "import-capture", "--session-dir", str(session_dir),
                   "--store", str(store_path), "--protocol-hint", "c2_binary")
    receipt = json.loads(await command(*import_args))
    check(receipt["status"] == "imported", "first import did not create an entry")
    (out / "import_receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    index_before = (store_path / "index.json").read_bytes()
    second = json.loads(await command(*import_args))
    check(second["status"] == "already_present" and second["entry_id"] == receipt["entry_id"],
          "repeat import was not idempotent")
    check((store_path / "index.json").read_bytes() == index_before, "repeat import modified index")
    store = ReplayStore(store_path)
    validation = store.validate()
    service = TCPReplayService(
        service=NetworkServicePolicy(service_type="tcp", role="c2",
                                     remote_ip="198.51.100.10", remote_port=48101,
                                     domain=None, bind_ip="127.0.0.1", bind_port=0,
                                     protocol_hint="c2_binary"),
        store=store, log_dir=out / "replay_logs")
    replay = await service.start()
    replay_port = int(replay.sockets[0].getsockname()[1])
    try:
        replayed = await command(str(client), "127.0.0.1", str(replay_port))
        check(replayed == recorded, "offline replay differs from the recorded response")
        (out / "replay_client.stdout").write_bytes(replayed)
        reader, writer = await asyncio.open_connection("127.0.0.1", replay_port)
        try:
            writer.write(b"unknown")
            await writer.drain()
            check(await asyncio.wait_for(reader.read(), 2) == b"", "replay miss returned data")
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        replay.close()
        await replay.wait_closed()

    events = [json.loads(line) for line in
              (out / "replay_logs/network_events.jsonl").read_text().splitlines()]
    hits = [event for event in events if event["event"] == "replay_hit"]
    misses = [event for event in events if event["event"] == "replay_miss"]
    check(len(hits) == 1 and hits[0]["entry_id"] == receipt["entry_id"], "missing exact replay hit")
    check(len(misses) == 1, "missing replay miss evidence")
    check(mock_connections == 1, "unexpected upstream traffic")

    damaged = out / "damaged_capture"
    shutil.copytree(session_dir, damaged)
    chunk = next((damaged / "chunks").glob("*_server_to_client.bin"))
    chunk.write_bytes(b"corrupted")
    rejected = await command(
        sys.executable, str(PROJECT_ROOT / "scripts/replay_store.py"), "import-capture",
        "--session-dir", str(damaged), "--store", str(store_path),
        "--protocol-hint", "c2_binary", expected=1)
    (out / "corrupt_import.stdout").write_bytes(rejected)
    check((store_path / "index.json").read_bytes() == index_before, "failed import modified index")
    check(store.validate() == validation, "replay store changed during validation/replay")

    prebuilt = await prepare_prebuilt(out, client, sandbox=sandbox)
    report = {
        "status": "passed", "scope": "loopback record/import/replay and prebuilt validation",
        "record_exit_code": 0, "replay_exit_code": 0,
        "response_sha256": sha256_bytes(b"world"),
        "upstream_stopped_before_replay": True, "upstream_connections": mock_connections,
        "response_capture_chunks": summary["server_to_client"]["chunks"],
        "entry_id": receipt["entry_id"], "replay_hits": len(hits), "replay_misses": len(misses),
        "repeat_import": second["status"], "corrupt_capture_rejected": True,
        "store_sha256": validation["store_sha256"],
        **prebuilt,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New output directory; never overwritten")
    parser.add_argument("--sandbox", action="store_true",
                        help="Also execute the prepared replay iteration on a privileged development VM")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = asyncio.run(run(args.out.absolute(), sandbox=args.sandbox))
    except (OSError, RuntimeError, TimeoutError) as exc:
        print(f"C2 record/import/replay failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
