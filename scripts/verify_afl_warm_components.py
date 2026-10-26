"""Real QEMU/AFL warm-fork verification, without claiming M4 retirement."""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
from unittest.mock import patch

from experiments.afl_file.build import components
from taintforge_env import afl_file as f, afl_transport as transport
from taintforge_env.afl_warm import FilesystemBaseline, MAGIC


class NativeSession:
    def __init__(self, root, built, qemu, *, extra=None):
        self.root = Path(root).resolve(); self.root.mkdir(parents=True, exist_ok=False)
        self.fs = self.root/'fs'; self.fs.mkdir()
        (self.fs/'etc').mkdir(); (self.fs/'tmp').mkdir()
        self.input = self.fs/'etc/input'; self.input.write_bytes(b'A')
        self.marker, self.prepared = self.fs/'tmp/marker', self.fs/'tmp/prepared'
        self.map = self.root/'coverage'; f.create_map(self.map)
        self.connection, peer = socket.socketpair()
        self.connection.settimeout(10)
        plugin = built['probe']+f',coverage={self.map},input={self.input},warm=fd:{peer.fileno()}'
        if extra: plugin += ','+extra
        self.output = (self.root/'qemu.log').open('wb')
        self.process = subprocess.Popen([str(qemu), '-strace', '-plugin', plugin, built['guest'],
            str(self.input), str(self.marker), str(self.prepared)], cwd='/', pass_fds=(peer.fileno(),),
            stdout=self.output, stderr=self.output, stdin=subprocess.DEVNULL)
        peer.close()
        try:
            magic, version, self.pid, self.rss = struct.unpack('!4I', transport.recv_exact(self.connection, 16))
            f.p.require((magic, version) == (MAGIC, 1), 'Invalid native handshake')
            self.baseline = FilesystemBaseline(self.fs, self.root/'baseline')
        except BaseException:
            self.close(abort=True); raise
        self.children = []

    def attempt(self, data, *, timeout_ms=1000):
        self.baseline.restore(); self.input.write_bytes(data)
        with self.map.open('r+b') as output:
            output.write(f.HEADER.pack(b'TFACOV1\0', 1, f.MAP_SIZE, 0, 0, 0, 0, 0, 0)+bytes(f.MAP_SIZE))
        self.connection.sendall(struct.pack('!3I', MAGIC, 1, timeout_ms))
        magic, child, status, timed_out = struct.unpack('!4I', transport.recv_exact(self.connection, 16))
        self.children.append(child)
        f.p.require(magic == MAGIC and status == 0 and not timed_out, 'Native attempt failed')
        coverage, bitmap = f.inspect_map(self.map)
        f.p.require(self.marker.is_file(), 'Child failed its clean-filesystem oracle')
        f.p.require(self.prepared.read_bytes() == b'P', 'Preparation repeated or checkpoint changed')
        return coverage, bitmap

    def close(self, *, abort=False):
        try:
            if self.process.poll() is None:
                if abort:
                    self.connection.close()
                else: self.connection.sendall(struct.pack('!3I', MAGIC, 0, 0))
                self.process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill(); self.process.wait(timeout=5)
            raise
        finally:
            self.connection.close(); self.output.close()


def verify(out, *, qemu, afl_bin, seconds=5, executions=64):
    out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'status': 'failed', 'scope': 'real_qemu_warm_components',
              'm4_retirement_executed': False, 'real_malware_tested': False}
    session = None
    try:
        built = components(out/'build')
        session = NativeSession(out/'native', built, qemu)
        maps = [session.attempt(data)[1] for data in (b'A', b'A', b'B', b'AFL!', b'A')]
        f.p.require(maps[0] == maps[1] == maps[4] and len(set(maps)) >= 3,
                    'Warm input coverage is unstable or insensitive')
        session.close()
        f.p.require(session.process.returncode == 0, 'Warm parent did not stop cleanly')
        campaign = out/'campaign'; campaign.mkdir()
        (campaign/'seeds').mkdir(); (campaign/'seeds/seed').write_bytes(b'A')
        manifest = {'schema': 1, 'profile': 'component-only', 'status': 'prepared', 'max_input': 4096,
                    'launch': {'timeout_seconds': 10}, 'build': {'bridge': built['bridge']}}
        f.atomic_json(campaign/'campaign.json', manifest)
        session = NativeSession(out/'afl-native', built, qemu)

        class Server(transport.AttemptServer):
            def execute(self, connection):
                size = struct.unpack('!I', transport.recv_exact(connection, 4))[0]
                f.p.require(1 <= size <= 4096, 'Input limit')
                data = transport.recv_exact(connection, size)
                case = self.root/'cases'/f'{self.executed:08d}'; case.mkdir()
                self.executed += 1; (case/'input').write_bytes(data)
                coverage, bitmap = session.attempt(data)
                (case/'coverage.map').write_bytes(bitmap)
                f.atomic_json(case/'result.json', {'status': 'passed', 'coverage': coverage})
                connection.sendall(struct.pack('!4I', 0x54464131, 0, 0, f.MAP_SIZE)+bitmap)
                self.completed += 1

        with patch.object(f, 'verify_campaign', return_value=manifest), patch.object(transport, 'AttemptServer', Server):
            result = transport.run_campaign(campaign, afl_bin=afl_bin, seconds=seconds, executions=executions)
        f.p.require(result['status'] == 'completed', 'AFL campaign failed')
        queue = list((campaign/'afl/default/queue').glob('id:*'))
        f.p.require(len(queue) > 1 and session.prepared.read_bytes() == b'P', 'No coverage growth or repeated preparation')
        f.p.require(len(set(session.children)) == len(session.children), 'Child identity reused')
        session.close()
        report.update(status='passed', qemu_version=f.p.command(qemu, '--version').splitlines()[0],
                      same_input_stable=True, distinct_input_maps=len(set(maps)),
                      queue_entries=len(queue), cases=result['completed_cases'],
                      original_preparations=1, parent_pid=session.pid, parent_rss_mib=session.rss,
                      unique_children=len(session.children), private_memory_reset=True,
                      filesystem_reset=True)
        return report
    except BaseException as exc:
        report['error'] = str(exc); raise
    finally:
        if session is not None and session.process.poll() is None: session.close(abort=True)
        f.atomic_json(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('out', 'qemu', 'afl-bin'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=5)
    parser.add_argument('--executions', type=int, default=64)
    args = parser.parse_args()
    import json
    print(json.dumps(verify(args.out, qemu=args.qemu.resolve(), afl_bin=args.afl_bin,
                            seconds=args.seconds, executions=args.executions), indent=2))


if __name__ == '__main__': main()
