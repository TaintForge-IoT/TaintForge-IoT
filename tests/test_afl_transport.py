"""Descriptor transport, size bounds, error propagation, and cancellation."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest

from taintforge_env import afl_file as f
from taintforge_env.afl_transport import AttemptServer, recv_exact


class TransportTests(unittest.TestCase):
    def server(self, command, deadline=2):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        f.atomic_json(self.root/'campaign.json',{'max_input':16})
        server=AttemptServer(self.root,command=command,deadline=deadline);server.start()
        self.addCleanup(server.close)
        return server

    def test_invalid_length_never_starts_an_attempt(self):
        server=self.server([sys.executable,'-c','raise SystemExit(99)'])
        with server.connect() as connection:
            connection.settimeout(5);connection.sendall(struct.pack('!I',17))
            self.assertEqual(struct.unpack('!4I',recv_exact(connection,16)),(0x54464131,3,0,0))
        self.assertEqual(server.executed,0)
        self.assertEqual(len(server.errors),1)

    def test_failed_worker_has_no_bitmap_success(self):
        server=self.server([sys.executable,'-c','raise SystemExit(2)'])
        with server.connect() as connection:
            connection.settimeout(5);connection.sendall(struct.pack('!I',1)+b'A')
            self.assertEqual(struct.unpack('!4I',recv_exact(connection,16))[1],3)
        case=self.root/'cases/00000000'
        self.assertEqual(f.read_json(case/'transport.json')['status'],'failed')
        self.assertFalse((case/'coverage.map').exists())

    def test_deadline_stops_worker_and_records_cleanup(self):
        script="import os,pathlib,sys,time; pathlib.Path(sys.argv[-1],'pid').write_text(str(os.getpid())); time.sleep(20)"
        server=self.server([sys.executable,'-c',script],deadline=.2)
        with server.connect() as connection:
            connection.settimeout(5);connection.sendall(struct.pack('!I',1)+b'A')
            self.assertEqual(struct.unpack('!4I',recv_exact(connection,16))[1],3)
        case=self.root/'cases/00000000'
        with self.assertRaises(ProcessLookupError):os.kill(int((case/'pid').read_text()),0)
        self.assertTrue(f.read_json(case/'transport.json')['cleanup_confirmed'])

    def test_disconnection_is_cancelled_without_fake_target_failure(self):
        script="import os,pathlib,sys,time; pathlib.Path(sys.argv[-1],'pid').write_text(str(os.getpid())); time.sleep(20)"
        server=self.server([sys.executable,'-c',script])
        connection=server.connect();connection.sendall(struct.pack('!I',1)+b'A')
        case=self.root/'cases/00000000'
        until=time.monotonic()+3
        while not (case/'pid').exists() and time.monotonic()<until:time.sleep(.01)
        self.assertTrue((case/'pid').exists())
        connection.close();server.close()
        with self.assertRaises(ProcessLookupError):os.kill(int((case/'pid').read_text()),0)
        self.assertEqual(f.read_json(case/'transport.json')['status'],'cancelled')
        self.assertEqual(server.errors,[])
        self.assertEqual(server.completed,0)


if __name__=='__main__':unittest.main()
