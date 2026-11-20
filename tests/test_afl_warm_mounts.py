"""Checkpoint resets must not traverse service bind mounts or remove their ancestors."""
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from taintforge_env import afl_warm as w


class MountInventoryTests(unittest.TestCase):
    def test_mountinfo_decodes_paths_and_retains_stacked_mount_identities(self):
        root = Path('/tmp/root with \\slash')
        point = root/'home/lisoon/logs/phase1'
        escaped = str(point).replace('\\', r'\134').replace(' ', r'\040')
        data = ('1 0 0:1 / / rw - overlay overlay rw\n'
                '2 1 0:1 /source '+escaped+' rw shared:99 - ext4 /dev/root rw\n'
                '3 2 0:1 /other '+escaped+' ro - ext4 /dev/root rw\n')
        with patch.object(Path, 'read_text', return_value=data):
            mounts = w.rootfs_mounts(root)
        self.assertEqual(set(mounts), {Path('home/lisoon/logs/phase1')})
        self.assertEqual([record[0] for record in mounts[point.relative_to(root)]], ['2', '3'])

    def test_malformed_mountinfo_fails(self):
        with patch.object(Path, 'read_text', return_value='not a mount record\n'):
            with self.assertRaisesRegex(RuntimeError, 'Invalid mountinfo'):
                w.rootfs_mounts(Path('/tmp/root'))


class ProtectedTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/'root'
        self.output = self.root/'home/lisoon/taintforge/session/run/logs/phase1'
        self.output.mkdir(parents=True)
        (self.output/'capture.json').write_bytes(b'original export')
        (self.root/'etc').mkdir()
        self.input = self.root/'etc/input'
        self.input.write_bytes(b'A')
        self.sibling = self.root/'home/lisoon/note'
        self.sibling.write_bytes(b'guest data')
        self.mounts = {self.output.relative_to(self.root): (('100', '1', '0:1', '/export'),)}
        self.inventory = patch.object(w, 'rootfs_mounts', side_effect=lambda root: dict(self.mounts))
        self.inventory.start()
        self.addCleanup(self.inventory.stop)

    def baseline(self):
        return w.FilesystemBaseline(self.root, self.base/'baseline', protected_mounts=(self.output,))

    def test_nested_service_mount_is_opaque_and_siblings_are_restored(self):
        os.mkfifo(self.output/'controller.fifo', 0o600)
        baseline = self.baseline()
        self.assertFalse((baseline.backup/self.output.relative_to(self.root)).exists())
        identities = {name: (self.root/name).stat().st_ino for name in baseline.ancestors}
        output_inode = self.output.stat().st_ino
        for index in range(3):
            self.input.write_bytes(b'mutated')
            self.sibling.write_bytes(b'changed')
            dirty = self.root/'home/lisoon/new-file'
            dirty.write_bytes(b'dirty')
            export = b'live export '+str(index).encode()
            (self.output/'capture.json').write_bytes(export)
            baseline.restore()
            self.assertEqual(self.input.read_bytes(), b'A')
            self.assertEqual(self.sibling.read_bytes(), b'guest data')
            self.assertFalse(dirty.exists())
            self.assertEqual((self.output/'capture.json').read_bytes(), export)
            self.assertTrue(stat.S_ISFIFO((self.output/'controller.fifo').lstat().st_mode))
            self.assertEqual(self.output.stat().st_ino, output_inode)
            self.assertEqual({name: (self.root/name).stat().st_ino for name in identities}, identities)

    def test_protected_mount_is_never_deleted_or_chowned(self):
        baseline = self.baseline()
        rmdir, unlink = Path.rmdir, Path.unlink

        def guarded_rmdir(path):
            self.assertFalse(path == self.output or path.is_relative_to(self.output))
            return rmdir(path)

        def guarded_unlink(path, *args, **kwargs):
            self.assertFalse(path.is_relative_to(self.output))
            return unlink(path, *args, **kwargs)

        with patch.object(Path, 'rmdir', guarded_rmdir), patch.object(Path, 'unlink', guarded_unlink), \
             patch.object(w.os, 'geteuid', return_value=0), patch.object(w.os, 'chown') as chown:
            baseline.restore()
        self.assertTrue(chown.called)
        for call in chown.call_args_list:
            self.assertFalse(Path(call.args[0]).is_relative_to(self.output))

    def test_partial_copy_collision_retries_from_a_clean_tree_and_verifies_content(self):
        baseline = self.baseline()
        copy = baseline._copy
        injected = False

        def collide(source, destination, relative=Path('.')):
            nonlocal injected
            if relative == Path('.') and not injected:
                injected = True
                (destination/'etc').mkdir()
                (destination/'etc/dirty').write_bytes(b'dirty partial copy')
                raise FileExistsError('injected copy collision')
            return copy(source, destination, relative)

        (self.output/'capture.json').write_bytes(b'preserve service output')
        with patch.object(baseline, '_copy', side_effect=collide):
            baseline.restore()
        self.assertEqual(baseline.restore_retries, 1)
        self.assertFalse((self.root/'etc/dirty').exists())
        self.assertEqual(self.input.read_bytes(), b'A')
        self.assertEqual((self.output/'capture.json').read_bytes(), b'preserve service output')

    def test_incorrect_copy_is_rejected_before_the_next_child(self):
        baseline = self.baseline()
        copy = baseline._copy

        def corrupt(source, destination, relative=Path('.')):
            copy(source, destination, relative)
            if relative == Path('.'):
                self.input.write_bytes(b'bad reset')

        with patch.object(baseline, '_copy', side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError, 'differs from the checkpoint'):
                baseline.restore()

    def test_reserved_names_are_excluded_only_at_guest_root(self):
        (self.root/'proc').mkdir()
        (self.root/'proc/live').write_bytes(b'live')
        nested = self.root/'home/proc'
        nested.mkdir()
        (nested/'guest').write_bytes(b'baseline')
        baseline = self.baseline()
        (self.root/'proc/live').write_bytes(b'preserved')
        (nested/'guest').write_bytes(b'dirty')
        baseline.restore()
        self.assertEqual((self.root/'proc/live').read_bytes(), b'preserved')
        self.assertEqual((nested/'guest').read_bytes(), b'baseline')

    def test_unknown_mount_refused_before_snapshot(self):
        self.mounts[Path('var/new-mount')] = (('200', '1', '0:2', '/'),)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported checkpoint mount'):
            self.baseline()
        self.assertFalse((self.base/'baseline').exists())
        self.assertEqual(self.input.read_bytes(), b'A')

    def test_missing_required_service_mount_refused(self):
        self.mounts.clear()
        with self.assertRaisesRegex(RuntimeError, 'Required service mount is missing'):
            self.baseline()

    def test_mount_change_refused_before_deleting_guest_files(self):
        for change in ('remove', 'replace', 'add'):
            with self.subTest(change=change):
                baseline = w.FilesystemBaseline(self.root, self.base/('baseline-'+change),
                                               protected_mounts=(self.output,))
                original = dict(self.mounts)
                self.input.write_bytes(b'leave untouched on failure')
                if change == 'remove': self.mounts.clear()
                elif change == 'replace': self.mounts[self.output.relative_to(self.root)] = (('101',),)
                else: self.mounts[Path('etc/new')] = (('201',),)
                with self.assertRaisesRegex(RuntimeError, 'mount layout changed'):
                    baseline.restore()
                self.assertEqual(self.input.read_bytes(), b'leave untouched on failure')
                self.mounts = original

    def test_replaced_mount_ancestor_refused_without_following_symlink(self):
        baseline = self.baseline()
        outside = self.base/'outside'
        outside.mkdir()
        (outside/'sentinel').write_bytes(b'keep')
        (self.root/'home').rename(self.root/'original-home')
        (self.root/'home').symlink_to(outside, target_is_directory=True)
        self.input.write_bytes(b'untouched')
        with self.assertRaisesRegex(RuntimeError, 'mount ancestor is not a directory'):
            baseline.restore()
        self.assertEqual((outside/'sentinel').read_bytes(), b'keep')
        self.assertEqual(self.input.read_bytes(), b'untouched')

    def test_guest_symlink_is_restored_without_writing_its_external_target(self):
        external = self.base/'external'
        external.write_bytes(b'keep')
        link = self.root/'etc/link'
        link.symlink_to(external)
        baseline = self.baseline()
        link.unlink()
        link.write_bytes(b'guest replacement')
        baseline.restore()
        self.assertTrue(link.is_symlink())
        self.assertEqual(external.read_bytes(), b'keep')

    def test_special_guest_files_and_hardlinks_are_still_rejected(self):
        fifo = self.root/'etc/fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(RuntimeError, 'private regular files'):
            self.baseline()
        fifo.unlink()
        shutil.rmtree(self.base/'baseline')
        os.link(self.input, self.root/'etc/hardlink')
        with self.assertRaisesRegex(RuntimeError, 'private regular files'):
            self.baseline()


class WorkerShutdownTests(unittest.TestCase):
    def server(self, directory):
        server = w.WarmAttemptServer(directory)
        server.output = io.BytesIO()
        server.worker = Mock()
        server.worker.poll.return_value = None
        server.worker.returncode = 1
        server.started = True
        return server

    def test_closed_broker_allows_worker_to_finish_and_publish_failure(self):
        with tempfile.TemporaryDirectory() as td:
            server = self.server(Path(td))
            with patch.object(w.socket, 'socket') as connection, patch.object(w, 'stop_case') as stop:
                connection.return_value.__enter__.return_value.connect.side_effect = ConnectionRefusedError()
                with self.assertRaisesRegex(RuntimeError, 'Warm pipeline failed'):
                    server.close()
                server.worker.wait.assert_called_once_with(timeout=20)
                stop.assert_not_called()
            self.assertTrue(server.output.closed)

    def test_unresponsive_worker_is_still_terminated(self):
        with tempfile.TemporaryDirectory() as td:
            server = self.server(Path(td))
            server.worker.wait.side_effect = subprocess.TimeoutExpired('worker', 20)
            with patch.object(w.socket, 'socket') as connection, patch.object(w, 'stop_case') as stop:
                connection.return_value.__enter__.return_value.connect.side_effect = ConnectionRefusedError()
                with self.assertRaisesRegex(RuntimeError, 'Warm pipeline failed'):
                    server.close()
                stop.assert_called_once_with(server.worker, server.root)
            self.assertTrue(server.output.closed)


@unittest.skipUnless(os.environ.get('TF_WARM_REAL_MOUNTS') == '1',
                     'Run explicitly inside sudo unshare --mount --fork for real bind mounts')
class RealMountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or not all(shutil.which(tool) for tool in ('mount', 'umount')):
            raise RuntimeError('Real mount checks require root and mount/umount')
        if os.stat('/proc/self/ns/mnt').st_ino == os.stat('/proc/1/ns/mnt').st_ino:
            raise RuntimeError('Refusing real mount checks outside a private mount namespace')
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tf-warm-mount-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/'root with space'
        self.output = self.base/'export'
        self.output.mkdir()
        (self.output/'capture.json').write_bytes(b'keep real export')
        self.point = self.root/'home/lisoon/session/run/logs/phase1'
        self.point.mkdir(parents=True)
        (self.root/'etc').mkdir()
        (self.root/'etc/input').write_bytes(b'A')
        self.bind(self.output, self.point)

    def bind(self, source, destination):
        subprocess.run(['mount', '--bind', str(source), str(destination)], check=True)

        def unmount():
            if destination.relative_to(self.root) in w.rootfs_mounts(self.root):
                subprocess.run(['umount', str(destination)], check=True)

        self.addCleanup(unmount)

    def test_real_same_filesystem_bind_survives_repeated_resets(self):
        self.assertEqual(self.point.stat().st_dev, self.point.parent.stat().st_dev)
        baseline = w.FilesystemBaseline(self.root, self.base/'baseline', protected_mounts=(self.point,))
        self.assertFalse((baseline.backup/self.point.relative_to(self.root)).exists())
        before = (self.output/'capture.json').stat()
        for _ in range(3):
            (self.root/'etc/input').write_bytes(b'dirty')
            baseline.restore()
            self.assertEqual((self.root/'etc/input').read_bytes(), b'A')
            self.assertEqual((self.output/'capture.json').read_bytes(), b'keep real export')
            self.assertEqual((self.output/'capture.json').stat().st_ino, before.st_ino)
            self.assertIn(self.point.relative_to(self.root), w.rootfs_mounts(self.root))

    def test_unexpected_real_bind_is_rejected(self):
        extra = self.root/'etc/unexpected'
        extra.mkdir()
        self.bind(self.output, extra)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported checkpoint mount'):
            w.FilesystemBaseline(self.root, self.base/'baseline', protected_mounts=(self.point,))
        self.assertEqual((self.output/'capture.json').read_bytes(), b'keep real export')


if __name__ == '__main__':
    unittest.main()
