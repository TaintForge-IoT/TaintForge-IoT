from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintforge_env.observations import (
    ObservationBundle,
    ObservationLoadError,
    load_observation_bundle,
)
from taintforge_env.requirement_extractor import RequirementExtractor
from taintforge_env.requirements import (
    BlockingAssessment,
    RequirementKind,
    RequirementStatus,
)


class RequirementExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = RequirementExtractor()

    def test_missing_file_followed_by_nonzero_exit_is_likely_blocking(self) -> None:
        bundle = self.bundle(
            syscall_events=(
                self.syscall(
                    syscall="openat",
                    path="/etc/device.conf",
                    errno="ENOENT",
                    args='AT_FDCWD, "/etc/device.conf", O_RDONLY',
                    raw='openat(AT_FDCWD, "/etc/device.conf", O_RDONLY) = -1 ENOENT',
                ),
                {
                    "event": "process_exit",
                    "syscall": "exit",
                    "execution_context": "guest",
                    "return_value": 10,
                    "result": "10",
                },
            )
        )

        report = self.extractor.extract(bundle)
        requirement = self.only_requirement(report)

        self.assertEqual(requirement.kind, RequirementKind.FILESYSTEM)
        self.assertEqual(requirement.resource, "/etc/device.conf")
        self.assertEqual(requirement.operation, "path_exists")
        self.assertEqual(requirement.status, RequirementStatus.UNMET)
        self.assertEqual(requirement.blocking, BlockingAssessment.LIKELY)
        self.assertTrue(requirement.repairable)

    def test_open_with_o_creat_reports_missing_parent_not_missing_file(self) -> None:
        bundle = self.bundle(
            syscall_events=(
                self.syscall(
                    syscall="openat",
                    path="/var/run/mirai/mirai.pid",
                    errno="ENOENT",
                    args=(
                        'AT_FDCWD, "/var/run/mirai/mirai.pid", '
                        "O_WRONLY|O_CREAT|O_TRUNC, 0644"
                    ),
                ),
            )
        )

        report = self.extractor.extract(bundle)
        requirement = self.only_requirement(report)

        self.assertEqual(requirement.resource, "/var/run/mirai")
        self.assertEqual(requirement.operation, "directory_exists")
        self.assertEqual(dict(requirement.details)["trigger_path"], "/var/run/mirai/mirai.pid")

    def test_permission_failure_is_not_misclassified_as_missing_path(self) -> None:
        bundle = self.bundle(
            syscall_events=(
                self.syscall(
                    syscall="openat",
                    path="/etc/shadow",
                    errno="EACCES",
                    args='AT_FDCWD, "/etc/shadow", O_RDONLY',
                ),
            )
        )

        requirement = self.only_requirement(self.extractor.extract(bundle))
        self.assertEqual(requirement.operation, "path_access")
        self.assertEqual(requirement.errno, "EACCES")

    def test_network_connect_failure_creates_unmet_endpoint_requirement(self) -> None:
        event = self.syscall(
            syscall="connect",
            errno="ECONNREFUSED",
            args="3, {sa_family=AF_INET, sin_port=htons(48101)}, 16",
        )
        event["remote_ip"] = "185.62.190.0"
        event["remote_port"] = 48101
        event["transport"] = "tcp"
        bundle = self.bundle(syscall_events=(event,))

        requirement = self.only_requirement(self.extractor.extract(bundle))
        self.assertEqual(requirement.kind, RequirementKind.NETWORK)
        self.assertEqual(requirement.resource, "tcp://185.62.190.0:48101")
        self.assertEqual(requirement.status, RequirementStatus.UNMET)

    def test_intercepted_tcp_request_with_response_is_provided(self) -> None:
        bundle = self.bundle(
            network_events=(
                {
                    "event": "tcp_connection_open",
                    "listener_type": "catch_all_transparent",
                    "connection_id": 7,
                    "original_remote_ip": "91.200.10.5",
                    "original_remote_port": 5555,
                },
                {
                    "event": "tcp_response",
                    "listener_type": "catch_all_transparent",
                    "connection_id": 7,
                    "original_remote_ip": "91.200.10.5",
                    "original_remote_port": 5555,
                },
            )
        )

        requirement = self.only_requirement(self.extractor.extract(bundle))
        self.assertEqual(requirement.status, RequirementStatus.PROVIDED)
        self.assertEqual(dict(requirement.details)["response_observed"], "true")

    def test_tcp_response_from_another_listener_does_not_match_by_id_only(self) -> None:
        bundle = self.bundle(
            network_events=(
                {
                    "event": "tcp_connection_open",
                    "listener_type": "catch_all_transparent",
                    "connection_id": 1,
                    "original_remote_ip": "91.200.10.5",
                    "original_remote_port": 5555,
                },
                {
                    "event": "tcp_response",
                    "listener_type": "known",
                    "connection_id": 1,
                    "original_remote_ip": "185.62.190.0",
                    "original_remote_port": 48101,
                },
            )
        )

        requirement = self.only_requirement(self.extractor.extract(bundle))
        self.assertEqual(requirement.status, RequirementStatus.UNKNOWN)
        self.assertEqual(dict(requirement.details)["response_observed"], "false")

    def test_loader_error_creates_library_requirement(self) -> None:
        bundle = self.bundle(
            stderr_text=(
                "/bin/unpacked.elf: error while loading shared libraries: "
                "libcrypto.so.1.0.0: cannot open shared object file: "
                "No such file or directory\n"
            )
        )

        requirement = self.only_requirement(self.extractor.extract(bundle))
        self.assertEqual(requirement.kind, RequirementKind.LIBRARY)
        self.assertEqual(requirement.resource, "libcrypto.so.1.0.0")
        self.assertEqual(requirement.blocking, BlockingAssessment.LIKELY)

    def test_rootfs_diff_records_observed_write_requirement(self) -> None:
        bundle = self.bundle(
            rootfs_diff={
                "created": [
                    {
                        "path": "/var/run/mirai.pid",
                        "type": "file",
                    }
                ],
                "modified": [],
            }
        )

        requirement = self.only_requirement(self.extractor.extract(bundle))
        self.assertEqual(requirement.operation, "path_writable")
        self.assertEqual(requirement.status, RequirementStatus.PROVIDED)

    def test_host_wrapper_syscalls_are_ignored(self) -> None:
        bundle = self.bundle(
            syscall_events=(
                {
                    **self.syscall(
                        syscall="openat",
                        path="/host/file",
                        errno="ENOENT",
                    ),
                    "execution_context": "host_wrapper",
                },
            )
        )

        report = self.extractor.extract(bundle)
        self.assertEqual(report.requirements, ())

    def test_invalid_jsonl_is_rejected_with_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            logs_dir = run_dir / "logs"
            logs_dir.mkdir()
            (logs_dir / "syscall_events.jsonl").write_text(
                '{"event":"syscall"}\nnot-json\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ObservationLoadError, r":2:"):
                load_observation_bundle(run_dir)

    @staticmethod
    def bundle(
        *,
        syscall_events: tuple[dict, ...] = (),
        network_events: tuple[dict, ...] = (),
        stderr_text: str = "",
        rootfs_diff: dict | None = None,
    ) -> ObservationBundle:
        return ObservationBundle(
            run_dir=Path("/tmp/test-run"),
            syscall_events=syscall_events,
            network_events=network_events,
            stderr_text=stderr_text,
            rootfs_diff=rootfs_diff,
        )

    @staticmethod
    def syscall(
        *,
        syscall: str,
        path: str | None = None,
        errno: str | None = None,
        args: str = "",
        raw: str | None = None,
        return_value: int | None = None,
    ) -> dict:
        return {
            "event": "syscall",
            "syscall": syscall,
            "category": "filesystem",
            "execution_context": "guest",
            "path": path,
            "paths": [path] if path is not None else [],
            "errno": errno,
            "args": args,
            "raw": raw or f"{syscall}({args})",
            "return_value": return_value,
        }

    @staticmethod
    def only_requirement(report):
        if len(report.requirements) != 1:
            raise AssertionError(
                f"expected exactly one requirement, got {len(report.requirements)}: "
                f"{report.to_dict()}"
            )
        return report.requirements[0]


if __name__ == "__main__":
    unittest.main()
