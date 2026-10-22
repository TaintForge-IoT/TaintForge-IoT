from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .log_io import iter_log_lines, read_log_preview
from .attempt_finalization import write_json


def _first_artifact(*paths: Path) -> Path:
    return next((path for path in paths if path.exists()), paths[0])

def is_malware_syscall_event(event: dict) -> bool:
    context = event.get("context") or event.get("execution_context")
    return context == "guest"

PREVIEW_CHARS = 4000
NETWORK_ATTEMPT_SYSCALLS = {"connect", "send", "sendto", "sendmsg", "sendmmsg"}


def _network_setting(runtime: dict, policy: dict, runtime_key: str, policy_key: str) -> tuple[Any, str | None]:
    # The per-attempt runtime records the selected mode; a template policy may
    # still exist when this attempt uses network=none. Preserve explicit False.
    if runtime_key in runtime:
        return runtime[runtime_key], f"config/runtime.json:{runtime_key}"
    if policy_key in policy:
        return policy[policy_key], f"config/network_policy.json:{policy_key}"
    return None, None


class ReportGenerationError(RuntimeError):
    pass


class RunReportGenerator:
    def __init__(self, out_dir: str | Path):
        self.out_dir = Path(out_dir)
        self.config_dir = self.out_dir / "config"
        self.logs_dir = self.out_dir / "logs"

        self.runtime_path = self.config_dir / "runtime.json"
        self.network_policy_path = self.config_dir / "network_policy.json"
        self.library_plan_path = self.config_dir / "library_plan.json"
        self.library_resolution_path = self.config_dir / "library_resolution.json"
        self.network_events_path = self.logs_dir / "network_events.jsonl"
        self.runtime_status_path = _first_artifact(
            self.config_dir / "prebuilt_execution.json", self.logs_dir / "runtime_status.json",
            self.out_dir / "runtime_status.json", self.config_dir / "runtime_status.json",
        )
        self.security_status_path = self.logs_dir / "security_status.json"
        self.runner_manifest_path = self.config_dir / "prebuilt_runner_manifest.json"
        self.syscall_events_path = self.logs_dir / "syscall_events.jsonl"
        self.syscall_summary_path = self.logs_dir / "syscall_events.summary.json"
        self.rootfs_snapshot_before_path = _first_artifact(
            self.config_dir / "rootfs_before.json", self.logs_dir / "rootfs_snapshot_before.json")
        self.rootfs_snapshot_after_path = _first_artifact(
            self.config_dir / "rootfs_after.json", self.logs_dir / "rootfs_snapshot_after.json")
        self.rootfs_diff_path = _first_artifact(
            self.config_dir / "rootfs_diff.json", self.logs_dir / "rootfs_diff.json",
            self.out_dir / "rootfs_diff.json")

        self.report_json_path = self.out_dir / "report.json"
        self.report_md_path = self.out_dir / "report.md"


    def build_filesystem_section(self, rootfs_diff: dict[str, Any]) -> dict[str, Any]:
        available = bool(rootfs_diff) and "_error" not in rootfs_diff
        created = rootfs_diff.get("created", [])
        modified = rootfs_diff.get("modified", [])
        deleted = rootfs_diff.get("deleted", [])

        return {
            "observation_available": available,
            "created_count": rootfs_diff.get("created_count", len(created)) if available else None,
            "modified_count": rootfs_diff.get("modified_count", len(modified)) if available else None,
            "deleted_count": rootfs_diff.get("deleted_count", len(deleted)) if available else None,
            "created": created[:100],
            "modified": modified[:100],
            "deleted": deleted[:100],
        }

    def build_syscalls_section(
        self,
        syscall_events: list[dict[str, Any]],
        syscall_summary: dict[str, Any],
    ) -> dict[str, Any]:
        # connect/send attempts remain observable even when QEMU prints only a
        # sockaddr pointer. An undecoded endpoint must not erase the syscall.
        network_attempts = []
        attempts_count = unknown_endpoints = 0
        network_targets = set()
        for event in syscall_events:
            if event.get("syscall") not in NETWORK_ATTEMPT_SYSCALLS:
                continue
            remote_ip, remote_port = event.get("remote_ip"), event.get("remote_port")
            endpoint_parsed = remote_ip is not None and remote_port is not None
            target = f"{remote_ip}:{remote_port}" if endpoint_parsed else None
            attempts_count += 1
            unknown_endpoints += not endpoint_parsed
            if target is not None:
                network_targets.add(target)
            if len(network_attempts) < 100:
                network_attempts.append({
                    "syscall": event.get("syscall"), "category": event.get("category"),
                    "remote_ip": remote_ip, "remote_port": remote_port, "target": target,
                    "endpoint_parsed": endpoint_parsed, "result": event.get("result"),
                    "errno": event.get("errno"), "raw": event.get("raw"),
                    "source_file": event.get("source_file"), "line_number": event.get("line_number"),
                })
        attempt_details = {
            "network_targets": sorted(network_targets),
            "network_attempts_count": attempts_count,
            "network_attempts_without_endpoint_count": unknown_endpoints,
            "network_attempts": network_attempts,
        }
        if syscall_summary:
            return {
                "events_total": syscall_summary.get("events_total", len(syscall_events)),
                "by_syscall": syscall_summary.get("by_syscall", {}),
                "by_category": syscall_summary.get("by_category", {}),
                "by_context": syscall_summary.get("by_context", {}),
                "paths": syscall_summary.get("paths", []),
                "guest_paths": syscall_summary.get(
                    "guest_paths",
                    syscall_summary.get("paths", []),
                ),
                "host_wrapper_paths": syscall_summary.get("host_wrapper_paths", []),
                "all_paths": syscall_summary.get("all_paths", []),
                **attempt_details,
                "high_risk_count": syscall_summary.get("high_risk_count", 0),
                "high_risk_events": syscall_summary.get("high_risk_events", []),
            }

        by_syscall = Counter(
            str(event.get("syscall", "unknown"))
            for event in syscall_events
        )

        by_category = Counter(
            str(event.get("category", "unknown"))
            for event in syscall_events
        )

        paths = sorted(
            {
                path
                for event in syscall_events
                for path in event.get("paths", [])
                if path
            }
        )

        high_risk_events = [
            event
            for event in syscall_events
            if event.get("high_risk")
        ]

        return {
            "events_total": len(syscall_events),
            "by_syscall": dict(by_syscall),
            "by_category": dict(by_category),
            "paths": paths,
            **attempt_details,
            "high_risk_count": len(high_risk_events),
            "high_risk_events": high_risk_events[:50],
        }
    def generate(self) -> dict[str, Any]:
        if not self.out_dir.exists():
            raise ReportGenerationError(f"out_dir does not exist: {self.out_dir}")

        runtime = self.load_json_optional(self.runtime_path)
        network_policy = self.load_json_optional(self.network_policy_path)
        library_plan = self.load_json_optional(self.library_plan_path)
        library_resolution = self.load_json_optional(self.library_resolution_path)
        network_events = self.load_jsonl_optional(self.network_events_path)
        runtime_status = self.load_json_optional(self.runtime_status_path)
        security_status = self.load_json_optional(self.security_status_path)
        runner_manifest = self.load_json_optional(self.runner_manifest_path)
        finalization = self.load_json_optional(self.config_dir / "finalization_status.json")
        stages = finalization.get("stages", {})
        syscalls_available = self.syscall_events_path.is_file() and (
            not finalization or stages.get("syscalls", {}).get("status") == "completed")
        # A killed parser may have left a valid prefix. It is evidence for
        # offline recovery, never a complete syscall result for this attempt.
        raw_syscall_events = self.load_jsonl_optional(self.syscall_events_path) if syscalls_available else []
        rootfs_diff = self.load_json_optional(self.rootfs_diff_path)
        if finalization and stages.get("filesystem", {}).get("status") != "completed":
            rootfs_diff = {}

        syscall_events = [
            e for e in raw_syscall_events
            if is_malware_syscall_event(e)
        ]

        report = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "out_dir": str(self.out_dir),
            "paths": self.build_paths_section(),
            "runtime": self.build_runtime_section(runtime=runtime, runtime_status=runtime_status),
            "libraries": self.build_libraries_section(
                library_plan=library_plan,
                library_resolution=library_resolution,
            ),
            "network": self.build_network_section(
                network_policy=network_policy,
                network_events=network_events,
                runtime=runtime,
            ),
            "syscalls": self.build_syscalls_section(
                syscall_events=syscall_events,
                syscall_summary={},
            ),
            "filesystem": self.build_filesystem_section(rootfs_diff),
            "artifacts": self.build_artifacts_section(network_events),
            "logs": self.build_logs_section(),
            "security": self.build_security_section(
                network_policy=network_policy, security_status=security_status,
                runtime=runtime, runner_manifest=runner_manifest,
            ),
        }
        report["syscalls"]["observation_available"] = syscalls_available
        if not syscalls_available:
            for name in ("events_total", "network_attempts_count", "network_attempts_without_endpoint_count", "high_risk_count"):
                report["syscalls"][name] = None
        if finalization:
            report["finalization"] = finalization
            report["phase1"] = self.load_json_optional(self.config_dir / "phase1_result.json")

        self.save_json_report(report)
        self.save_markdown_report(report)

        return report

    def build_paths_section(self) -> dict[str, str]:
        return {
            "runtime": self.rel(self.runtime_path),
            "network_policy": self.rel(self.network_policy_path),
            "library_plan": self.rel(self.library_plan_path),
            "library_resolution": self.rel(self.library_resolution_path),
            "network_events": self.rel(self.network_events_path),
            "syscall_events": self.rel(self.syscall_events_path),
            "syscall_summary": self.rel(self.syscall_summary_path),
            "runtime_status": self.rel(self.runtime_status_path),
            "security_status": self.rel(self.security_status_path),
            "runner_manifest": self.rel(self.runner_manifest_path),
            "runtime_stdout": self.rel(self.logs_dir / "runtime_stdout.log"),
            "runtime_stderr": self.rel(self.logs_dir / "runtime_stderr.log"),
            "report_json": self.rel(self.report_json_path),
            "report_md": self.rel(self.report_md_path),
            "rootfs_snapshot_before": self.rel(self.rootfs_snapshot_before_path),
            "rootfs_snapshot_after": self.rel(self.rootfs_snapshot_after_path),
            "rootfs_diff": self.rel(self.rootfs_diff_path),
        }

    def build_runtime_section(self, runtime: dict[str, Any], runtime_status: dict[str, Any]) -> dict[str, Any]:
        host_binary_path = runtime.get("host_binary_path")
        host_binary_info = None

        if host_binary_path:
            host_binary_info = self.file_info(Path(host_binary_path))

        return {
            "arch": runtime.get("arch"),
            "rootfs": runtime.get("rootfs"),
            "host_binary_path": host_binary_path,
            "host_binary": host_binary_info,
            "guest_binary_path": runtime.get("guest_binary_path"),
            "qemu_required": runtime.get("qemu_required"),
            "qemu_binary_name": runtime.get("qemu_binary_name"),
            "qemu_host_path": runtime.get("qemu_host_path"),
            "qemu_guest_path": runtime.get("qemu_guest_path"),
            "libraries_ok": runtime.get("libraries_ok"),
            "library_resolution_path": runtime.get("library_resolution_path"),
            "status": runtime_status,
            "stdout_preview": self.read_text_optional(self.logs_dir / "runtime_stdout.log"),
            "stderr_preview": self.read_text_optional(self.logs_dir / "runtime_stderr.log"),
        }

    def build_libraries_section(
        self,
        library_plan: dict[str, Any],
        library_resolution: dict[str, Any],
    ) -> dict[str, Any]:
        requirements = library_plan.get("requirements", [])
        resolved = library_resolution.get("resolved", [])
        missing = library_resolution.get("missing", [])

        return {
            "requirements_count": len(requirements),
            "resolved_count": len(resolved),
            "missing_count": len(missing),
            "requirements": requirements,
            "resolved": resolved,
            "missing": missing,
        }

    def build_network_section(
        self,
        network_policy: dict[str, Any],
        network_events: list[dict[str, Any]],
        runtime: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        runtime = runtime or {}
        mode, mode_source = _network_setting(runtime, network_policy, "network_mode", "mode")
        allow_internet, internet_source = _network_setting(
            runtime, network_policy, "allow_internet", "allow_internet")
        services = network_policy.get("services", [])
        catch_all = network_policy.get("catch_all", {})

        events_by_type = Counter(
            str(event.get("event", "unknown"))
            for event in network_events
        )

        listener_types = Counter(
            str(event.get("listener_type", "unknown"))
            for event in network_events
        )

        known_tcp_events = [
            event for event in network_events
            if event.get("listener_type") == "known"
        ]

        unknown_tcp_events = [
            event for event in network_events
            if event.get("listener_type") == "catch_all_transparent"
        ]

        udp_events = [
            event for event in network_events
            if event.get("listener_type") == "udp_transparent" or event.get("transport") == "udp"
        ]

        dns_events = [
            event for event in network_events
            if event.get("udp_role") == "dns" or str(event.get("event", "")).startswith("dns_")
        ]

        http_events = [
            event for event in network_events
            if event.get("event") == "tcp_data"
            and event.get("http_parse_ok") is True
        ]

        http_hosts = sorted(
            {
                event.get("http_host")
                for event in http_events
                if event.get("http_host")
            }
        )

        http_requests = [
            {
                "method": event.get("http_method"),
                "host": event.get("http_host"),
                "path": event.get("http_path"),
                "user_agent": event.get("http_user_agent"),
                "original_remote_ip": event.get("original_remote_ip"),
                "original_remote_port": event.get("original_remote_port"),
                "payload_file": event.get("payload_file"),
            }
            for event in http_events
        ]

        dns_queries = sorted(
            {
                event.get("dns_query")
                for event in dns_events
                if event.get("dns_query")
            }
        )

        dns_responses_sent = sum(
            1
            for event in dns_events
            if event.get("dns_response_sent") is True
        )

        return {
            "mode": mode,
            "mode_source": mode_source,
            "allow_internet": allow_internet,
            "allow_internet_source": internet_source,
            "events_available": self.network_events_path.is_file(),
            "services_count": len(services),
            "services": services,
            "catch_all": catch_all,
            "events_total": len(network_events),
            "events_by_type": dict(events_by_type),
            "listener_types": dict(listener_types),
            "known_tcp_events": len(known_tcp_events),
            "unknown_tcp_events": len(unknown_tcp_events),
            "udp_datagrams": len(udp_events),
            "dns_datagrams": sum(e.get("transport") == "udp" or e.get("listener_type") == "udp_transparent" for e in dns_events),
            "dns_events_total": len(dns_events),
            "dns_queries": dns_queries,
            "dns_responses_sent": dns_responses_sent,
            "dns_responses_prepared": sum(e.get("dns_response_prepared") is True for e in dns_events),
            "known_tcp_targets": self.unique_targets(known_tcp_events),
            "unknown_tcp_targets": self.unique_targets(unknown_tcp_events),
            "udp_targets": self.unique_targets(udp_events),
            "http_requests_count": len(http_requests),
            "http_hosts": http_hosts,
            "http_requests": http_requests[:100],
        }

    def build_artifacts_section(
        self,
        network_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload_names = sorted(
            {
                event.get("payload_file")
                for event in network_events
                if event.get("payload_file")
            }
        )

        payload_files = []

        for name in payload_names:
            path = self.logs_dir / str(name)
            payload_files.append(self.file_info(path))

        log_files = []

        if self.logs_dir.exists():
            for path in sorted(self.logs_dir.iterdir()):
                if path.is_file() and path.suffix != ".bin":
                    log_files.append(self.file_info(path))

        return {
            "payload_count": len(payload_files),
            "payload_files": payload_files,
            "log_files": log_files,
        }

    def build_logs_section(self) -> dict[str, Any]:
        return {
            "runtime_stdout": self.read_text_optional(
                self.logs_dir / "runtime_stdout.log"
            ),
            "runtime_stderr": self.read_text_optional(
                self.logs_dir / "runtime_stderr.log"
            ),
            "network_self_test_stdout": self.read_text_optional(
                self.logs_dir / "network_self_test_stdout.log"
            ),
            "network_self_test_stderr": self.read_text_optional(
                self.logs_dir / "network_self_test_stderr.log"
            ),
            "transparent_logger_stdout": self.read_text_optional(
                self.logs_dir / "transparent_logger_stdout.log"
            ),
            "transparent_logger_stderr": self.read_text_optional(
                self.logs_dir / "transparent_logger_stderr.log"
            ),
            "network_emulator_stdout": self.read_text_optional(
                self.logs_dir / "network_emulator_stdout.log"
            ),
            "network_emulator_stderr": self.read_text_optional(
                self.logs_dir / "network_emulator_stderr.log"
            ),
        }

    def build_security_section(
        self,
        network_policy: dict[str, Any],
        security_status: dict[str, Any],
        runtime: dict[str, Any] | None = None,
        runner_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        status_available = bool(security_status) and "_error" not in security_status
        status = security_status if status_available else {}
        manifest = runner_manifest or {}
        isolation = manifest.get("isolation") if "_error" not in manifest else None
        if not isinstance(isolation, dict):
            isolation = None
        allow_internet, _ = _network_setting(
            runtime or {}, network_policy, "allow_internet", "allow_internet")

        return {
            "status_available": status_available,
            "status_source": self.rel(self.security_status_path) if status_available else None,
            "status_error": security_status.get("_error"),
            "configured_isolation": isolation,
            "configuration_source": self.rel(self.runner_manifest_path) if isolation is not None else None,
            "isolation_ready": status.get("isolation_ready"),
            "chroot_enabled": status.get("chroot_enabled", status.get("chroot")),
            "network_namespace_enabled": status.get("network_namespace"),
            "pid_namespace_enabled": status.get("pid_namespace"),
            "mount_namespace_enabled": status.get("mount_namespace"),
            "uts_namespace_enabled": status.get("uts_namespace"),
            "ipc_namespace_enabled": status.get("ipc_namespace"),
            "user_namespace_enabled": status.get("user_namespace"),
            "mount_propagation": status.get("mount_propagation"),
            "sandbox_hostname": status.get("sandbox_hostname"),
            "proc_mode": status.get("proc_mode"),
            "iptables_default_deny_expected": status.get("iptables_default_deny_expected"),
            "host_ip_forwarding_expected": status.get("host_ip_forwarding_expected"),
            "allow_internet": allow_internet,
            "known_endpoint_dnat": status.get("known_endpoint_dnat"),
            "tcp_catch_all_redirect": status.get("tcp_catch_all_redirect"),
            "udp_catch_all_redirect": status.get("udp_catch_all_redirect"),
            "strace_enabled": status.get("strace_enabled"),
            "resource_limits": status.get("resource_limits"),
            "limitations": status.get("limitations"),
        }

    def save_json_report(self, report: dict[str, Any]) -> None:
        write_json(self.report_json_path, report)

    def save_markdown_report(self, report: dict[str, Any]) -> None:
        content = self.render_markdown(report)
        self.report_md_path.write_text(content, encoding="utf-8")

    def render_markdown(self, report: dict[str, Any]) -> str:
        runtime = report["runtime"]
        libraries = report["libraries"]
        network = report["network"]
        syscalls = report["syscalls"]
        filesystem = report["filesystem"]
        artifacts = report["artifacts"]
        security = report["security"]
        logs = report["logs"]

        lines: list[str] = []

        lines.append("# TaintForge-IoT Phase 2 Run Report")
        lines.append("")
        lines.append(f"Generated at UTC: `{report['generated_at_utc']}`")
        lines.append(f"Output directory: `{report['out_dir']}`")
        lines.append("")

        if report.get("finalization"):
            lines.extend(["## Attempt finalization", "", "| Operation | Status | Error / reason |", "|---|---|---|"])
            for name, stage in report["finalization"].get("stages", {}).items():
                reason = str(stage.get("error", stage.get("reason", ""))).replace("\n", " ")
                lines.append(f"| {self.md(name)} | {self.md(stage.get('status'))} | {self.md(reason)} |")
            phase1 = report.get("phase1", {})
            lines.extend(["", f"Phase 1 artifact integrity: `{phase1.get('artifact_integrity', 'not_applicable')}`.",
                          "A completed verification operation can still describe an incomplete capture.", ""])

        lines.append("## Runtime")
        lines.append("")
        lines.append(f"- Architecture: `{runtime.get('arch')}`")
        lines.append(f"- RootFS: `{runtime.get('rootfs')}`")
        lines.append(f"- Host binary: `{runtime.get('host_binary_path')}`")
        lines.append(f"- Guest binary: `{runtime.get('guest_binary_path')}`")
        lines.append(f"- QEMU required: `{runtime.get('qemu_required')}`")
        lines.append(f"- QEMU guest path: `{runtime.get('qemu_guest_path')}`")
        lines.append(f"- Libraries OK: `{runtime.get('libraries_ok')}`")
        lines.append("")

        status = runtime.get("status") or {}

        if status:
            lines.append("### Runtime status")
            lines.append("")
            exit_code = status.get("guest_exit_code", status.get("exit_code"))
            lines.append(f"- Exit code: `{exit_code if exit_code is not None else 'unknown'}`")
            lines.append(f"- Timed out: `{status.get('timed_out')}`")
            lines.append(f"- Timeout seconds: `{status.get('timeout_seconds')}`")
            lines.append(f"- Duration seconds: `{status.get('duration_seconds')}`")
            lines.append(f"- Started at UTC: `{status.get('started_at_utc')}`")
            lines.append(f"- Finished at UTC: `{status.get('finished_at_utc')}`")
            lines.append(f"- Command: `{status.get('command')}`")
            lines.append("")

        host_binary = runtime.get("host_binary")
        if host_binary:
            lines.append("### Host binary metadata")
            lines.append("")
            lines.append(f"- Exists: `{host_binary.get('exists')}`")
            lines.append(f"- Size: `{host_binary.get('size_bytes')}` bytes")
            lines.append(f"- SHA256: `{host_binary.get('sha256')}`")
            lines.append("")

        lines.append("## Libraries")
        lines.append("")
        lines.append(f"- Requirements: `{libraries['requirements_count']}`")
        lines.append(f"- Resolved: `{libraries['resolved_count']}`")
        lines.append(f"- Missing: `{libraries['missing_count']}`")
        lines.append("")

        if libraries["resolved"]:
            lines.append("### Resolved libraries")
            lines.append("")
            lines.append("| Name | Kind | Guest path | Source path |")
            lines.append("|---|---|---|---|")

            for item in libraries["resolved"]:
                lines.append(
                    "| "
                    f"{self.md(item.get('name'))} | "
                    f"{self.md(item.get('kind'))} | "
                    f"`{item.get('guest_path')}` | "
                    f"`{item.get('source_path')}` |"
                )

            lines.append("")

        if libraries["missing"]:
            lines.append("### Missing libraries")
            lines.append("")
            lines.append("| Name | Kind | Guest path |")
            lines.append("|---|---|---|")

            for item in libraries["missing"]:
                lines.append(
                    "| "
                    f"{self.md(item.get('name'))} | "
                    f"{self.md(item.get('kind'))} | "
                    f"`{item.get('guest_path')}` |"
                )

            lines.append("")

        lines.append("## Network")
        lines.append("")
        lines.append(f"- Mode: `{network.get('mode')}`")
        lines.append(f"- Allow internet: `{network.get('allow_internet')}`")
        lines.append("- Mode and internet access above describe the saved configuration.")
        lines.append(f"- Network service log available: `{network.get('events_available')}`")
        lines.append(f"- Known services: `{network.get('services_count')}`")
        lines.append(f"- Total events: `{network.get('events_total')}`")
        lines.append(f"- Known TCP events: `{network.get('known_tcp_events')}`")
        lines.append(f"- Unknown TCP events: `{network.get('unknown_tcp_events')}`")
        lines.append(f"- UDP datagrams: `{network.get('udp_datagrams')}`")
        lines.append(f"- DNS datagrams: `{network.get('dns_datagrams')}`")
        lines.append(f"- DNS responses sent: `{network.get('dns_responses_sent')}`")
        lines.append(f"- DNS queries: `{network.get('dns_queries')}`")
        lines.append("")

        if network["services"]:
            lines.append("### Known services")
            lines.append("")
            lines.append("| Role | Remote | Local bind | Protocol hint |")
            lines.append("|---|---|---|---|")

            for service in network["services"]:
                remote = f"{service.get('remote_ip')}:{service.get('remote_port')}"
                local = f"{service.get('bind_ip')}:{service.get('bind_port')}"
                lines.append(
                    "| "
                    f"{self.md(service.get('role'))} | "
                    f"`{remote}` | "
                    f"`{local}` | "
                    f"{self.md(service.get('protocol_hint'))} |"
                )

            lines.append("")

        lines.append("### Observed targets")
        lines.append("")
        lines.append(f"- Known TCP targets: `{network.get('known_tcp_targets')}`")
        lines.append(f"- Unknown TCP targets: `{network.get('unknown_tcp_targets')}`")
        lines.append(f"- UDP targets: `{network.get('udp_targets')}`")
        lines.append("")

        network_attempts = syscalls.get("network_attempts") or []
        lines.append("### Network attempts from malware syscalls")
        lines.append("")
        lines.append(f"- Recorded connect/send attempts: `{syscalls.get('network_attempts_count', 0)}`")
        lines.append(f"- Attempts with an undecoded endpoint: `{syscalls.get('network_attempts_without_endpoint_count', 0)}`")
        lines.append("")
        if network_attempts:
            lines.append("| Syscall | Target | Result |")
            lines.append("|---|---|---|")

            for event in network_attempts[:50]:
                target = event.get("target") or "unknown (endpoint not decoded)"
                lines.append(
                    "| "
                    f"`{event.get('syscall')}` | "
                    f"`{target}` | "
                    f"`{event.get('result')}` |"
                )
        elif syscalls.get("observation_available") is False:
            lines.append("- Syscall processing is unavailable; network attempts are unknown.")
        else:
            lines.append("- No network attempts recorded from malware syscalls.")
        lines.append("")

        http_requests = network.get("http_requests") or []
        lines.append("### Observed HTTP requests")
        lines.append("")
        if http_requests:
            lines.append("| Method | Host | Path | Original target | User-Agent |")
            lines.append("|---|---|---|---|---|")

            for item in http_requests[:50]:
                original_target = (
                    f"{item.get('original_remote_ip')}:{item.get('original_remote_port')}"
                )

                lines.append(
                    "| "
                    f"`{item.get('method')}` | "
                    f"`{item.get('host')}` | "
                    f"`{item.get('path')}` | "
                    f"`{original_target}` | "
                    f"`{item.get('user_agent')}` |"
                )
        else:
            lines.append("- No HTTP requests recorded.")
        lines.append("")


        lines.append("### Event types")
        lines.append("")
        if network["events_by_type"]:
            for name, count in sorted(network["events_by_type"].items()):
                lines.append(f"- `{name}`: `{count}`")
        else:
            lines.append("- No network events recorded.")
        lines.append("")

        lines.append("## Syscalls")
        lines.append("")
        lines.append(f"- Total syscall events: `{syscalls.get('events_total')}`")
        lines.append(f"- High-risk events: `{syscalls.get('high_risk_count')}`")
        lines.append("")

        lines.append("### Syscalls by category")
        lines.append("")
        by_category = syscalls.get("by_category") or {}
        if by_category:
            for name, count in sorted(by_category.items()):
                lines.append(f"- `{name}`: `{count}`")
        else:
            lines.append("- Syscall processing is unavailable." if syscalls.get("observation_available") is False else "- No syscall events recorded.")
        lines.append("")

        lines.append("### Top syscalls")
        lines.append("")
        by_syscall = syscalls.get("by_syscall") or {}
        if by_syscall:
            top_syscalls = sorted(
                by_syscall.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:20]

            for name, count in top_syscalls:
                lines.append(f"- `{name}`: `{count}`")
        else:
            lines.append("- Syscall processing is unavailable." if syscalls.get("observation_available") is False else "- No syscall events recorded.")
        lines.append("")

        malware_paths = syscalls.get("paths") or []
        lines.append("### Observed malware filesystem paths")
        lines.append("")
        if malware_paths:
            for path in malware_paths[:50]:
                lines.append(f"- `{path}`")
            if len(malware_paths) > 50:
                lines.append(f"- ... truncated, total malware paths: `{len(malware_paths)}`")
        else:
            lines.append("- Syscall paths are unavailable." if syscalls.get("observation_available") is False else "- No malware filesystem paths recorded.")
        lines.append("")

        high_risk = syscalls.get("high_risk_events") or []
        lines.append("### High-risk syscall events")
        lines.append("")
        if high_risk:
            lines.append("| Syscall | Result | Source | Raw |")
            lines.append("|---|---|---|---|")

            for event in high_risk[:20]:
                raw = str(event.get("raw", "")).replace("|", "\\|")
                lines.append(
                    "| "
                    f"`{event.get('syscall')}` | "
                    f"`{event.get('result')}` | "
                    f"`{event.get('source_file')}:{event.get('line_number')}` | "
                    f"`{raw[:160]}` |"
                )
        else:
            lines.append("- Syscall risk assessment is unavailable." if syscalls.get("observation_available") is False else "- No high-risk syscall events recorded.")
        lines.append("")

        lines.append("## Filesystem mutations")
        lines.append("")
        filesystem_available = filesystem.get("observation_available") is True
        lines.append(f"- Observation available: `{filesystem_available}`")
        if not filesystem_available:
            lines.append("- Filesystem changes are unknown: no usable before/after diff was recorded.")
        lines.append(f"- Created files/entries: `{filesystem.get('created_count')}`")
        lines.append(f"- Modified files/entries: `{filesystem.get('modified_count')}`")
        lines.append(f"- Deleted files/entries: `{filesystem.get('deleted_count')}`")
        lines.append("")

        created = filesystem.get("created") or []
        lines.append("### Created entries")
        lines.append("")
        if not filesystem_available:
            lines.append("- Created entries were not established.")
        elif created:
            lines.append("| Path | Type | Size | SHA256 |")
            lines.append("|---|---|---:|---|")

            for item in created[:50]:
                lines.append(
                    "| "
                    f"`{item.get('path')}` | "
                    f"`{item.get('type')}` | "
                    f"{item.get('size')} | "
                    f"`{item.get('sha256')}` |"
                )
        else:
            lines.append("- No created entries.")
        lines.append("")

        modified = filesystem.get("modified") or []
        lines.append("### Modified entries")
        lines.append("")
        if not filesystem_available:
            lines.append("- Modified entries were not established.")
        elif modified:
            lines.append("| Path | Changes |")
            lines.append("|---|---|")

            for item in modified[:50]:
                changes = ", ".join(sorted((item.get("changes") or {}).keys()))
                lines.append(
                    "| "
                    f"`{item.get('path')}` | "
                    f"`{changes}` |"
                )
        else:
            lines.append("- No modified entries.")
        lines.append("")

        deleted = filesystem.get("deleted") or []
        lines.append("### Deleted entries")
        lines.append("")
        if not filesystem_available:
            lines.append("- Deleted entries were not established.")
        elif deleted:
            lines.append("| Path | Type | Size | SHA256 |")
            lines.append("|---|---|---:|---|")

            for item in deleted[:50]:
                lines.append(
                    "| "
                    f"`{item.get('path')}` | "
                    f"`{item.get('type')}` | "
                    f"{item.get('size')} | "
                    f"`{item.get('sha256')}` |"
                )
        else:
            lines.append("- No deleted entries.")
        lines.append("")

        lines.append("## Artifacts")
        lines.append("")
        lines.append(f"- Payload files: `{artifacts['payload_count']}`")
        lines.append("")

        if artifacts["payload_files"]:
            lines.append("| File | Size | SHA256 |")
            lines.append("|---|---:|---|")

            for item in artifacts["payload_files"]:
                lines.append(
                    "| "
                    f"`{item.get('path')}` | "
                    f"{item.get('size_bytes')} | "
                    f"`{item.get('sha256')}` |"
                )

            lines.append("")

        lines.append("## Security model")
        lines.append("")
        lines.append("Runtime fields come from the saved security status. Unknown means no value was recorded.")
        lines.append("Configured isolation and internet access describe intended setup; they do not verify enforcement.")
        lines.append("")
        for key, value in security.items():
            if isinstance(value, (dict, list)):
                rendered = json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            else:
                rendered = str(value) if value is not None else "unknown"

            lines.append(f"- `{key}`: `{rendered}`")
        lines.append("")
        lines.append("## Runtime stdout preview")
        lines.append("")
        lines.append("```text")
        lines.append(logs.get("runtime_stdout") or "")
        lines.append("```")
        lines.append("")

        lines.append("## Runtime stderr preview")
        lines.append("")
        lines.append("```text")
        lines.append(logs.get("runtime_stderr") or "")
        lines.append("```")
        lines.append("")

        lines.append("## Network self-test stdout preview")
        lines.append("")
        lines.append("```text")
        lines.append(logs.get("network_self_test_stdout") or "")
        lines.append("```")
        lines.append("")

        return "\n".join(lines)

    def load_json_optional(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}

        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                return {"_error": f"Expected a JSON object: {path}"}
            return value
        except json.JSONDecodeError:
            return {
                "_error": f"Invalid JSON: {path}",
            }

    def load_jsonl_optional(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []

        events = []

        for line in iter_log_lines(path):
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return events

    def read_text_optional(self, path: Path, limit: int = PREVIEW_CHARS) -> str:
        if not path.exists():
            return ""

        data, truncated = read_log_preview(path, limit)
        return data + "\n...[truncated]..." if truncated else data

    def file_info(self, path: Path) -> dict[str, Any]:
        return {
            "path": self.rel(path),
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() and path.is_file() else None,
            "sha256": self.sha256(path) if path.exists() and path.is_file() else None,
        }

    @staticmethod
    def sha256(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def unique_targets(events: list[dict[str, Any]]) -> list[str]:
        targets = set()

        for event in events:
            ip = event.get("original_remote_ip")
            port = event.get("original_remote_port")

            if ip is None or port is None:
                continue

            targets.add(f"{ip}:{port}")

        return sorted(targets)

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.out_dir))
        except ValueError:
            return str(path)

    @staticmethod
    def md(value: Any) -> str:
        if value is None:
            return ""

        return str(value).replace("|", "\\|")


def generate_report(out_dir: str | Path) -> dict[str, Any]:
    generator = RunReportGenerator(out_dir=out_dir)
    return generator.generate()
