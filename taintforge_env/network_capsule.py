"""Bind fresh i386 retirement attempts to their owned controlled network runtime."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from .network_policy import load_network_policy
from .network_namespace import NETNS_ROOT, namespace_identity
from .network_runtime import NetworkRuntimeClient, NetworkRuntimeError, _private_json, _regular
from .phase1_runtime import read_json
from .unified_runtime import canonical_hash


PROFILE = "network-capsule-static-i386-v1"
IDENTITY = ("session_id", "attempt_id", "attempt_contract_sha256", "analysis_instance_id", "bundle_sha256")
MODES = {"controlled", "replay", "record"}


def require(condition, message):
    if not condition:
        raise NetworkRuntimeError(message)


def digest(path):
    return hashlib.sha256(_regular(path, 1024 * 1024)).hexdigest()


def validate_mode(mode, settings, *, observer=False, warm=False):
    require(mode in {"none", *MODES}, "unsupported capsule network mode")
    if mode == "none":
        return
    require(observer, "network retirement requires --network-observer")
    require(not warm, "network retirement does not support AFL warm/file checkpoints")
    require("control_guard" not in settings,
            "the fd/path control guard does not admit network syscalls; its policy cannot be relaxed implicitly")


def policy_identity(path):
    return canonical_hash(load_network_policy(path).to_dict())


def staged_profile(context, runtime, phase1):
    mode = runtime["network_mode"]
    validate_mode(mode, runtime["capsule"], observer="network_observer" in phase1,
                  warm=any(key in runtime for key in ("afl_file", "afl_warm")))
    if mode == "none":
        return None
    effective = getattr(context, "effective_network_policy", None)
    policy_hash = canonical_hash(effective.to_dict()) if effective is not None else policy_identity(context.template_network_policy_path)
    return {"profile": PROFILE, "mode": mode, "policy_sha256": policy_hash,
            "observer": phase1["network_observer"],
            "execution_timeout_ms": runtime["capsule"]["total_ms"] - 1000}


def runtime_path(binding):
    return Path(binding["run_dir"]) / "config/network_capsule_runtime.json"


def bind_runtime(binding, command, backend):
    """Called after network setup, before starting this attempt's systemd service."""
    root = Path(binding["run_dir"])
    require(binding.get("network", {}).get("profile") == PROFILE, "capsule network profile is not bound")
    require(backend.runtime is not None and backend.plan is not None, "controlled network runtime is not ready")
    require(backend.runtime.attempt_id == binding["attempt_id"], "network runtime belongs to another attempt")
    require(policy_identity(root / "config/network_policy_requested.json") == binding["network"]["policy_sha256"],
            "requested network policy differs from the staged capsule")
    command = list(map(str, command))
    require(command[:5] == ["sudo", "-n", "ip", "netns", "exec"], "unexpected controlled network command")
    require(command[5] == backend.plan.namespace_name, "controlled command names another namespace")
    guard = str(backend.config.project_root / "scripts/run_network_guard.py")
    require(command.count(guard) == 1 and command[-1] == str(root / "run_prebuilt_sandbox.sh"),
            "controlled command does not execute the bound wrapper")
    separator = command.index("--", command.index(guard))
    command[separator:separator] = ["--capsule-binding", str(root / "config/capsule_binding.json")]
    descriptor = backend.runtime.client_path
    client = NetworkRuntimeClient(descriptor)
    record = {"schema_version": 1, "profile": PROFILE, **{key: binding[key] for key in IDENTITY},
        "lifecycle_attempt": binding["lifecycle_attempt"], "network": binding["network"],
        "capsule_binding_sha256": digest(root / "config/capsule_binding.json"),
        "namespace": namespace_identity(backend.plan.namespace_name),
        "descriptor": {"path": str(descriptor), "sha256": digest(descriptor), "limits_sha256": client.limits.sha256},
        "policies": {name: digest(root / "config" / name) for name in
                     ("network_policy_requested.json", "network_policy.json")}, "command": command}
    record["contract_sha256"] = canonical_hash(record)
    require(not runtime_path(binding).exists(), "capsule network runtime was already bound")
    _private_json(runtime_path(binding), record)
    verify_runtime(binding, live=True)
    return command


def verify_runtime(binding, *, live=False, inside_namespace=False):
    require(binding.get('profile') == 'input-static-i386-retirement-m3'
            and binding.get('network', {}).get('profile') == PROFILE,
            'network runtime requires its fresh static i386 capsule profile')
    record = json.loads(_regular(runtime_path(binding), 1024 * 1024))
    require(isinstance(record, dict) and record.get("schema_version") == 1 and record.get("profile") == PROFILE,
            "invalid capsule network runtime record")
    body = {key: value for key, value in record.items() if key != "contract_sha256"}
    require(record.get("contract_sha256") == canonical_hash(body), "capsule network runtime digest differs")
    require(all(record.get(key) == binding[key] for key in IDENTITY)
            and record.get("lifecycle_attempt") == binding["lifecycle_attempt"]
            and record.get("network") == binding.get("network"), "capsule/network attempt identities differ")
    root = Path(binding["run_dir"])
    require(record["capsule_binding_sha256"] == digest(root / "config/capsule_binding.json"),
            "capsule binding changed after network setup")
    require(set(record["policies"]) == {"network_policy_requested.json", "network_policy.json"},
            "capsule network policy inventory differs")
    for name, expected in record["policies"].items():
        require(digest(root / "config" / name) == expected, "bound network policy changed: " + name)
    expected_descriptor = root / "config/network_runtime/client.json"
    require(record["descriptor"]["path"] == str(expected_descriptor), "network descriptor escapes this attempt")
    if live:
        require(digest(expected_descriptor) == record["descriptor"]["sha256"], "network runtime descriptor changed")
        client = NetworkRuntimeClient(expected_descriptor)
        require(client.attempt_id == binding["attempt_id"] and client.limits.sha256 == record["descriptor"]["limits_sha256"],
                "network runtime limits or attempt changed")
        require(namespace_identity(record["namespace"]["name"]) == record["namespace"],
                "owned network namespace was replaced")
    if inside_namespace:
        current = os.stat("/proc/self/ns/net")
        require((current.st_dev, current.st_ino) == (record["namespace"]["device"], record["namespace"]["inode"]),
                "capsule is outside its bound network namespace")
    return record


def service_command(binding, command):
    record = verify_runtime(binding, live=True)
    require(list(command) == record["command"], "capsule service command differs from its network contract")
    name = record["namespace"]["name"]
    require(command[:6] == ["sudo", "-n", "ip", "netns", "exec", name],
            "capsule service requires its exact owned namespace command")
    # ip netns exec replaces /sys, hiding the service's cgroup mount.
    return ["nsenter", f"--net={NETNS_ROOT / name}", "--", *command[6:]]


class NetworkCapsuleStopped(NetworkRuntimeError):
    def __init__(self, reason, *, runtime_error=None):
        self.reason = reason
        self.failure = {"category": "network_runtime", "component": "network", "stage": "qemu_wait",
                        "exception_type": type(self).__name__, "errno": None, "message": reason}
        if runtime_error is not None:
            self.failure["runtime_error"] = runtime_error
        super().__init__(reason)


class Monitor:
    def __init__(self, binding):
        self.binding = binding
        self.record = verify_runtime(binding, live=True, inside_namespace=True)
        self.client = NetworkRuntimeClient(self.record["descriptor"]["path"])
        self.deadline = None

    def arm(self):
        self.deadline = time.monotonic() + self.binding["network"]["execution_timeout_ms"] / 1000

    def check(self):
        cancel = Path(self.binding["run_dir"]) / "logs/capsule/network_cancel.json"
        reason = None
        runtime_error = None
        if cancel.exists():
            request = json.loads(_regular(cancel))
            require(request.get("attempt_id") == self.binding["attempt_id"], "network cancellation belongs to another attempt")
            reason = request.get("reason")
            require(isinstance(reason, str) and reason.startswith("network_"), "invalid network cancellation reason")
            runtime_error = request.get("runtime_error")
            require(runtime_error is None or isinstance(runtime_error, dict), "invalid network runtime error details")
        try:
            status = self.client.call("status")
            reason = status["termination_reason"] or reason
        except NetworkRuntimeError as exc:
            reason = reason or "network_runtime_owner_lost"
            runtime_error = runtime_error or {"error": str(exc), "details": exc.details}
        if reason is None and self.deadline is not None and time.monotonic() >= self.deadline:
            reason = "network_capsule_timeout"
            self.client.fail(reason)
        if reason:
            self.client.fail(reason)
            try:
                reason = self.client.call('status')['termination_reason'] or reason
            except NetworkRuntimeError:
                pass
            raise NetworkCapsuleStopped(reason, runtime_error=runtime_error)


def request_cancel(binding, reason, *, runtime_error=None):
    verify_runtime(binding, live=False)
    request = {"schema_version": 1, "attempt_id": binding["attempt_id"], "reason": reason}
    if runtime_error is not None:
        request["runtime_error"] = runtime_error
    _private_json(Path(binding["run_dir"]) / "logs/capsule/network_cancel.json", request)


def stop_qemu(process, seconds):
    deadline = time.monotonic() + seconds
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=max(0.01, seconds * 0.6))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
    return process.wait()


def interrupted_retirement(binding, result):
    """Verify a saved post-unmap prefix; never invent an observer DONE event."""
    from experiments.retirement_observer import controller as observer
    from . import phase1_retirement as retirement, retirement_mappings as mappings
    output = Path(binding["run_dir"]) / "logs/capsule"
    controller_path = output / 'controller.json'
    if controller_path.exists():
        controller = read_json(controller_path, 256 * 1024)
        require(not controller.get('evidence_persistence_error'),
                'observer evidence persistence failed: ' + str(controller.get('evidence_persistence_error')))
    journal = read_json(output / "observer-events.json", 256 * 1024)
    events = journal["events"]
    require(journal.get("schema") == 2 and 0 < len(events) <= 40, "invalid interrupted observer journal")
    for index, event in enumerate(events, 1):
        require(event.get("controller_seq") == index and type(event.get("controller_ns")) is int
                and event["controller_ns"] > 0 and (index == 1 or event["controller_ns"] >= events[index-2]["controller_ns"]),
                "invalid interrupted observer ordering")
    events = [{key: value for key, value in event.items() if key not in ('controller_seq', 'controller_ns')}
              for event in events]
    kinds = [event["command"] if event["event"] == "command" else event["event"] for event in events]
    prefix = ["snapshot", "maps_held", "CHECK 1", "snapshot", "RESUME 1", "resumed", "export_ready", "STAMP", "stamp",
              "permit_grant", "released", "module_unmapped", "HOLD 2", "snapshot", "maps_held", "CHECK 2", "snapshot", "RESUME 2", "resumed"]
    require(kinds[:len(prefix)] == prefix and kinds[len(prefix):] in
            ([], ["progress_window"], ["progress_window", "done"], ["progress_window", "early_exit"]),
            "network stop lacks a complete post-unmap resume prefix")
    pid = result["qemu_pid"]
    identity = mappings.load_identity(binding)
    retired = retirement.verify_retirement(binding, pid)
    for point in (1, 2):
        snapshots = [event for event in events if event["event"] == "snapshot" and event["point"] == point]
        require(len(snapshots) == 2, "network stop lacks held snapshots")
        for sample, snap in enumerate(snapshots, 1):
            observer.snapshot_ok(snap, pid, point, sample, observer.PROTOCOL)
        observer.same_hold(*snapshots, binding["observer"]["hold_ms"])
        if point == 1:
            require(snapshots[0]['seq'] == 1 and snapshots[0]['pc'] == binding['input_retirement']['entry_point'],
                    'interrupted bootstrap differs from the original input')
        resumed = [e for e in events if e['event'] == 'resumed' and e['point'] == point]
        require(len(resumed) == 1 and resumed[0].get('protocol') == observer.PROTOCOL
                and resumed[0]['seq'] == snapshots[0]['seq'], 'interrupted resume does not match its hold')
        held = next(event for event in events if event["event"] == "maps_held" and event["point"] == point)
        mappings.verify_observation(binding, held, pid)
    unmapped = next(event for event in events if event["event"] == "module_unmapped")
    directory = retirement.directory(binding)
    for filename, key in (("maps-unmapped.txt", "maps_sha256"), ("process-unmapped.stat", "process_stat_sha256")):
        require(hashlib.sha256((directory / filename).read_bytes()).hexdigest() == unmapped[key], "unmap observation changed")
    require(mappings.process_identity((directory / "process-unmapped.stat").read_text()) ==
            (pid, identity["process_start_ticks"]), "unmap process identity changed")
    mappings.verdict(identity, (directory / "maps-unmapped.txt").read_text(), True)
    stamp = next(e for e in events if e['event'] == 'stamp')
    permit = next(e for e in events if e['event'] == 'permit_grant')
    held = next(e for e in events if e['event'] == 'snapshot' and e['point'] == 2)
    require(stamp.get('protocol') == observer.PROTOCOL and stamp.get('host_pid') == pid
            and type(stamp.get('seq')) is int and stamp['seq'] >= 1
            and permit['pre_permit_seq'] == stamp['seq'] and held['seq'] >= stamp['seq']
            and held['monotonic_ms'] >= stamp['monotonic_ms'], 'invalid interrupted progress stamp')
    if len(kinds) > len(prefix):
        window = events[len(prefix)]
        require(window == dict(event='progress_window', scope=observer.WINDOW, lower_seq=stamp['seq'],
                upper_seq=held['seq'], entries=held['seq']-stamp['seq'], exact_uninstall_interval=False,
                exact_oep_cutover=False), 'invalid interrupted progress window')
    if kinds[-1] in {'done', 'early_exit'}:
        last = events[-1]
        require(last.get('protocol') == observer.PROTOCOL and last.get('host_pid') == pid
                and type(last.get('seq')) is int and last['seq'] > held['seq'], 'invalid terminal observer event')
    result = {"status": "verified", "scope": "retirement_and_post_unmap_resume_prefix",
            "phase1_retired": True, "observer_completed": kinds[-1] == "done",
            "observer_journal_sha256": digest(output / "observer-events.json"), "claims": retirement.CLAIMS}
    if 'hardening' in binding['settings']:
        from . import capsule_hardening as m4
        result['hardening'] = m4.verify_saved(binding, events, pid)
        m4.verify_ledger(binding, retired['events'][-1]['data'], read_json(retirement.analysis(binding).paths['report']))
    return result


def finalize_interrupted(binding, result, guest_exit):
    from . import capsule_resources, phase1_retirement
    record = verify_runtime(binding)
    stop = result["network_termination"]
    require(all(stop.get(key) == binding[key] for key in IDENTITY), "network stop belongs to another attempt")
    runtime = read_json(Path(binding["run_dir"]) / "logs/network_runtime_status.json")
    require(runtime.get("attempt_id") == binding["attempt_id"]
            and runtime.get("limits_sha256") == record["descriptor"]["limits_sha256"]
            and runtime.get("termination_reason") == stop.get("reason"), "network stop differs from final runtime evidence")
    summary = {**result, "status": "interrupted", "network_termination": stop, "claims": phase1_retirement.CLAIMS,
               "application_success": "evaluated_separately_by_phase2"}
    try:
        summary["retirement_before_stop"] = interrupted_retirement(binding, result)
    except (OSError, ValueError, RuntimeError, KeyError, StopIteration) as exc:
        summary["retirement_before_stop"] = {"status": "unverified", "error": str(exc)[:1000]}
    summary["resources"] = capsule_resources.verify_saved(binding, guest_exit)
    return summary


def finalize_integration(binding):
    """Publish independent component facts before deciding whether this attempt may complete."""
    verify_runtime(binding)
    root = Path(binding['run_dir'])
    capsule = read_json(root / 'config/capsule_result.json')
    phase = read_json(root / 'config/phase1_result.json')
    network = read_json(root / 'logs/network_runtime_status.json')
    require(network.get('attempt_id') == binding['attempt_id']
            and all(capsule.get(key) == binding[key] for key in IDENTITY), 'network/capsule finalization identities differ')
    retired = (capsule.get('phase1_retirement', {}).get('phase1_retired') is True or
               capsule.get('retirement_before_stop', {}).get('status') == 'verified')
    tree_empty = capsule.get('resources', {}).get('tree_empty') is True
    cleared = tree_empty and network.get('cleanup_status') == 'cleaned'
    observed = phase.get('artifact_integrity') == 'verified' and phase.get('runtime_observed') is True
    reason = network.get('termination_reason')
    complete = capsule.get('status') == 'passed' and reason is None and retired and observed and cleared
    receipt = {'schema_version': 1, 'profile': PROFILE, **{key: binding[key] for key in IDENTITY},
        'status': 'passed' if complete else 'interrupted' if reason and cleared else 'failed',
        'phase1_runtime_verified': observed, 'phase1_retired': retired, 'capsule_tree_empty': tree_empty,
        'network_cleanup': network.get('cleanup_status'), 'network_termination_reason': reason,
        'application_success': 'evaluated_separately_by_phase2',
        'evidence_sha256': {name: digest(root / name) for name in
            ('config/capsule_result.json', 'config/phase1_result.json', 'logs/network_runtime_status.json')}}
    _private_json(root / 'config/network_capsule_result.json', receipt)
    require(complete, 'network/capsule integration did not complete: ' + str(reason or capsule.get('status')))
    return receipt
