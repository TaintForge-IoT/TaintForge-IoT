"""Separate a verified warm coordinator's completion from its child findings."""
from __future__ import annotations

import json
from pathlib import Path


def completed_coordinator(artifacts, contract, guest_exit_code, timed_out):
    """Return True only for a clean, bound, finalized warm parent.

    The aggregate trace retains every child's signal. Those signals remain
    findings, but cannot determine the coordinator's exit status. Individual
    case analysis and ordinary attempts keep their existing signal semantics.
    """
    config = Path(artifacts)/'config'

    def read(name):
        path = config/name
        if path.is_symlink():
            raise ValueError('Invalid warm coordinator evidence: '+name)
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError('Invalid warm coordinator evidence: '+name)
        return value

    if not (config/'runtime.json').exists():
        return False
    runtime = read('runtime.json')
    if 'afl_warm' not in runtime or 'afl_case' in runtime:
        return False

    def require(condition, reason):
        if not condition:
            raise ValueError('Unverified warm coordinator: '+reason)

    def object_field(value, key):
        item = value.get(key)
        require(isinstance(item, dict), 'missing or invalid object: '+key)
        return item

    from .afl_warm import validate
    warm = validate(runtime['afl_warm'])
    binding = read('capsule_binding.json')
    capsule = read('capsule_result.json')
    execution = read('prebuilt_execution.json')
    finalization = read('finalization_status.json')
    require(binding.get('afl_warm') == warm, 'configuration mismatch')
    for item in (binding, capsule, finalization):
        require(item.get('attempt_id') == contract.attempt_id and
                item.get('attempt_contract_sha256') == contract.contract_sha256,
                'attempt identity mismatch')
    for key in ('session_id', 'analysis_instance_id', 'bundle_sha256'):
        require(isinstance(binding.get(key), str) and bool(binding[key]) and
                capsule.get(key) == binding[key], 'capsule identity mismatch: '+key)
    require(capsule.get('status') == 'passed' and
            capsule.get('restart') == 'live_post_retirement_fork', 'capsule did not pass')
    for value in (guest_exit_code, execution.get('guest_exit_code'),
                  capsule.get('qemu_exit'), capsule.get('controller_exit')):
        require(type(value) is int and value == 0, 'parent or controller did not exit cleanly')
    require(timed_out is False and execution.get('timed_out') is False and
            capsule.get('supervisor_kill') is False and
            isinstance(capsule.get('controller_failures'), list) and capsule['controller_failures'] == [],
            'parent interrupted or controller failed')
    retirement = object_field(capsule, 'phase1_retirement')
    require(retirement.get('status') == 'verified' and retirement.get('phase1_retired') is True,
            'Phase 1 retirement not verified')
    resources = object_field(capsule, 'resources')
    require(resources.get('status') == 'verified' and resources.get('tree_empty') is True,
            'service cleanup not verified')
    require(object_field(capsule, 'hardening').get('status') == 'verified', 'hardening not verified')
    from . import afl_capsule, capsule_control
    if afl_capsule.enabled(warm):
        capsule_control.validate(binding.get('settings', {}).get('control_guard'))
        admitted = afl_capsule.verify_ready({'capsule_checkpoint': capsule.get('afl_checkpoint'),
            'pid_namespace_pid': capsule.get('qemu_pid'), 'run_dir': binding.get('run_dir')},
            runtime['capsule']['analysis_policy'], contract=contract,
            session_id=binding['session_id'], run_dir=binding['run_dir'])
        require(admitted['identity'] == {k: binding[k] for k in admitted['identity']} and
                capsule.get('analysis_quality') == admitted['analysis_quality'] and
                object_field(capsule, 'control_guard').get('status') == 'verified',
                'M5 checkpoint and final evidence differ')
    worker = object_field(capsule, 'warm')
    require(worker.get('status') == 'passed' and type(worker.get('phase1_runs')) is int and
            worker['phase1_runs'] == 1 and type(worker.get('children')) is int and worker['children'] >= 0,
            'executor did not finish one warm session')
    require(finalization.get('status') == 'completed' and
            finalization.get('guest_stop_confirmed') is True, 'finalization incomplete')
    stages = object_field(finalization, 'stages')
    for name in ('execution', 'filesystem', 'phase1', 'syscalls', 'requirements', 'repair_plan', 'capsule'):
        require(object_field(stages, name).get('status') == 'completed', 'finalization stage: '+name)
    require(object_field(stages, 'network_cleanup').get('status') == 'not_applicable',
            'warm profile requires network=none')
    return True
