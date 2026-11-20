"""M5 admission evidence for a live post-retirement AFL coordinator."""
from pathlib import Path
import re

from . import afl_file as f, analysis_quality, capsule_control, capsule_hardening

PROFILE = 'warm-m5-capsule-v1'
SOURCES = ('taintforge_env/afl_capsule.py', 'taintforge_env/capsule_control.py',
           'taintforge_env/capsule_supervision.py', 'taintforge_env/analysis_quality.py',
           'taintforge_env/capsule_hardening.py', 'taintforge_env/phase1_retirement.py',
           'experiments/retirement_observer/control_guard.h')


def enabled(config):
    return config.get('capsule_profile') == PROFILE


def validate_binding(binding):
    """Only the bound warm profile may combine M5 with AFL input plumbing."""
    warm = binding.get('afl_warm', {})
    guarded = 'control_guard' in binding.get('settings', {})
    if enabled(warm):
        return binding_policy(binding)
    if guarded:
        f.p.require(not any(k in binding for k in ('afl_file', 'afl_warm')),
                    'M5 AFL requires the admitted warm capsule profile')


def binding_policy(binding):
    settings = binding.get('settings', {})
    f.p.require(enabled(binding.get('afl_warm', {})), 'Warm M5 profile is not bound')
    capsule_control.validate(settings.get('control_guard'))
    capsule_hardening.config(binding)
    capsule_control.verify_bundle(binding['capsule'])
    return analysis_quality.validate(settings.get('analysis_policy'))


def checkpoint(binding, pid):
    """Replay saved proof at HOLD 2; safe both before AFL and after exit."""
    from . import phase1_retirement as retirement
    from experiments.retirement_observer import controller as observer

    policy = binding_policy(binding)
    retired = retirement.verify_retirement(binding, pid)
    decision = retired.get('analysis_quality', {})
    analysis_quality.require_accepted(decision)
    f.p.require(decision.get('policy') == policy and decision.get('identity') ==
                {k: binding[k] for k in ('session_id', 'attempt_id', 'analysis_instance_id', 'lifecycle_attempt')},
                'Warm analysis decision belongs to another policy or attempt')
    root = Path(binding['run_dir'])
    journal = f.read_json(root/'logs/capsule/observer-events.json')
    events = [{k: v for k, v in e.items() if k not in ('controller_seq', 'controller_ns')}
              for e in journal['events']]
    protocol = observer.observation_protocol(binding['observer'])
    private = capsule_control.private_prefix(binding)
    snapshots = []
    for sample in (1, 2):
        matches = [e for e in events if e.get('event') == 'snapshot' and
                   e.get('point') == 2 and e.get('sample') == sample]
        f.p.require(len(matches) == 1, 'Missing or duplicate warm post-unmap snapshot')
        observer.snapshot_ok(matches[0], pid, 2, sample, protocol, control_guard=private)
        snapshots.append(matches[0])
    observer.same_hold(*snapshots, binding['observer']['hold_ms'])
    f.p.require(snapshots[-1]['control_guard']['checked_syscalls'] > 0,
                'Warm M5 syscall guard has not observed the guest')
    hardening = capsule_hardening.verify_saved(binding, events, pid)
    report = f.read_json(retirement.analysis(binding).paths['report'])
    capsule_hardening.verify_ledger(binding, retired['events'][-1]['data'], report)
    return {'schema': 1, 'profile': PROFILE, 'status': 'admitted',
            'identity': {k: binding[k] for k in
                         ('session_id', 'attempt_id', 'attempt_contract_sha256', 'analysis_instance_id', 'lifecycle_attempt')},
            'parent_namespace_pid': pid, 'phase1_runs': 1,
            'analysis_quality': decision,
            'control_guard': snapshots[-1]['control_guard'],
            'execution_context_sha256': hardening['contexts'],
            'phase1_output_fds_released': hardening['phase1_output_fds_released'],
            'memory_isolation': False, 'hostile_sample_ready': False}


def verify_completion(binding, capsule):
    root = Path(binding['run_dir'])
    saved = f.read_json(root/'logs/capsule/afl-checkpoint.json')
    f.p.require(capsule.get('status') == 'passed', 'Warm M5 capsule did not finish')
    expected = checkpoint(binding, capsule['qemu_pid'])
    f.p.require(saved == expected, 'Warm M5 checkpoint evidence changed')
    f.p.require(capsule.get('analysis_quality') == saved['analysis_quality'] and
                capsule.get('control_guard', {}).get('status') == 'verified',
                'Warm M5 final evidence does not match checkpoint admission')
    return saved


def verify_ready(ready, policy, *, contract=None, session_id=None, run_dir=None):
    """The owner-readable broker record precedes the independently checked close."""
    analysis_quality.validate(policy)
    value = ready.get('capsule_checkpoint', {})
    f.p.require(isinstance(value, dict) and value.get('profile') == PROFILE and
                type(value.get('schema')) is int and value['schema'] == 1 and value.get('status') == 'admitted' and
                type(value.get('parent_namespace_pid')) is int and
                value['parent_namespace_pid'] > 0 and
                value['parent_namespace_pid'] == ready.get('pid_namespace_pid') and
                type(value.get('phase1_runs')) is int and value['phase1_runs'] == 1 and
                value.get('phase1_output_fds_released') is True,
                'Warm M5 checkpoint was not admitted')
    decision = value.get('analysis_quality', {})
    analysis_quality.require_accepted(decision)
    f.p.require(decision.get('policy') == policy, 'Warm M5 readiness policy mismatch')
    identity = value.get('identity', {})
    keys = ('session_id', 'attempt_id', 'attempt_contract_sha256', 'analysis_instance_id', 'lifecycle_attempt')
    f.p.require(isinstance(identity, dict) and set(identity) == set(keys) and
                all(isinstance(identity[k], str) and identity[k] for k in keys) and
                re.fullmatch(r'[0-9a-f]{64}', identity['attempt_contract_sha256']) and
                re.fullmatch(r'[0-9a-f]{32}', identity['lifecycle_attempt']) and
                decision.get('identity') == {k: identity[k] for k in keys if k != 'attempt_contract_sha256'},
                'Warm M5 checkpoint identity mismatch')
    if contract is not None:
        f.p.require(identity['attempt_id'] == contract.attempt_id and
                    identity['attempt_contract_sha256'] == contract.contract_sha256,
                    'Warm M5 checkpoint belongs to another attempt contract')
    if session_id is not None:
        f.p.require(identity['session_id'] == session_id, 'Warm M5 checkpoint belongs to another session')
    if run_dir is not None:
        f.p.require(ready.get('run_dir') == str(run_dir), 'Warm M5 checkpoint belongs to another run')
    private=ready.get('run_dir')
    f.p.require(isinstance(private,str),'Warm M5 readiness has no run path')
    capsule_control.private_prefix({'run_dir':private,'control_guard_private_path':private})
    capsule_control.verify_snapshot(value.get('control_guard'),private=private)
    contexts=value.get('execution_context_sha256')
    f.p.require(isinstance(contexts,list) and len(contexts)==2 and
                all(isinstance(x,str) and re.fullmatch(r'[0-9a-f]{64}',x) for x in contexts),
                'Warm M5 readiness has no execution context evidence')
    f.p.require(value['control_guard']['checked_syscalls'] > 0, 'Warm M5 guard was never active')
    return value
