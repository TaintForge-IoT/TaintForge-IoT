"""Bounded filesystem-repair epochs; never modify a live warm parent."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import shutil

from . import afl_file as f
from .afl_replay import clone_campaign
from .repair_plan import RepairActionKind, RepairPlan
from .repair_applier import RepairApplier, RepairApplierConfig
from .afl_evidence import completed_cases, child_report, reusable


def collect(source, staging):
    """Deduplicate authorized directory decisions, retaining exact requirements."""
    source, staging = Path(source), Path(staging)
    staging.mkdir(parents=True, exist_ok=False)
    seen, selected, deferred = {}, [], {}
    manifest = f.verify_campaign(source)
    for case in completed_cases(source, manifest):
        result = child_report(case, manifest['max_input'])
        path = case/'phase2/result.json'
        capture = path.parent/'capture.json'
        f.p.require(result['status'] == 'passed' and result['capture_sha256'] == f.p.sha(capture),
                    'Unverified Phase 2 result in repair epoch')
        requirements = path.parent/'config/runtime_requirements.json'
        plan_path = path.parent/'config/repair_plan.json'
        f.p.require(result.get('requirements_sha256') == f.p.sha(requirements) and
                    result.get('repair_plan_sha256') == f.p.sha(plan_path),
                    'Repair requirements changed or repair plan changed')
        plan = RepairPlan.load(plan_path)
        f.p.require(plan.source_sha256 == f.p.sha(requirements), 'Repair requirements changed')
        decisions = []
        for decision in plan.decisions:
            if not decision.automatic_allowed:
                if decision.disposition.value != 'not_required':
                    deferred[decision.action.value+'\0'+decision.resource] = decision.to_dict()
                continue
            f.p.require(decision.action == RepairActionKind.CREATE_DIRECTORY,
                        'Epoch backend supports automatic directory repairs only')
            key = decision.action.value+'\0'+decision.resource
            parameters = json.dumps(dict(decision.parameters), sort_keys=True)
            f.p.require(key not in seen or seen[key] == parameters, 'Conflicting automatic repairs')
            if key in seen:
                continue
            f.p.require(len(seen) < 128, 'Too many automatic repairs in one epoch')
            seen[key] = parameters
            decisions.append(decision)
        if decisions:
            target = staging/f'{len(selected):04d}'
            target.mkdir()
            req = target/'requirements.json'; shutil.copyfile(requirements, req)
            reduced = replace(plan, source_requirements=str(req), decisions=tuple(decisions))
            reduced.save(target/'plan.json')
            selected.append({'plan': str(target/'plan.json'), 'requirements': str(req),
                             'application': str(target/'application.json')})
    summary = {'automatic_resources': len(seen), 'selected_plans': len(selected),
               'deferred': list(deferred.values()), 'keys': sorted(seen), 'plans': selected}
    f.atomic_json(staging/'selection.json', summary)
    return summary


def stopped(source):
    source = Path(source)
    manifest = f.verify_campaign(source)
    f.p.require(reusable(manifest) and 'warm' in manifest and 'phase2' in manifest['warm'],
                'Repair epochs require a completed warm campaign with per-child Phase 2')
    session = f.read_json(source/'warm-session-result.json')
    capsule = session.get('capsule', {})
    f.p.require(capsule.get('status') == 'passed' and capsule.get('resources', {}).get('tree_empty') is True
                and capsule.get('phase1_retirement', {}).get('phase1_retired') is True
                and manifest.get('phase1_runs') == 1,
                'Previous capsule has not been verified stopped')
    state = f.read_json(source/'phase2-progress.json')
    f.p.require(state['status'] == 'passed' and state['pending'] == 0,
                'Previous Phase 2 still has pending work')
    completed_cases(source, manifest)
    return manifest


def evolve(source, output, *, max_epochs=3, seconds=None, executions=None, afl_bin=None, max_artifact_mib=None):
    from .afl_transport import run_campaign
    f.p.require(type(max_epochs) is int and 1 <= max_epochs <= 32, 'Invalid epoch limit')
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    initial = stopped(source)
    seconds = min(300, initial['warm']['campaign_seconds']) if seconds is None else seconds
    f.p.require(type(seconds) is int and 1 <= seconds <= initial['warm']['campaign_seconds'],
                'Repair campaign exceeds the prepared capsule lifetime; prepare a longer initial campaign')
    f.p.require(max_artifact_mib is None or (type(max_artifact_mib) is int and 16 <= max_artifact_mib <= 1048576), 'Invalid artifact budget')
    f.p.require(executions is None or (type(executions) is int and executions >= 1), 'Invalid execution budget')
    f.p.require(not output.resolve().is_relative_to(source), 'Repair output must be outside its source campaign')
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'status': 'failed', 'initial_campaign': str(source), 'epochs': [],
              'policy': 'automatic_directories_only; one_new_phase1_per_changed_environment'}
    seen_repairs, environments = set(), set()
    try:
        previous = f.verify_campaign(source)
        from .environment_snapshot import EnvironmentSnapshotStore
        environments.add(EnvironmentSnapshotStore(previous['snapshot_store']).verify(previous['snapshot_id']).tree_sha256)
        for index in range(max_epochs):
            stopped(source)
            stage = output/f'repairs-{index:03d}'
            selected = collect(source, stage)
            entry = {'parent_campaign': str(source), 'selection': str(stage/'selection.json'),
                     'automatic_resources': selected['automatic_resources'], 'deferred': len(selected['deferred'])}
            report['epochs'].append(entry)
            if not selected['keys']:
                report['stop_reason'] = 'no_automatic_repairs'
                break
            f.p.require(not seen_repairs.intersection(selected['keys']), 'Repeated repair epoch detected')
            seen_repairs.update(selected['keys'])
            applications = []
            def edit(fs):
                for item in selected['plans']:
                    applied = RepairApplier(RepairApplierConfig(denied_prefixes=('/proc', '/sys', '/dev', '/__taintforge', '/__taintforge_capsule'))).apply_file(plan_path=item['plan'], requirements_path=item['requirements'],
                        rootfs=fs, out_path=item['application'])
                    applications.append(applied.summary())
            campaign = output/f'epoch-{index:03d}'
            value = clone_campaign(source, campaign, edit_rootfs=edit)
            entry.update(campaign=str(campaign), applications=applications)
            digest = EnvironmentSnapshotStore(value['snapshot_store']).verify(value['snapshot_id']).tree_sha256
            if digest in environments or not any(item['applied_total'] for item in applications):
                entry['status'] = 'not_started'
                value['status'] = 'not_started'
                f.atomic_json(campaign/'campaign.json', value)
                report['stop_reason'] = 'no_environment_change'
                break
            environments.add(digest)
            # A new epoch is prepared independently; preserve the imported AFL corpus.
            result = run_campaign(campaign, afl_bin=afl_bin, seconds=seconds, executions=executions,
                                  max_artifact_mib=max_artifact_mib)
            if result['status'] == 'resource_limited':
                entry.update(status='resource_limited', phase1_runs=result.get('phase1_runs', 0),
                             cases=result['cases'])
                report.update(status='resource_limited', stop_reason='storage_limit', last_campaign=str(campaign))
                break
            f.p.require(result['status'] == 'completed' and result['phase1_runs'] == 1, 'Repair epoch failed')
            entry.update(status='completed', phase1_runs=1, cases=result['cases'], environment_sha256=digest)
            source = campaign
        else:
            report['stop_reason'] = 'epoch_limit'
        report.update(status='resource_limited' if report.get('stop_reason') == 'storage_limit' else 'passed',
                      last_campaign=report.get('last_campaign', str(source)),
                      new_phase1_runs=sum(item.get('phase1_runs', 0) for item in report['epochs']))
    except BaseException as exc:
        report['error'] = str(exc)
        raise
    finally:
        f.atomic_json(output/'epochs.json', report)
    return report
