"""Offline audit of Phase 2 case isolation receipts and optional Phase 1 source.

A consistency audit is not an independent proof of sandbox security, an OEP
proof, or a declaration that unknown malware is safe to execute.
"""
from __future__ import annotations

from pathlib import Path

from .ablation import file_sha
from .forensics import safe_json
from taintforge_env import afl_rebuilt as backend, capsule_resources


EXPECTED_NS = ('mnt', 'pid', 'net', 'uts', 'ipc')
UNPACK_STATUS = 'PASS_WITH_OBSERVED_IMAGE_AND_SELECTED_CASE_EQUIVALENCE'


def require(value, message):
    if not value:
        raise ValueError(message)


def audited_case(path, campaign):
    root = Path(path)
    binding, binding_sha = safe_json(root / 'config/rebuilt_binding.json')
    result, result_sha = safe_json(root / 'result.json')
    service, service_sha = safe_json(root / 'logs/capsule/service.json')
    namespaces, ns_sha = safe_json(root / 'logs/capsule/namespaces.json')
    resources, resource_sha = safe_json(root / 'logs/capsule/resources.json')
    require(binding['profile'] == backend.PROFILE and binding['run_dir'] == str(root) and
            binding['rootfs'] == str(root / 'rootfs') and
            binding['attempt_contract_sha256'] == backend.contract(binding),
            'Unbound case capsule contract: ' + str(root))
    require(binding['target_sha256'] == campaign['target_sha256'] and
            binding['bundle_sha256'] == campaign['runtime_sha256'] and
            binding['coverage_plugin_sha256'] == campaign['coverage_plugin_sha256'] and
            binding['input_path'] == '/etc/dta-input',
            'Capsule target/runtime/input identity differs from campaign')
    identity = binding['attempt_contract_sha256']
    require(result['input_sha256'] == binding['input_sha256'] and
            result.get('phase1_executed') is False and
            result.get('hostile_sample_ready') is False and
            result.get('protected_control_channel') is False,
            'Case has mismatched input or promoted security claim')
    require(file_sha(root / 'input', 4096) == binding['input_sha256'] and
            file_sha(root / 'rootfs/etc/dta-input', 4096) == binding['input_sha256'] and
            file_sha(root / 'rootfs/bin/sample.elf') == campaign['target_sha256'],
            'Case files changed after isolation')
    require(service.get('status') == resources.get('status') == 'verified' and
            service.get('tree_empty') is True and
            service.get('attempt_contract_sha256') == resources.get('attempt_contract_sha256') == identity and
            service.get('attempt_id') == resources.get('attempt_id') == binding['attempt_id'],
            'Service cleanup/cgroup evidence does not bind to capsule attempt')
    require(resources.get('no_new_privs') is True and resources.get('core_rlimit') == [0, 0] and
            resources.get('memory_isolation') is False and resources.get('hostile_sample_ready') is False,
            'Resource limitation evidence is missing or overstated')
    require(namespaces.get('request_sha256') == identity and
            namespaces.get('host') == binding['host_namespaces'] and
            set(namespaces.get('observed', {})) >= set(EXPECTED_NS) and
            all(namespaces['observed'][name] != namespaces['host'][name] for name in EXPECTED_NS),
            'Namespace identity evidence is incomplete or unchanged')
    require(result['status'] in ('passed', 'quarantined'),
            'Uncompleted guest case cannot support capsule-success claim')
    if result['status'] == 'passed':
        verified_resources = capsule_resources.verify_saved(binding, result['guest_exit'])
        require(result.get('resources') == verified_resources,
                'Saved capsule cleanup was not reproducible under the recorded resource policy')
    else:
        require(result.get('classification') == 'unverified_abnormal_exit',
                'Unrecognised abnormal case classification')
    return {'case': str(root), 'attempt_id': binding['attempt_id'],
            'input_sha256': binding['input_sha256'], 'status': result['status'],
            'evidence_sha256': {'binding': binding_sha, 'result': result_sha,
                'service': service_sha, 'resources': resource_sha, 'namespaces': ns_sha}}


def phase1_source(unpack_output, *, target_sha256):
    """Check the project's official unpack.py output, without re-running Phase 1."""
    directory = Path(unpack_output).expanduser().resolve(strict=True)
    summary, summary_hash = safe_json(directory / 'summary.json')
    rebuild, rebuild_hash = safe_json(directory / 'rebuild.json')
    require(summary.get('status') == UNPACK_STATUS and summary.get('errors') == [] and
            summary.get('all_selected_cases_match') is True and
            summary.get('rebuilt_sha256') == target_sha256 and
            summary.get('oep_proven') is False and summary.get('protected_channel') is False and
            summary.get('fuzzing_ready') is False,
            'Phase 1 source report does not support this recovered ELF and scope')
    require(rebuild.get('elf_sha256') == target_sha256 and
            file_sha(directory / 'rebuilt.elf') == target_sha256 and
            file_sha(directory / 'inputs/packed.elf') == summary.get('packed_sha256'),
            'Recorded Phase 1 input/reconstructed bytes changed')
    return {'source_dir': str(directory), 'summary_sha256': summary_hash,
            'rebuild_sha256': rebuild_hash, 'packed_sha256': summary['packed_sha256'],
            'rebuilt_sha256': target_sha256, 'recovered_source_consistency_verified': True,
            'runtime_capture_independently_reexecuted': False,
            'OEP_proven': False, 'phase1_executed_in_rebuilt_AFL_campaign': False}


def audit_campaign(campaign, *, source=None):
    root = Path(campaign).expanduser().resolve(strict=True)
    manifest, manifest_sha = safe_json(root / 'campaign.json')
    require(manifest.get('status') == 'completed' and manifest.get('profile') == backend.PROFILE and
            manifest.get('phase1_executed') is False and
            manifest.get('protected_control_channel') is False and
            manifest.get('hostile_sample_ready') is False,
            'Unsupported rebuilt campaign status or claimed safety properties')
    verified = []
    identities = set()
    # Include calibration and AFL delivery, not post-campaign proof replays.
    for container in ('baseline', 'cases'):
        directory = root / container
        require(directory.is_dir() and not directory.is_symlink(), 'Missing case directory: ' + container)
        for path in sorted(directory.iterdir()):
            if not path.is_dir() or path.is_symlink():
                raise ValueError('Unexpected capsule case path: ' + str(path))
            item = audited_case(path, manifest)
            require(item['attempt_id'] not in identities, 'Reused capsule attempt identity')
            identities.add(item['attempt_id'])
            verified.append(item)
    require(sum('/cases/' in row['case'] for row in verified) == manifest.get('cases'),
            'Campaign count and audited capsule case inventory differ')
    output = {'schema': 1, 'profile': 'rebuilt_capsule_receipt_audit_v1',
        'campaign_manifest_sha256': manifest_sha, 'target_sha256': manifest['target_sha256'],
        'audited_cases': len(verified), 'unique_capsule_attempts': len(identities),
        'case_receipts': verified, 'capsule_receipt_consistency_verified': True,
        'controlled_hostile_sample_execution_verified': False,
        'protected_control_channel': False, 'hostile_sample_ready': False,
        'phase1_executed_in_rebuilt_campaign': False,
        'limits': ['Historical host namespaces and service receipts are not independently re-observed',
                   'Memory isolation and protected-control-channel hardening are not proven',
                   'Phase 1 handoff is optional and does not prove continuous warm checkpoint reuse']}
    if source is not None:
        linked = phase1_source(source, target_sha256=manifest['target_sha256'])
        if manifest.get('phase1_source_consistency') is not None:
            require(manifest['phase1_source_consistency'] == linked,
                    'Saved Phase 1 source consistency differs from current evidence')
        output['phase1_source'] = linked
    return output
