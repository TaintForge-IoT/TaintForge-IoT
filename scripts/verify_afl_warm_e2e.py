"""Host acceptance: one real M4/Phase-1 run, multiple post-retirement forks."""
import argparse
from pathlib import Path

from experiments.afl_file.build import guest
from taintforge_env import afl_file as f, afl_warm
from taintforge_env.afl_transport import run_campaign
from taintforge_env.capsule_resources import preflight


def verify(out, *, qemu, plugin, afl_bin, seconds=30, executions=32):
    out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'status': 'failed', 'scope': 'real_m4_warm_end_to_end'}
    try:
        preflight()
        f.p.command('sudo', '-n', 'true')
        f.p.command('sudo', '-n', 'unshare', '--mount', '--pid', '--fork', '--net', 'true')
        binary = guest(out/'fixture')
        seeds = out/'seeds'; seeds.mkdir(); (seeds/'A').write_bytes(b'A')
        campaign = out/'campaign'
        afl_warm.prepare_campaign(campaign, binary=binary, qemu=qemu, plugin=plugin,
            guest_path='/etc/afl-input', seeds=seeds, bootstrap_seconds=120,
            campaign_seconds=seconds+30, timeout_ms=3000, max_rss_mib=512,
            memory_mib=1024, analysis_mib=512)
        result = run_campaign(campaign, afl_bin=afl_bin, seconds=seconds, executions=executions)
        ready = f.read_json(campaign/'warm-ready.json')
        executor = f.read_json(campaign/'warm-executor.json')
        session = f.read_json(campaign/'warm-session-result.json')
        capsule = session['capsule']
        f.p.require(result['status'] == 'completed' and result['phase1_runs'] == executor['phase1_runs'] == 1,
                    'Phase 1 was repeated or the campaign failed')
        f.p.require(capsule['status'] == 'passed' and capsule['phase1_retirement']['phase1_retired'] is True and
                    capsule['resources']['tree_empty'] is True, 'Retirement or service cleanup is unproven')
        f.p.require(capsule['guest_completed'] is False and executor['status'] == 'passed',
                    'Template parent must not masquerade as an ordinary completed guest')
        cases = [f.read_json(path) for path in sorted((campaign/'cases').glob('*/result.json'))]
        f.p.require(len(cases) >= 2 and len({c['child_namespace_pid'] for c in cases}) == len(cases),
                    'No independent child executions')
        f.p.require(all(c['phase1_runs'] == 1 and c['guest_exit'] == 0 for c in cases),
                    'Fixture failed the memory/filesystem reset oracle')
        by_input = {}
        for case in cases:
            by_input.setdefault(case['input']['input_sha256'], set()).add(case['coverage']['map_sha256'])
        f.p.require(all(len(value) == 1 for value in by_input.values()), 'Repeated input coverage is unstable')
        queue = list((campaign/'afl/default/queue').glob('id:*'))
        f.p.require(len(queue) > 1, 'AFL did not retain a new path')
        report.update(status='passed', phase1_runs=1, children=len(cases), queue_entries=len(queue),
                      checkpoint=ready, retirement_verified=True, service_cleanup_verified=True)
        return report
    except Exception as exc:
        report['error'] = str(exc); raise
    finally: f.atomic_json(out/'acceptance.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('out', 'qemu', 'plugin', 'afl-bin'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--executions', type=int, default=32)
    args = parser.parse_args()
    import json
    print(json.dumps(verify(args.out, qemu=args.qemu, plugin=args.plugin, afl_bin=args.afl_bin,
                            seconds=args.seconds, executions=args.executions), indent=2))


if __name__ == '__main__': main()
