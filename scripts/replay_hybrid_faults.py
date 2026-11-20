"""Repeat quarantined rebuilt cases under the same isolated Phase 2 sandbox.

The result is a reproducibility report, NOT a verified crash/hang diagnosis:
QEMU, the guest, plugin and sandbox may share the same abnormal failure mode.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import traceback

from experiments.hybrid_prefix_v1.runtime import save
from taintforge_env import afl_rebuilt as backend


def replay(campaign, *, max_cases=16, repetitions=2):
    campaign = backend.private_path(campaign)
    backend.require(type(max_cases) is int and 1 <= max_cases <= 64 and
                    type(repetitions) is int and 2 <= repetitions <= 4,
                    'Invalid bounded fault replay budget')
    manifest = backend.read_json(campaign / 'campaign.json')
    backend.require(manifest['profile'] == backend.PROFILE and
                    manifest['status'] == 'completed', 'Completed rebuilt campaign required')
    source = backend.read_json(campaign / 'quarantined.json')
    backend.require(source.get('schema') == 1 and isinstance(source.get('cases'), list),
                    'No bounded quarantine inventory')
    output = campaign / 'fault-replays'
    backend.require(not output.exists(), 'Fault replay output already exists')
    output.mkdir(mode=0o700)
    report = {'schema': 1, 'status': 'failed', 'profile': 'rebuilt-fault-triage-v1',
              'target_sha256': manifest['target_sha256'], 'repetitions': repetitions,
              'verified_target_crash': False, 'verified_target_hang': False, 'cases': []}
    try:
        for row in source['cases'][:max_cases]:
            number = row.get('case')
            backend.require(type(number) is int and 0 <= number < manifest['cases'],
                            'Quarantine case index outside source manifest')
            source_case = campaign / 'cases' / f'{number:08d}'
            data = (source_case / 'input').read_bytes()
            original = backend.read_json(source_case / 'result.json')
            backend.require(original.get('status') == 'quarantined' and
                            original.get('input_sha256') == backend.digest(source_case / 'input') and
                            original['input_sha256'] == row['input_sha256'],
                            'Quarantine case input or classification changed')
            results = []
            for i in range(repetitions):
                attempt = output / f'case-{number:08d}-repeat-{i}'
                result, _ = backend.execute_case(campaign, data, attempt)
                results.append({'attempt': str(attempt.relative_to(campaign)),
                                'status': result['status'],
                                'classification': result.get('classification'),
                                'returncode': result.get('returncode'),
                                'coverage_sha256': result.get('coverage', {}).get('map_sha256')})
            consistent = all(result['status'] == 'quarantined' and
                             result['classification'] == 'unverified_abnormal_exit'
                             for result in results)
            summary = {'case': number, 'input_sha256': row['input_sha256'],
                       'reproduced_abnormal_candidate': consistent,
                       'results': results,
                       'verified_target_crash': False, 'verified_target_hang': False}
            report['cases'].append(summary)
            save(output / 'replay-report.json', report)
        report['status'] = 'completed'
        return report
    except BaseException as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        (output / 'failure.log').write_text(traceback.format_exc())
        raise
    finally:
        save(output / 'replay-report.json', report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', type=Path, required=True)
    parser.add_argument('--max-cases', type=int, default=16)
    parser.add_argument('--repetitions', type=int, default=2)
    args = parser.parse_args(argv)
    try:
        result = replay(args.campaign, max_cases=args.max_cases, repetitions=args.repetitions)
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print('FAULT_REPLAY_FAILED: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
