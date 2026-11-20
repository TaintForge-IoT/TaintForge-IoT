"""Check the selected M4 build against the current native sources."""
import argparse
from pathlib import Path
import re

from experiments.execution_capsule_probe import controller as p
from taintforge_env.phase1_retirement import check_runtime
from taintforge_env.phase1_runtime import Phase1Runtime, digest, read_json


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {'qemu_unpacker.c', 'phase1_retire.c', 'phase1_resources.c',
            'ir_concolic.c', 'build_group7_4c1_plugin.sh', 'phase1_build_manifest.py'}


def check(plugin, source, header):
    source, header = Path(source).absolute(), Path(header).absolute()
    p.require(source.is_dir() and not source.is_symlink(), 'Invalid Phase 1 source directory')
    runtime = Phase1Runtime.load(Path(plugin))
    check_runtime(runtime, trigger='verdict')
    manifest = read_json(runtime.manifest)
    profile = manifest.get('compiled_profile', {})
    p.require(profile == {'architecture': 'i386', 'mode': 'linux-user', 'processes': 1, 'threads': 1}
              and type(profile['processes']) is int and type(profile['threads']) is int,
              'M4 requires the single-process i386 native profile')
    ledger = manifest.get('resource_ledger', {})
    p.require(ledger == {'schema': 1, 'scope': 'explicit_project_allocations',
                         'external_allocations_tracked': False} and type(ledger['schema']) is int,
              'Selected build lacks the M4 resource ledger')
    inputs = manifest['build_inputs']
    sources = inputs.get('source_files')
    p.require(isinstance(sources, dict) and REQUIRED <= sources.keys(),
              'Build manifest omits Phase 1/M4 source inputs')
    for name, expected in sources.items():
        p.require(isinstance(name, str) and name not in {'.', '..'} and
                  Path(name).name == name and '\\' not in name and
                  isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected),
                  'Invalid native source identity')
        path = source / name
        p.require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                  'Phase 1 source differs from selected build: ' + name)
    p.require({path.name for path in source.glob('*.h')} <= sources.keys(),
              'Current Phase 1 headers are absent from the build manifest')
    p.require(header.is_file() and not header.is_symlink() and
              digest(header) == inputs.get('qemu_header_sha256'),
              'QEMU header differs from selected build')
    p.require(digest(runtime.plugin) == runtime.plugin_sha256 and
              digest(runtime.manifest) == runtime.manifest_sha256,
              'Phase 1 runtime changed during the source check')
    return {'schema': 1, 'profile': 'phase1-m4-build-v1', 'status': 'compatible',
            'build_id': runtime.build_id, 'plugin_sha256': runtime.plugin_sha256,
            'runtime_manifest_sha256': runtime.manifest_sha256,
            'source_revision': manifest.get('source_revision'), 'source_files': sources,
            'checker_sha256': digest(Path(__file__)),
            'qemu_header_sha256': digest(header), 'guest_executed': False,
            'retirement_verified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin', required=True, type=Path)
    parser.add_argument('--source', type=Path, default=ROOT / 'unpacker/test')
    parser.add_argument('--header', type=Path, default=ROOT / 'experiments/execution_capsule_probe/vendor/qemu-plugin.h')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        parser.error('Build check output already exists')
    try:
        report = check(args.plugin, args.source, args.header)
        code = 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        report = {'schema': 1, 'profile': 'phase1-m4-build-v1', 'status': 'failed',
                  'error': f'{type(exc).__name__}: {exc}', 'guest_executed': False,
                  'retirement_verified': False}
        code = 1
    p.write_json(args.out, report)
    print('Phase 1/M4 build: ' + report['status'])
    return code


if __name__ == '__main__':
    raise SystemExit(main())
