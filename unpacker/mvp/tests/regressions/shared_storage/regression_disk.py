"""Disk admission for saved observations; this is not a filesystem quota."""
from pathlib import Path
import shutil

import hashlib
import json
import os


def require(value, message):
    if not value: raise RuntimeError(message)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Missing regular disk context file: ' + str(path))
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


BASELINE_ENV = 'TF_REGRESSION_STORAGE_BASELINE'
BASELINE_SHA_ENV = 'TF_REGRESSION_STORAGE_BASELINE_SHA256'


GIB = 1024 ** 3
RESERVE = 4 * GIB
GROWTH = 12 * GIB
REQUIRED = RESERVE + GROWTH


def inspect(path):
    path = Path(path).resolve(strict=True)
    usage = shutil.disk_usage(path)
    return {
        'path': str(path), 'filesystem_device': path.stat().st_dev,
        'total_bytes': usage.total, 'used_bytes': usage.used, 'free_bytes': usage.free,
        'required_free_bytes': REQUIRED, 'reserve_bytes': RESERVE,
        'growth_admission_bytes': GROWTH, 'shortfall_bytes': max(0, REQUIRED - usage.free),
        'status': 'STORAGE_READY' if usage.free >= REQUIRED else 'NEEDS_SPACE',
        'scope': 'available space on the output filesystem; admission checks, not a quota',
    }


def describe(value):
    free = value['free_bytes']; shortfall = max(0, REQUIRED - free)
    return ('Output disk: %.6f GiB (%d bytes) free; %d bytes required; '
            '%d bytes shortfall; path=%s' % (free / GIB, free, REQUIRED, shortfall, value['path']))


def require_initial(value):
    require(value['free_bytes'] >= REQUIRED,
            describe(value) + '. Free space or choose --output-dir on another filesystem.')


def validate_initial(value):
    for key in ('filesystem_device', 'free_bytes', 'total_bytes', 'required_free_bytes',
                'reserve_bytes', 'growth_admission_bytes'):
        require(type(value.get(key)) is int and value[key] >= 0, 'Invalid initial disk field: ' + key)
    require_initial(value)
    require(value['required_free_bytes'] == REQUIRED and value['reserve_bytes'] == RESERVE and
            value['growth_admission_bytes'] == GROWTH and value['status'] == 'STORAGE_READY' and
            value['total_bytes'] >= value['free_bytes'], 'Initial disk admission policy differs')


def continuation(initial, current):
    validate_initial(initial)
    growth = max(0, initial['free_bytes'] - current['free_bytes'])
    admitted = (current['filesystem_device'] == initial['filesystem_device'] and
                current['free_bytes'] >= RESERVE and growth <= GROWTH)
    return {'case_path': current['path'], 'filesystem_device': current['filesystem_device'],
            'free_bytes': current['free_bytes'], 'initial_free_bytes': initial['free_bytes'],
            'observed_growth_bytes': growth, 'remaining_growth_bytes': max(0, GROWTH - growth),
            'reserve_bytes': RESERVE, 'growth_admission_bytes': GROWTH,
            'admitted': admitted, 'status': 'CONTINUATION_READY' if admitted else 'CONTINUATION_BLOCKED',
            'scope': 'one initial 16 GiB admission; preparation and guest execution share 12 GiB growth and 4 GiB reserve'}


def describe_continuation(value):
    return ('Shared disk budget: free=%.6f GiB (%d bytes), reserve=4 GiB, '
            'growth=%.6f/12 GiB, remaining=%.6f GiB; %s' %
            (value['free_bytes'] / GIB, value['free_bytes'], value['observed_growth_bytes'] / GIB,
             value['remaining_growth_bytes'] / GIB, value['status']))


def select_initial(previous, current):
    validate_initial(previous)
    if previous['filesystem_device'] == current['filesystem_device']:
        return dict(previous)
    validate_initial(current)
    return dict(current)


class Admission:
    def __init__(self, work, initial=None):
        self.work = Path(work).resolve(strict=True)
        selected = dict(initial) if initial is not None else None
        inherited = os.environ.get(BASELINE_ENV)
        inherited_sha = os.environ.get(BASELINE_SHA_ENV)
        require(bool(inherited) == bool(inherited_sha), 'Incomplete inherited disk context')
        if inherited:
            candidate = Path(inherited)
            require(candidate.is_absolute() and candidate.resolve(strict=True) == candidate and
                    candidate.stat().st_size <= 65536, 'Invalid inherited disk context path')
            require(digest(candidate) == inherited_sha, 'Inherited disk context changed')
            value = json.loads(candidate.read_text())
            require(selected is None or selected == value, 'Calling and inherited disk baselines differ')
            selected = value
            self.baseline_path, self.baseline_sha256 = candidate, inherited_sha
        else:
            selected = selected if selected is not None else inspect(self.work)
            validate_initial(selected)
            self.baseline_path = self.work / 'disk-baseline.json'
            require(not self.baseline_path.exists(), 'Disk baseline destination already exists')
            save(self.baseline_path, selected)
            self.baseline_sha256 = digest(self.baseline_path)
        self.module_sha256 = digest(Path(__file__).resolve())
        self.value = {'initial': dict(selected), 'baseline_path': str(self.baseline_path),
                      'baseline_sha256': self.baseline_sha256,
                      'checks': [], 'scope': 'shared preparation and guest budget; admission checks, not a quota'}
        self.persist()
        validate_initial(self.value['initial'])
        self.before_case('admission-start')
        os.environ[BASELINE_ENV] = str(self.baseline_path)
        os.environ[BASELINE_SHA_ENV] = self.baseline_sha256

    def persist(self):
        save(self.work / 'disk-admission.json', self.value)

    def before_case(self, case):
        require(digest(self.baseline_path) == self.baseline_sha256, 'Shared disk baseline changed')
        require(digest(Path(__file__).resolve()) == self.module_sha256, 'Shared disk policy changed')
        current = inspect(self.work)
        decision = continuation(self.value['initial'], current)
        self.value['checks'].append(dict(decision, case=case))
        self.persist()
        require(decision['admitted'], 'Disk admission stopped before ' + case + ': ' + describe_continuation(decision))
        return decision
