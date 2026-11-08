"""Disk admission for saved observations; this is not a filesystem quota."""
from pathlib import Path
import shutil

from support import require, save

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
        self.work = Path(work)
        self.value = {'initial': dict(initial) if initial is not None else inspect(work),
                      'checks': [], 'scope': 'shared preparation and guest budget; admission checks, not a quota'}
        self.persist()
        validate_initial(self.value['initial'])
        self.before_case('admission-start')

    def persist(self):
        save(self.work / 'disk-admission.json', self.value)

    def before_case(self, case):
        current = inspect(self.work)
        decision = continuation(self.value['initial'], current)
        self.value['checks'].append(dict(decision, case=case))
        self.persist()
        require(decision['admitted'], 'Disk admission stopped before ' + case + ': ' + describe_continuation(decision))
        return decision
