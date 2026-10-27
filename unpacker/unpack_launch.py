"""Exact fixed stdin/argv launch binding for selected-execution unpack proofs.

This profile supplies a concrete stdin file but does not model reads from it.
The observer/native whitelist must still reject unsupported input syscalls.
"""
import base64
import hashlib
import json
import math
from pathlib import Path

try:
    from .unpack_process import validate_cases
except ImportError:
    from unpack_process import validate_cases


PROFILE = 'TF_FIXED_LAUNCH_CASE_V1'
CASE_FILE = 'launch-case.json'
STDIN_FILE = 'stdin.bin'
MAX_CASE_BYTES = 2 * 1024**2


def require(value, message):
    if not value:
        raise ValueError(message)


def normalize_case(case):
    """Reuse the process case validator, admitting no external file inputs."""
    require(type(case) is dict, 'A fixed launch case must be an object')
    row = validate_cases([case])[0]
    require(not row['files'] and not row['output_files'],
            'Fixed launch proof does not support file inputs or output files')
    data = base64.b64decode(row['stdin_base64'], validate=True)
    require(base64.b64encode(data).decode('ascii') == row['stdin_base64'],
            'Fixed launch stdin must use canonical base64')
    return {key: row[key] for key in ('id', 'argv', 'stdin_base64')}


def case_bytes(case):
    return (json.dumps(normalize_case(case), sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def case_sha256(case):
    return hashlib.sha256(case_bytes(case)).hexdigest()


def stdin_bytes(case):
    return base64.b64decode(normalize_case(case)['stdin_base64'], validate=True)


def load_case(path):
    """Read one bounded case, rejecting duplicate keys and nonfinite numbers."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and
            0 < path.stat().st_size <= MAX_CASE_BYTES, 'Fixed launch case is missing or oversized')

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate fixed launch case key: ' + key)
            result[key] = value
        return result

    def number(text):
        result = float(text)
        require(math.isfinite(result), 'Nonfinite fixed launch case number')
        return result

    def constant(text):
        raise ValueError('Nonfinite fixed launch case number: ' + text)

    return normalize_case(json.loads(path.read_bytes(), object_pairs_hook=pairs,
                                    parse_float=number, parse_constant=constant))


def validate_launch(launch, case, stdin, *, capture_directory=None):
    """Bind a successful fixed launch to its retained bytes and exact argv.

    This validates records; it does not rerun the observer, IR, or SMT solver.
    The caller separately checks the captured timeline and replay premises.
    """
    case = normalize_case(case)
    require(type(stdin) is bytes and stdin == stdin_bytes(case),
            'Retained stdin differs from the fixed launch case')
    require(type(launch) is dict and launch.get('launch_input_profile') == PROFILE,
            'Missing fixed launch input profile')
    expected_argv = ['target.elf', *case['argv']]
    stdin_sha = hashlib.sha256(stdin).hexdigest()
    require(launch.get('launch_case_file') == CASE_FILE and
            launch.get('stdin_file') == STDIN_FILE and
            launch.get('launch_case_id') == case['id'] and
            launch.get('launch_case_sha256') == case_sha256(case) and
            launch.get('stdin_sha256') == stdin_sha and
            type(launch.get('stdin_size')) is int and launch['stdin_size'] == len(stdin) and
            launch.get('stdin_empty') is (not stdin) and
            type(launch.get('stdin_offset_after_capture')) is int and
            launch['stdin_offset_after_capture'] == 0 and
            launch.get('guest_argv') == expected_argv,
            'Fixed launch stdin/argv identity or unconsumed boundary differs')
    require(launch.get('new_independent_execution') is True and
            type(launch.get('returncode')) is int and launch['returncode'] == 0 and
            launch.get('payload_instruction_execution_allowed') is False and
            launch.get('execution_mode') == 'normal',
            'Fixed launch execution scope differs')
    environment = {'LC_ALL': 'C', 'TZ': 'UTC'}
    require(launch.get('controlled_host_environment') == environment and
            launch.get('guest_environ') == ['LC_ALL=C', 'TZ=UTC'],
            'Fixed launch environment differs')
    directory = Path(capture_directory) if capture_directory is not None else Path(launch.get('cwd', ''))
    require(directory.is_absolute() and launch.get('cwd') == str(directory),
            'Fixed launch working directory differs')
    command = launch.get('argv')
    require(type(command) is list and all(type(arg) is str for arg in command) and
            len(command) == 8 + len(case['argv']) and command[0] and
            command[1:4] == ['-s', '1044480', '-plugin'] and command[4] and
            command[5:] == ['-0', 'target.elf', str(directory / 'packed.elf'), *case['argv']],
            'Fixed launch command does not pass the declared argv')
    return dict(schema_version=1, profile=PROFILE, case_id=case['id'],
        case_sha256=case_sha256(case), stdin_sha256=stdin_sha, stdin_bytes=len(stdin),
        argv=case['argv'], guest_argv=expected_argv, fixed_case_only=True,
        stdin_consumed_before_selected_boundary=False,
        stdin_unconsumed_before_selected_boundary=True,
        stdin_admitted_as_initial_memory=False, new_independent_execution=True,
        input_domain_universally_proved=False, payload_behavior_proved=False)
