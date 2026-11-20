"""Strict guest syscall profile for capsule control resources."""
from pathlib import PurePosixPath
import hashlib
import re

from experiments.execution_capsule_probe import controller as p

PROFILE = 'static-i386-fd-path-v1'
POLICY = {'profile': PROFILE, 'failure': 'abort_attempt', 'guest_fd_limit': 4096,
          'paths': 'canonical_absolute_no_links', 'memory_isolation': False}


def policy():
    return dict(POLICY)


def validate(value):
    p.require(isinstance(value, dict) and value == POLICY and
              all(type(value[k]) is type(v) for k, v in POLICY.items()), 'Invalid capsule control policy')
    return value


def private_prefix(binding):
    value = binding['control_guard_private_path']
    recorded = binding.get('recorded_phase1_directory')
    expected = str(PurePosixPath(recorded).parents[1]) if recorded else binding['run_dir']
    p.require(isinstance(value, str) and value.startswith('/') and not value.startswith('//') and value != '/' and
              PurePosixPath(value).as_posix() == value and
              ',' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value) and len(value.encode()) < 4096 and
              '..' not in PurePosixPath(value).parts and value == expected, 'Invalid capsule private path')
    return value


def verify_bundle(profile):
    digest = profile.get('source_sha256', {}).get('control_guard.h')
    p.require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest),
              'Observer build lacks the capsule control guard')


def verify_snapshot(item, *, private=None):
    p.require(isinstance(item, dict) and set(item) == {'profile', 'checked_syscalls', 'guest_fds', 'private_path_sha256'} and
              item['profile'] == PROFILE and type(item['checked_syscalls']) is int and
              0 <= item['checked_syscalls'] < 2**64 and type(item['guest_fds']) is int and
              0 <= item['guest_fds'] <= 4096 and isinstance(item['private_path_sha256'], str) and
              re.fullmatch('[0-9a-f]{64}', item['private_path_sha256']),
              'Missing or invalid native control guard evidence')
    if private is not None:
        p.require(item['private_path_sha256'] == hashlib.sha256(private.encode()).hexdigest(),
                  'Native guard protects a different private path')
    return item
