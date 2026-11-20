"""Coverage and mutation rules for the bundled, fixed-size parser."""
from __future__ import annotations

import hashlib
from .runtime import require

SEED = b'AA' + b'x' * 30
INPUT_PATH = '/etc/afl-input'
MAP_SIZE = 65536


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_input(raw):
    require(isinstance(raw, bytes) and len(raw) == 32 and raw[4:] == b'x' * 28,
            'Input is outside the bundled fixed parser contract')
    return raw


def checked_mask(offsets):
    require(isinstance(offsets, (list, tuple)) and offsets and
            all(type(offset) is int for offset in offsets) and
            list(offsets) == sorted(set(offsets)) and set(offsets) <= {0, 1, 2, 3},
            'Invalid DTA mask for the bundled fixed parser')
    return tuple(offsets)


def masked_mutation(parent, offsets, ordinal):
    checked_input(parent)
    offsets = checked_mask(offsets)
    require(type(ordinal) is int and ordinal >= 1, 'Invalid mutation ordinal')
    offset = offsets[(ordinal - 1) % len(offsets)]
    bit = ((ordinal - 1) // len(offsets)) % 8
    output = bytearray(parent)
    output[offset] ^= 1 << bit
    return bytes(output), offset, bit


def changed_offsets(first, second):
    checked_input(first)
    checked_input(second)
    return [index for index, (before, after) in enumerate(zip(first, second)) if before != after]


def count_class(value):
    if value < 4:
        return (0, 1, 2, 4)[value]
    return 8 if value < 8 else 16 if value < 16 else 32 if value < 32 else 64 if value < 128 else 128


class CoveragePlateau:
    def __init__(self, threshold):
        require(type(threshold) is int and 4 <= threshold <= 256, 'Invalid plateau threshold')
        self.threshold = threshold
        self.seen = bytearray(MAP_SIZE)
        self.quiet = self.eligible = self.observations = 0

    def observe(self, bitmap, *, eligible):
        require(isinstance(bitmap, bytes) and len(bitmap) == MAP_SIZE and any(bitmap),
                'Missing guest coverage bitmap')
        fresh = 0
        for index, value in enumerate(bitmap):
            bucket = count_class(value)
            if bucket and not self.seen[index] & bucket:
                self.seen[index] |= bucket
                fresh += 1
        self.observations += 1
        self.eligible += int(eligible)
        if fresh:
            self.quiet = 0
        elif eligible:
            self.quiet += 1
        return fresh

    @property
    def stalled(self):
        return self.quiet >= self.threshold
