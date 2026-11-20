"""Bounded, variable-size DTA mask/mutation and AFL bitmap accounting.

No parser-specific offsets, bytes, executable addresses, or expected exit codes
are embedded in this policy. An unchanged input length is intentional for
masked mutations: changing length without taint evidence would not be DTA-guided.
"""
from __future__ import annotations

from bisect import bisect_left
from functools import lru_cache
from hashlib import sha256

MAX_INPUT = 4096
MAP_SIZE = 65536


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def checked_input(data: bytes, limit: int = MAX_INPUT) -> bytes:
    require(type(limit) is int and 1 <= limit <= MAX_INPUT, 'Invalid input limit')
    require(type(data) is bytes and 1 <= len(data) <= limit, 'Input outside 1..max_input bounds')
    return data


def checked_mask(offsets, limit: int = MAX_INPUT):
    require(type(limit) is int and 1 <= limit <= MAX_INPUT, 'Invalid mask limit')
    require(isinstance(offsets, (list, tuple)) and
            all(type(offset) is int and 0 <= offset < limit for offset in offsets) and
            list(offsets) == sorted(set(offsets)), 'Invalid DTA byte-offset mask')
    return tuple(offsets)


def mask_from_requests(requests, limit: int = MAX_INPUT):
    require(isinstance(requests, list), 'DTA handoff requests are not an array')
    gathered = set()
    for request in requests:
        site = request.get('observed_site') if isinstance(request, dict) else None
        offsets = site.get('offsets') if isinstance(site, dict) else None
        require(isinstance(offsets, list) and all(type(i) is int and 0 <= i < limit for i in offsets),
                'DTA contains an invalid/out-of-range dependency')
        gathered.update(offsets)
    return checked_mask(sorted(gathered), limit)


def diff_offsets(before: bytes, after: bytes):
    checked_input(before)
    checked_input(after)
    return [i for i in range(max(len(before), len(after))) if
            i >= min(len(before), len(after)) or before[i] != after[i]]


@lru_cache(maxsize=256)
def _byte_values(current):
    flips = tuple(current ^ (1 << bit) for bit in range(8))
    return flips + (0, 1, 0x7f, 0x80, 0xfe, 0xff, (current + 1) & 255, (current - 1) & 255)


def masked_mutation(parent: bytes, offsets, ordinal: int, limit: int = MAX_INPUT):
    """A deterministic bounded policy; no modification may escape DTA offsets.

    For each source byte, cover one-bit changes, 0/1/0x7f/0x80/0xff, and
    +1/-1. The returned offset is always in the tainted mask.
    """
    checked_input(parent, limit)
    offsets = checked_mask(offsets, limit)
    require(type(ordinal) is int and ordinal >= 1, 'Mutation ordinal must be positive')
    candidates = [offset for offset in offsets if offset < len(parent)]
    require(candidates, 'No DTA-observed offsets inside the parent input')
    index = (ordinal - 1) % len(candidates)
    action = ((ordinal - 1) // len(candidates)) % 16
    offset = candidates[index]
    output = bytearray(parent)
    output[offset] = _byte_values(parent[offset])[action]
    return bytes(output), offset, action


def mask_bits(offsets, length):
    checked_mask(offsets, MAX_INPUT)
    require(type(length) is int and 1 <= length <= MAX_INPUT, 'Invalid packed mask length')
    output = bytearray((length + 7) // 8)
    for offset in offsets:
        if offset < length:
            output[offset // 8] |= 1 << (offset % 8)
    return bytes(output)


def count_class(value):
    require(type(value) is int and 0 <= value <= 255, 'Invalid hitcount')
    if value < 4:
        return (0, 1, 2, 4)[value]
    return 8 if value < 8 else 16 if value < 16 else 32 if value < 32 else 64 if value < 128 else 128


class CoveragePlateau:
    def __init__(self, threshold=16):
        require(type(threshold) is int and 4 <= threshold <= 256, 'Invalid plateau threshold')
        self.threshold = threshold
        self.seen = bytearray(MAP_SIZE)
        self.quiet = self.observations = self.eligible = 0

    def observe(self, bitmap, *, eligible=False):
        require(type(bitmap) is bytes and len(bitmap) == MAP_SIZE, 'Invalid AFL coverage map')
        fresh = 0
        for index, value in enumerate(bitmap):
            bucket = count_class(value)
            if bucket and not self.seen[index] & bucket:
                self.seen[index] |= bucket
                fresh += 1
        self.observations += 1
        self.eligible += bool(eligible)
        if fresh:
            self.quiet = 0
        elif eligible:
            self.quiet += 1
        return fresh

    @property
    def stalled(self):
        return self.quiet >= self.threshold


def eligible_requests(requests, attempted_ids=frozenset()):
    """Only unseen, non-ambiguous DTA branches with a bounded native prefix."""
    found = []
    for row in requests:
        if row.get('opposite_observed_elsewhere') is not False:
            continue
        ident = row.get('request_id')
        site = row.get('observed_site')
        if not isinstance(ident, str) or len(ident) != 64 or ident in attempted_ids:
            continue
        if not isinstance(site, dict):
            continue
        seq, offsets = site.get('seq'), site.get('offsets')
        if type(seq) is not int or not 0 < seq <= 1024 or not isinstance(offsets, list) or not offsets:
            continue
        found.append(row)
    return sorted(found, key=lambda row: (row['observed_site']['seq'],
                                          len(row['observed_site']['offsets']), row['request_id']))


def focused_masks(requests, union_mask, *, limit=MAX_INPUT):
    """Audited per-site byte masks; never claim that the global union is narrow.

    Only unseen-opposite DTA sites with bounded prefixes influence scheduling.
    Every focus is a subset of the original, source-derived union. When all
    observed sites depend on the entire input, the result is empty: no focus
    claim is made, and the controller continues using the full DTA union.
    """
    union = checked_mask(union_mask, limit)
    allowed = set(union)
    result = []
    seen = set()
    for request in eligible_requests(requests):
        offsets = request['observed_site']['offsets']
        require(isinstance(offsets, list) and all(type(i) is int for i in offsets),
                'Invalid per-site DTA offset inventory')
        focus = tuple(sorted(set(offsets)))
        require(focus and set(focus) <= allowed,
                'Focused DTA site is not a subset of the audited DTA mask')
        if focus != union and focus not in seen:
            result.append(focus)
            seen.add(focus)
    # Sort by scope first; ties retain the original DTA request order.
    return tuple(sorted(result, key=len))


class BranchFocusedSchedule:
    """Prefer actual branch dependencies; reserve every fourth block for union.

    The full-union fallback is deliberately unconditional. It prevents a
    narrowing heuristic from excluding dependencies that other branches need.
    This changes mutation prioritization, not the asserted taint evidence.
    """
    BLOCK_LENGTH = 8

    def __init__(self, union_mask, requests, *, limit=MAX_INPUT):
        self.union = checked_mask(union_mask, limit)
        self.focus = focused_masks(requests, self.union, limit=limit)
        self.ordinals = {}
        self.remaining_values = {}
        self.focused_mutations = 0
        self.fallback_mutations = 0

    def skip_reason(self, parent, parent_sha, offset, value):
        # Each existing operation changes at most one byte. A changed (offset, value)
        # uniquely identifies an output for this parent, across both scheduling modes.
        remaining = self.remaining_values.setdefault(parent_sha, {})
        if offset not in remaining:
            remaining[offset] = set(_byte_values(parent[offset])) - {parent[offset]}
        if value in remaining[offset]:
            remaining[offset].remove(value)
            return None
        if len(remaining) == bisect_left(self.union, len(parent)) and not any(remaining.values()):
            return 'options_exhausted'
        return 'unchanged_input' if value == parent[offset] else 'duplicate_output'

    def next(self, generation, parent_length):
        require(type(generation) is int and generation >= 1, 'Invalid generation')
        require(type(parent_length) is int and 1 <= parent_length <= MAX_INPUT,
                'Invalid input length')
        if not self.union or self.union[0] >= parent_length:
            return None
        usable = tuple(mask for mask in self.focus if any(offset < parent_length for offset in mask))
        block = (generation - 1) // self.BLOCK_LENGTH
        if usable and block % 4 != 3:
            selected = usable[(block // 4 * 3 + block % 4) % len(usable)]
            scope = 'branch_focus'
            self.focused_mutations += 1
        else:
            selected = self.union
            scope = 'full_union_fallback'
            self.fallback_mutations += 1
        self.ordinals[selected] = self.ordinals.get(selected, 0) + 1
        return selected, self.ordinals[selected], scope


class AdaptiveBranchSchedule(BranchFocusedSchedule):
    """Conservative mixed-mode policy. At least 10 of each 16 custom slots
    use the *full* DTA union, even if the focus collapses to one byte.

    A quota is adjusted only from matched, guest-verified, custom-stage
    executions. AFL built-in stages do not masquerade as focus feedback.
    No profile asserts that an unobserved byte is independent.
    """
    PERIOD = 16
    FEEDBACK_WINDOW = 32

    def __init__(self, union_mask, requests, *, limit=MAX_INPUT):
        super().__init__(union_mask, requests, limit=limit)
        self.max_focus = 4 if len(self.focus) == 1 and len(self.focus[0]) == 1 else 6
        self.focus_quota = (2 if self.max_focus == 4 else 4) if self.focus else 0
        self.feedback = {'branch_focus': [0, 0], 'full_union_fallback': [0, 0]}
        self.adjustments = []

    def next(self, generation, parent_length):
        require(type(generation) is int and generation >= 1, 'Invalid generation')
        require(type(parent_length) is int and 1 <= parent_length <= MAX_INPUT, 'Invalid input length')
        if not self.union or self.union[0] >= parent_length:
            return None
        usable = tuple(mask for mask in self.focus if any(i < parent_length for i in mask))
        # Changing a focused mask never changes the audited full-union fallback.
        slot = (generation - 1) % self.PERIOD
        if usable and slot < self.focus_quota:
            selected = usable[((generation - 1) // self.PERIOD * self.max_focus + slot) % len(usable)]
            scope = 'branch_focus'
            self.focused_mutations += 1
        else:
            selected = self.union
            scope = 'full_union_fallback'
            self.fallback_mutations += 1
        self.ordinals[selected] = self.ordinals.get(selected, 0) + 1
        return selected, self.ordinals[selected], scope

    def observe(self, scope, fresh):
        """Use novelty, not number of changed bytes, to tune a bounded quota."""
        require(scope in self.feedback and type(fresh) is int and fresh >= 0,
                'Untrusted focused-scheduling feedback')
        row = self.feedback[scope]
        row[0] += 1
        row[1] += int(fresh > 0)
        if sum(x[0] for x in self.feedback.values()) < self.FEEDBACK_WINDOW:
            return
        focus, fallback = self.feedback.values()
        if self.focus and focus[0] >= 4 and fallback[0] >= 4:
            focus_rate = focus[1] / focus[0]
            fallback_rate = fallback[1] / fallback[0]
            if focus_rate > fallback_rate + .05:
                self.focus_quota = min(self.max_focus, self.focus_quota + 1)
            elif focus_rate < fallback_rate + .05:
                self.focus_quota = max(1, self.focus_quota - 1)
            self.adjustments.append({'focus_success': focus[1],
                'focus_trials': focus[0], 'fallback_success': fallback[1],
                'fallback_trials': fallback[0], 'quota_per_16': self.focus_quota})
        self.feedback = {'branch_focus': [0, 0], 'full_union_fallback': [0, 0]}
