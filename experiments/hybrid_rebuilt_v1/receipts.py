"""Immutable identity of one completed coverage delivery."""
from __future__ import annotations

from dataclasses import dataclass

from .forensics import read_bytes, safe_json
from .policy import MAP_SIZE, MAX_INPUT, digest, require


def verify_case_target(case, target_sha256, receipt):
    from taintforge_env.afl_rebuilt import contract

    require(not (case / 'config').is_symlink(), 'Symlink in case binding path')
    binding, binding_sha = safe_json(case / 'config/rebuilt_binding.json')
    require(binding.get('target_sha256') == target_sha256 and
            binding.get('input_sha256') == receipt.input_sha256 and
            binding.get('campaign_id') == receipt.campaign_id and
            binding.get('attempt_id') == receipt.attempt_id and
            binding.get('attempt_contract_sha256') == contract(binding),
            f'Case target/input/contract identity mismatch: {case.name}')
    return binding_sha


@dataclass(frozen=True)
class Delivery:
    input_sha256: str
    coverage_sha256: str
    quarantined: bool
    guest_exit: int | None
    started_ns: int | None
    finished_ns: int | None
    sent_ns: int | None
    campaign_id: str | None
    attempt_id: str | None
    result_sha256: str
    transport_sha256: str


def read_delivery(case, index, *, max_input=MAX_INPUT, verify_native=False):
    require(not case.parent.is_symlink() and not case.is_symlink(),
            'Symlink in case directory')
    result, result_sha = safe_json(case / 'result.json')
    transport, transport_sha = safe_json(case / 'transport.json')
    input_sha = digest(read_bytes(case / 'input', max_input))
    bitmap = read_bytes(case / 'coverage.map', MAP_SIZE)
    map_sha = digest(bitmap)
    require(len(bitmap) == MAP_SIZE and result.get('input_sha256') == input_sha,
            f'Case input or coverage size changed: {index}')
    quarantined = result.get('status') == 'quarantined'
    guest_exit = result.get('guest_exit')
    if quarantined:
        require(result.get('classification') == 'unverified_abnormal_exit' and
                not any(bitmap) and guest_exit is None, f'Invalid quarantine evidence: {index}')
    else:
        coverage = result.get('coverage')
        require(result.get('status') == 'passed' and isinstance(coverage, dict) and
                coverage.get('status') == 'verified' and coverage.get('map_sha256') == map_sha and any(bitmap) and
                type(guest_exit) is int and 0 <= guest_exit <= 255,
                f'Unverified case coverage or exit: {index}')
        if verify_native:
            from taintforge_env.afl_rebuilt import parse_map
            require(not (case / 'output').is_symlink(), 'Symlink in native coverage path')
            native, native_map = parse_map(case / 'output/coverage.bin', guest_exit)
            native['branch_outcomes'] = [list(row) for row in native['branch_outcomes']]
            require(result.get('returncode') == guest_exit and native_map == bitmap and native == coverage,
                    f'Guest plugin record differs from delivered coverage: {index}')
    require(type(transport.get('case')) is int and transport['case'] == index and
            transport.get('status') == 'delivered' and transport.get('input_sha256') == input_sha and
            transport.get('coverage_sha256') == map_sha and
            transport.get('feedback') == ('zero_unverified' if quarantined else 'verified_guest_coverage'),
            f'Case transport identity mismatch: {index}')
    version = transport.get('schema', 1)
    started_ns = transport.get('execution_started_ns')
    finished_ns = transport.get('execution_finished_ns')
    sent_ns = transport.get('transport_sent_ns')
    campaign_id, attempt_id = transport.get('campaign_id'), transport.get('attempt_id')
    require(type(version) is int and version in (1, 2) and
            ((version == 1 and sent_ns is None) or (version == 2 and type(sent_ns) is int and sent_ns > 0)),
            f'Invalid transport clock or schema: {index}')
    if version == 2:
        require(type(started_ns) is int and type(finished_ns) is int and
                0 < started_ns <= finished_ns <= sent_ns, f'Invalid case execution times: {index}')
        require(isinstance(campaign_id, str) and campaign_id and isinstance(attempt_id, str) and attempt_id and
                result.get('campaign_id') == campaign_id and result.get('attempt_id') == attempt_id,
                f'Case campaign/attempt mismatch: {index}')
    return Delivery(input_sha, map_sha, quarantined, guest_exit, started_ns, finished_ns, sent_ns,
                    campaign_id, attempt_id, result_sha, transport_sha), bitmap
