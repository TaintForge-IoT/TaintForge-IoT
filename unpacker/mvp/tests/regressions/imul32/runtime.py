"""One process, original project API, audited cached results and shared libraries."""
import importlib
import json
import os
from pathlib import Path
import sys

import runtime_dedup
from support import digest, read, require

ROOT = Path(__file__).resolve().parent


def verify_project(project, guards):
    for name, expected in read(ROOT / 'project-pins.json').items():
        path = project / name
        require(path.resolve(strict=True).is_relative_to(project) and digest(path) == expected,
                'Installed project input differs: ' + name)
        guards[path] = expected


def load(project, guards):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(project))
    api = importlib.import_module('taintforge_env.dse_analysis')
    unified = importlib.import_module('taintforge_env.unified_runtime')
    require(Path(api.__file__).resolve().is_relative_to(project) and Path(api.PROJECT).resolve() == project,
            'Wrong project API imported')
    for name, module in tuple(sys.modules.items()):
        filename = getattr(module, '__file__', None)
        if filename and name.split('.')[0] in ('taintforge_env', 'experiments', 'scripts'):
            path = Path(filename).resolve()
            require(path.is_relative_to(project), 'Foreign project module imported')
            guards[path] = digest(path)
    require('experiments.execution_capsule_retire.controller' in sys.modules, 'Retirement controller not imported')
    return api, unified


def request_identity(result, method, params):
    require(result['status'] == 'passed' and result['original_inputs_unchanged'] is True,
            'API request did not preserve its original inputs')
    require([r['case'] for r in result['runs']] == (['solve', 'observe'] if method == 'invert_file' else ['observe']),
            'API execution roles differ')
    for name in ('qemu', 'plugin', 'flags_receipt', 'binary', 'seed'):
        path = Path(params[name]).resolve(strict=True)
        item = result['inputs'][name]
        require(Path(item['path']) == path and item['sha256'] == digest(path) and item['size'] == path.stat().st_size,
                'Saved request input differs: ' + name)
    require(result['branch_pc'] == params['branch_pc'] and result['offsets'] == list(params['offsets']) and
            result['occurrence'] == params['occurrence'] and result['input_path'] == params['input_path'] and
            result['argv'] == list(params['argv']) and result['max_steps'] == params['max_steps'] and
            result['budgets'] == {'case_cpu_seconds': params['seconds'], 'memory_mib': params['memory_mib']},
            'Saved request branch, mutation scope or execution budget differs')


def archive_closed_journal(work):
    path = work / 'sudo-session.json'
    if not path.exists():
        return
    value = read(path)
    require(value.get('profile') == 'same-process-noninteractive-sudo-session-v1' and
            value['active'] is False and value['executor_binding_restored'] is True and value['thread_stopped'] is True,
            'Previous sudo journal is not closed')
    saved = work / ('sudo-session.before-resume.' + digest(path) + '.json')
    if saved.exists():
        require(digest(saved) == digest(path), 'Preserved sudo journal differs')
    else:
        os.link(path, saved)
    path.unlink()


class Requests:
    def __init__(self, api, unified, work, admission, identity, expected):
        self.api, self.unified, self.work, self.admission = api, unified, work, admission
        self.identity, self.expected = identity, set(expected)
        self.pool, self.transactions = work / 'runtime-pool', work / 'runtime-transactions'
        self.pool.mkdir(exist_ok=True)
        self.transactions.mkdir(exist_ok=True)
        self.reused = self.fresh = self.receipts = 0
        self.fresh_receipts = self.reused_receipts = 0

    def verify_bundle(self, path, expected):
        value = self.unified.verify_bundle(path, expected)
        files = {item['path']: item for item in value['files']}
        require(files[value['qemu']]['sha256'] == self.identity['qemu_sha256'] and
                files[value['plugin']]['sha256'] == self.identity['plugin_sha256'] and
                files[value['plugin'] + '.runtime.json']['sha256'] == self.identity['manifest_sha256'],
                'Saved runtime bundle is not the accepted IMUL32 runtime')
        return value

    def recover(self):
        def audit(path):
            require(self.api.audit_file_run(directory=path) == read(path / 'summary.json'),
                    'Recovered API reconstruction differs')
        for journal in sorted(self.transactions.glob('runtime-links.*/transaction.json')):
            state = read(journal)
            runtime_dedup.recover(journal, self.expected, state['bundle_sha256'], self.verify_bundle,
                                  audit)

    def execute(self, method, params, destination):
        require(destination in self.expected, 'API request is outside the fixed cohort')
        self.admission.before_case(destination.relative_to(self.work).as_posix())
        if destination.exists():
            require((destination / 'summary.json').is_file(),
                    'Incomplete API output preserved for inspection: ' + str(destination))
            result = read(destination / 'summary.json')
            request_identity(result, method, params)
            require(self.api.audit_file_run(directory=destination) == result, 'Cached API reconstruction differs')
            self.reused += 1
            self.reused_receipts += len(result['runs'])
        else:
            result = getattr(self.api, method)(**params, out=destination)
            request_identity(result, method, params)
            require(self.api.audit_file_run(directory=destination) == result, 'Fresh API reconstruction differs')
            self.fresh += 1
            self.fresh_receipts += len(result['runs'])
        def audit(path):
            require(self.api.audit_file_run(directory=path) == result, 'Post-link API reconstruction differs')
        runtime_dedup.compact([destination], self.pool, self.transactions, result['bundle_sha256'], self.verify_bundle, audit)
        self.receipts += len(result['runs'])
        for run in result['runs']:
            receipt_path = destination / run['case'] / 'receipt.json'
            require(digest(receipt_path) == run['receipt_sha256'], 'Execution receipt SHA256 differs')
            receipt = read(receipt_path)
            phase = receipt['phase1']
            require(receipt['status'] == 'passed' and receipt['guest_exit'] == 0 and
                    phase['runtime_observed'] is True and phase['artifact_integrity'] == 'verified' and
                    phase['plugin_sha256'] == self.identity['plugin_sha256'] and
                    phase['runtime_manifest_sha256'] == self.identity['manifest_sha256'] and
                    phase['build_id'] == self.identity['build_id'] and
                    receipt['flags_receipt_sha256'] == self.identity['flags_receipt_sha256'] and
                    receipt['target_sha256'] == digest(params['binary']) and
                    receipt['resources']['status'] == 'verified' and receipt['resources']['tree_empty'] is True,
                    'Permanent execution identity or retirement proof differs')
        return result
