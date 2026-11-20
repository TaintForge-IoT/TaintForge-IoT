"""Regression for repeated tainted branches and bounded DSE recapture sites."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from taintforge_env.dta_corpus import DtaCorpusError, generate_corpus, parse_trace
from taintforge_env.dta_handoff import _select_recapture_sites


def synthetic_trace(events: int) -> str:
    lines = ['[RUNTIME] log=roots profile=on progress=1']
    for index in range(1, events + 1):
        lines.extend((
            f'[BRANCH-PROV] event={index} edge={index} seq={index} vcpu=0 '
            'pc=0x8049000 next=0x8049010 outcome=taken cc=4 label=1 complete=0x1 reasons=0x0',
            f'[BRANCH-ROOT] event={index} channel=data root={index} '
            'resource=1 path=/etc/dta-input offset=0',
            f'[DCFG-JCC] event={index} edge={index} src-node=1 dst-node=2 '
            'src=0x8049000 dst=0x8049010 pc=0x8049000 src-gen=0 dst-gen=0 '
            f'kind=jcc-taken count={index} seq={index} label=1',
        ))
    return '\n'.join(lines) + '\n'


class BranchGroupBudgetTests(unittest.TestCase):
    def test_repeated_branch_occurrences_above_original_64_limit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trace = root / 'trace.log'
            trace.write_text(synthetic_trace(80), encoding='utf-8')
            parsed = parse_trace(trace, '/etc/dta-input', 32)
            self.assertEqual(len(parsed['groups']), 80)
            self.assertEqual(parsed['events'], 80)
            self.assertEqual({group['pc'] for group in parsed['groups']}, {0x8049000})
            self.assertEqual([group['occurrence'] for group in parsed['groups']], list(range(1, 81)))
            with self.assertRaisesRegex(DtaCorpusError, 'Branch group budget exceeded'):
                parse_trace(trace, '/etc/dta-input', 32, max_groups=64)
            binary = root / 'binary.elf'
            binary.write_bytes(b'not executed by a corpus planning test')
            seed = root / 'seed'
            seed.write_bytes(b'A' * 32)
            corpus = generate_corpus(seed=seed, binary=binary, trace=trace,
                                     input_path='/etc/dta-input', out=root / 'corpus',
                                     max_candidates=3)
            self.assertEqual(len(corpus['groups']), 80)
            self.assertEqual(corpus['budgets']['max_groups'], 4096)
            self.assertLessEqual(len(corpus['candidates']), 3)

    def test_hard_ceiling_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            trace = Path(td) / 'many.log'
            trace.write_text(synthetic_trace(4096), encoding='utf-8')
            self.assertEqual(len(parse_trace(trace, '/etc/dta-input', 32)['groups']), 4096)
            trace.write_text(synthetic_trace(4097), encoding='utf-8')
            with self.assertRaisesRegex(DtaCorpusError, 'Branch group budget exceeded'):
                parse_trace(trace, '/etc/dta-input', 32)

    def test_diverse_sites_preserved_on_handoff_overflow(self):
        def site(pc, seq, *, opposite='taken', offsets=None):
            return ({'case': 'baseline'}, {
                'pc': pc, 'outcome': opposite, 'seq': seq,
                'source_block_generation': 0, 'offsets': [0] if offsets is None else offsets,
                'occurrence': seq,
            })
        sites = [site(0x8049000, index) for index in range(1, 301)]
        sites.append(site(0x8049020, 301, offsets=[1]))
        sites.append(site(0x8049030, 302, offsets=[2]))
        known = {(0x8049000, 'taken'), (0x8049000, 'not-taken')}
        selected = _select_recapture_sites(sites, known, 2)
        self.assertEqual([group['pc'] for _, group in selected], [0x8049020, 0x8049030])
        self.assertEqual(len(sites) - len(selected), 300)
        self.assertEqual(_select_recapture_sites(sites[:2], known, 2), sites[:2])
        with self.assertRaisesRegex(DtaCorpusError, 'Invalid handoff sites budget'):
            _select_recapture_sites(sites, known, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
