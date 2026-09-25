"""Exercise the notebook's evaluation helpers without GPU/model downloads.

Run: python -m unittest discover -s ai/markuplm/tests -v
Definitions are extracted from the notebook so tests exercise the shipped code.
"""

import ast
from collections import defaultdict
import contextlib
import io
import json
import math
from pathlib import Path
import random
import tempfile
import time
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit


NOTEBOOK = Path(__file__).resolve().parents[3] / 'markuplm_v3.ipynb'
NB = json.loads(NOTEBOOK.read_text(encoding='utf-8'))


def load_helpers():
    wanted = {
        'netloc_of', 'host_group', 'require_two_classes', 'isolate_test_hosts',
        'split_by_netloc', 'split_test_by_netloc', 'assert_disjoint_splits',
        'threshold_at_fpr', 'operating_metrics', 'checkpoint_key',
        'count_decisions', 'decision_rows', 'append_parse_failures',
        'assert_complete_final', 'build_examples', 'write_jsonl',
    }
    definitions = []
    for cell in NB['cells']:
        if cell['cell_type'] == 'code':
            tree = ast.parse(''.join(cell['source']))
            definitions.extend(node for node in tree.body
                               if isinstance(node, ast.FunctionDef) and node.name in wanted)
    assert {node.name for node in definitions} == wanted
    namespace = {'math': math, 'random': random, 'urlsplit': urlsplit,
                 'defaultdict': defaultdict, 'json': json, 'time': time}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(NOTEBOOK), 'exec'), namespace)
    return namespace


def page(host, label, key, html='ok'):
    return {'sha256': key, 'url': f'https://{host}/page', 'netloc': host,
            'label_id': label, 'html_len': 1000, 'n_nodes': 10, 'html': html}


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.h = load_helpers()

    def test_all_cells_compile(self):
        for index, cell in enumerate(NB['cells']):
            if cell['cell_type'] == 'code':
                compile(''.join(cell['source']), f'cell_{index}', 'exec')

    def test_hostname_normalization_ignores_port_case_and_trailing_dot(self):
        normalize = self.h['netloc_of']
        self.assertEqual(normalize('https://Example.COM.:443/a'), 'example.com')
        self.assertEqual(normalize('https://user:pass@EXAMPLE.com:8443'), 'example.com')
        self.assertEqual(normalize('not-a-url'), '')
        self.assertEqual(normalize('http://[broken'), '')

    def test_seen_hosts_excluded_from_training_and_validation(self):
        train = [page('train.test', 0, 'a')]
        val = [page('val.test', 1, 'b')]
        samples = [page('train.test', 1, 'c'), page('val.test', 0, 'd'), page('new.test', 1, 'e')]
        unseen, seen = self.h['isolate_test_hosts'](samples, train, val)
        self.assertEqual([r['sha256'] for r in unseen], ['e'])
        self.assertEqual([r['sha256'] for r in seen], ['c', 'd'])

    def test_mixed_label_host_counted_per_class_in_validation_quota(self):
        # One mixed group has two pages but fits a quota of one PER CLASS.
        rows = [page('mixed.test', 0, 'a'), page('mixed.test', 1, 'b')]
        train, val = self.h['split_by_netloc'](rows, 1, 42)
        self.assertEqual(train, [])
        self.assertEqual(len(val), 2)

    def test_raw_split_keeps_hosts_whole_and_every_page(self):
        rows = [page(f'h{i}.test', label, f'{i}-{label}') for i in range(12) for label in (0, 1)]
        calib, final = self.h['split_test_by_netloc'](rows, 0.4, 42)
        self.h['assert_disjoint_splits']({'calib': calib, 'final': final})
        self.assertEqual(len(calib) + len(final), len(rows))
        self.assertEqual(self.h['split_test_by_netloc'](rows, 0.4, 42), (calib, final))

    def test_split_assertion_rejects_shared_hosts_and_shared_content(self):
        for other in (page('same.test', 1, 'b'), page('other.test', 1, 'a')):
            with self.assertRaises(ValueError):
                self.h['assert_disjoint_splits']({'train': [page('same.test', 0, 'a')], 'test': [other]})

    def test_missing_hosts_are_grouped_by_hash_not_all_together(self):
        self.assertNotEqual(self.h['host_group'](page('', 0, 'a')),
                            self.h['host_group'](page('', 1, 'b')))

    def test_tied_scores_cannot_exceed_fp_budget(self):
        # Including the boundary tie would flag 3/4 benign pages, exceeding 25%.
        metrics = self.h['operating_metrics']([0, 0, 0, 0, 1, 1], [.9, .8, .8, .1, .95, .85], .25)
        self.assertEqual(metrics['operating_fpr'], .25)
        self.assertEqual(metrics['recall_at_fpr'], 1.0)
        self.assertGreater(metrics['selection_logit_threshold'], .8)

    def test_small_benign_sample_allows_zero_fp(self):
        m = self.h['operating_metrics']([0, 0, 1, 1], [.9, .2, .95, .85], .02)
        self.assertEqual(m['operating_fpr'], 0)
        self.assertEqual(m['recall_at_fpr'], .5)

    def test_all_scores_tied_predicts_no_positive(self):
        m = self.h['operating_metrics']([0, 0, 1, 1], [1., 1., 1., 1.], .02)
        self.assertEqual(m['operating_fpr'], 0)
        self.assertEqual(m['recall_at_fpr'], 0)
        self.assertGreater(m['selection_logit_threshold'], 1.)

    def test_random_ties_respect_budget(self):
        rng = random.Random(3)
        for _ in range(200):
            negatives = rng.randint(1, 150)
            labels = [0] * negatives + [1] * 20
            scores = [rng.randint(-5, 5) for _ in labels]
            target = rng.choice([0., .01, .02, .1, .5])
            threshold = self.h['threshold_at_fpr'](labels, scores, target)
            fp = sum(s >= threshold for s in scores[:negatives])
            self.assertLessEqual(fp, math.floor(negatives * target))

    def test_threshold_rejects_invalid_inputs(self):
        for labels, scores, target in (([0, 1], [float('nan'), .5], .02),
                                      ([0, 1], [.2], .02), ([0, 0], [.2, .5], .02),
                                      ([0, 1], [.2, .5], 1.)):
            with self.assertRaises(ValueError):
                self.h['threshold_at_fpr'](labels, scores, target)

    def test_checkpoint_selection_prioritizes_recall_not_auc(self):
        key = self.h['checkpoint_key']
        a = {'recall_at_fpr': .8, 'operating_fpr': .02, 'loss': .3, 'auc': .9}
        b = {'recall_at_fpr': .7, 'operating_fpr': .01, 'loss': .2, 'auc': .99}
        self.assertGreater(key(a), key(b))
        self.assertGreater(key({**a, 'operating_fpr': .01}), key(a))
        self.assertGreater(key({**a, 'loss': .2}), key(a))

    def test_parse_failures_keep_identity_reason_and_actual_split(self):
        def parse(html):
            if html == 'broken':
                raise ValueError('bad markup')
            return None if html == 'empty' else (['text'], ['/html/body/p'], 1)
        self.h.update({'nodes_from_html': parse, 'tqdm': lambda rows, **kwargs: rows,
                       'np': SimpleNamespace(mean=lambda values: sum(values) / len(values)),
                       'ID2LABEL': {0: 'benign', 1: 'phishing'},
                       'CLEAN_STATS': {}, 'SKIPPED': {}, 'PARSE_FAILURES': {}})
        final_raw = [page('a.test', 0, 'a'), page('b.test', 1, 'b'),
                     page('c.test', 1, 'c', 'empty'), page('d.test', 0, 'd', 'broken')]
        with contextlib.redirect_stdout(io.StringIO()):
            parsed = self.h['build_examples'](final_raw, 'final')
            self.h['build_examples']([page('calib.test', 1, 'z', 'empty')], 'calibration')
        self.assertEqual([r['sha256'] for r in parsed], ['a', 'b'])
        failures = self.h['PARSE_FAILURES']['final']
        self.assertEqual([r['reason'] for r in failures], ['no_usable_nodes', 'ValueError'])
        records = self.h['decision_rows'](parsed, [0, 1], [.1, .9], .5)
        records = self.h['append_parse_failures'](records, failures, .5)
        manifest = [{'split': 'final', 'sha256': r['sha256']} for r in final_raw]
        manifest.append({'split': 'calibration', 'sha256': 'z'})
        self.h['assert_complete_final'](records, manifest)
        metrics = self.h['count_decisions']([r['label_id'] for r in records], [r['prediction'] for r in records])
        self.assertEqual((metrics['tp'], metrics['tn'], metrics['fn'], metrics['fp']), (1, 2, 1, 0))
        self.assertEqual(metrics['recall'], .5)  # calibration failure must not enter denominator

    def test_audit_rejects_missing_duplicate_or_extra_pages(self):
        manifest = [{'split': 'final', 'sha256': 'a'}, {'split': 'calibration', 'sha256': 'b'}]
        for records in ([], [{'sha256': 'a'}, {'sha256': 'a'}], [{'sha256': 'a'}, {'sha256': 'b'}]):
            with self.assertRaises(ValueError):
                self.h['assert_complete_final'](records, manifest)

    def test_error_rows_cover_all_four_outcomes_and_validate_alignment(self):
        rows = [page(f'h{i}', label, str(i)) for i, label in enumerate((0, 0, 1, 1))]
        records = self.h['decision_rows'](rows, [0, 0, 1, 1], [.1, .9, .1, .9], .5)
        self.assertEqual([r['outcome'] for r in records], ['TN', 'FP', 'FN', 'TP'])
        with self.assertRaises(ValueError):
            self.h['decision_rows'](rows, [1, 0, 1, 1], [.1, .9, .1, .9], .5)

    def test_export_preserves_boundary_precision_and_empty_error_sets(self):
        boundary = math.nextafter(.8, math.inf)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'predictions.jsonl'
            self.h['write_jsonl'](path, [{'threshold': boundary, 'score': .8}])
            restored = json.loads(path.read_text())
            self.assertGreater(restored['threshold'], restored['score'])
            self.h['write_jsonl'](path, [])
            self.assertEqual(path.read_text(), '')


if __name__ == '__main__':
    unittest.main()
