"""CPU-only tests of the laptop notebook's sampling and checkpoint decisions."""

import ast
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import random
import re
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit


NOTEBOOK = Path(__file__).resolve().parents[1] / 'train_html_phishing_classifier.ipynb'
NB = json.loads(NOTEBOOK.read_text(encoding='utf-8'))


def helpers():
    wanted = {'normalize_page', 'host_group', 'reservoir_add', 'select_coverage',
              'sample_shard', 'sample_split', 'deduplicate', 'choose_balanced',
              'split_hosts', 'assert_separate', 'ValidationLossTracker', 'encode_page'}
    constants = {'MIN_HTML_CHARS', 'MAX_HTML_CHARS', 'PARSE_CHAR_BUDGET',
                 'SHORT_HTML_CHARS', 'SHORT_FRACTION', 'BENIGN_LOGIN_FRACTION', 'LOGIN_RE'}
    nodes = []
    for cell in NB['cells']:
        if cell['cell_type'] != 'code':
            continue
        for node in ast.parse(''.join(cell['source'])).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in wanted:
                nodes.append(node)
            elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets):
                nodes.append(node)
    ns = {'hashlib': hashlib, 'math': math, 'random': random, 're': re, 'urlsplit': urlsplit,
          'Counter': Counter, 'defaultdict': defaultdict,
          'PHRESHPHISH_LABEL_TO_ID': {'benign': 0, 'phish': 1}, 'SEED': 42, 'DATASET_ID': 'fixture'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(NOTEBOOK), 'exec'), ns)
    return ns


def page(key, label=0, host=None, short=False, login=False):
    return {'sha256': str(key), 'host': host or f'{key}.test', 'label_id': label,
            'short': short, 'is_login': login}


class HtmlNotebookTests(unittest.TestCase):
    def setUp(self):
        self.h = helpers()

    def test_cells_compile(self):
        for index, cell in enumerate(NB['cells']):
            if cell['cell_type'] == 'code':
                compile(''.join(cell['source']), f'cell_{index}', 'exec')

    def test_saved_loss_sequence_selects_epoch_two_and_stops_after_four(self):
        tracker = self.h['ValidationLossTracker'](2)
        snapshots = []
        for epoch, loss in enumerate([.7923798, .6858962, .813467, 1.024039, 1.06602], 1):
            improved, stop = tracker.update(epoch, loss)
            if improved:
                snapshots.append(epoch)
            if stop:
                break
        self.assertEqual(snapshots, [1, 2])
        self.assertEqual(tracker.best_epoch, 2)
        self.assertEqual(epoch, 4)
        self.assertAlmostEqual(tracker.best_loss, .6858962)

    def test_improvement_resets_patience_and_ties_do_not_replace_checkpoint(self):
        tracker = self.h['ValidationLossTracker'](2)
        self.assertEqual(tracker.update(1, .8), (True, False))
        self.assertEqual(tracker.update(2, .9), (False, False))
        self.assertEqual(tracker.update(3, .7), (True, False))
        self.assertEqual(tracker.update(4, .7), (False, False))
        self.assertEqual(tracker.update(5, .8), (False, True))
        self.assertEqual(tracker.best_epoch, 3)

    def test_nonfinite_loss_is_never_selected(self):
        tracker = self.h['ValidationLossTracker'](2)
        for loss in (float('nan'), float('inf'), -float('inf')):
            with self.assertRaises(ValueError):
                tracker.update(1, loss)
        self.assertIsNone(tracker.best_epoch)

    def test_118_character_benign_page_is_now_eligible(self):
        html = '<html><head><title>My Blog</title></head><body><h1>Welcome</h1><p>Just a personal blog about hiking.</p></body></html>'
        row = self.h['normalize_page']({'html': html, 'label': 'benign', 'url': 'https://BLOG.test.:443/'})
        self.assertIsNotNone(row)
        self.assertEqual(row['html_len'], 118)
        self.assertTrue(row['short'])
        self.assertEqual(row['host'], 'blog.test')
        self.assertEqual(row['label_id'], 0)

    def test_login_sampling_heuristic_never_changes_source_label(self):
        for label, expected in (('benign', 0), ('phish', 1)):
            for attr in ('type="password"', "TYPE='PASSWORD'", 'type=password'):
                row = self.h['normalize_page']({'html': f'<html><form><input {attr}></form></html>',
                                                'label': label, 'url': 'https://login.test'})
                self.assertTrue(row['is_login'])
                self.assertEqual(row['label_id'], expected)

    def test_hash_uses_full_content_before_parser_truncation(self):
        prefix = '<html>' + 'a' * self.h['PARSE_CHAR_BUDGET']
        rows = [self.h['normalize_page']({'html': prefix + suffix, 'label': 'benign', 'url': ''})
                for suffix in ('tail-one', 'tail-two')]
        self.assertEqual(rows[0]['html'], rows[1]['html'])
        self.assertNotEqual(rows[0]['sha256'], rows[1]['sha256'])

    def test_invalid_or_unknown_rows_are_not_labeled_implicitly(self):
        for raw in ({'html': None, 'label': 'benign'}, {'html': 'x', 'label': 'phish'},
                    {'html': '<html>some visible content</html>', 'label': 'unknown'}):
            self.assertIsNone(self.h['normalize_page'](raw))

    def test_training_coverage_reserves_short_and_benign_login_slots(self):
        uniform = [page(i) for i in range(20)]
        short = [page(f's{i}', short=True) for i in range(5)]
        login = [page(f'l{i}', login=True) for i in range(5)]
        chosen = self.h['select_coverage'](uniform, short, login, 10, .2, .2)
        self.assertEqual(len(chosen), 10)
        self.assertEqual(sum(r['short'] for r in chosen), 2)
        self.assertEqual(sum(r['is_login'] for r in chosen), 2)

    def test_missing_coverage_backfills_without_synthetic_examples(self):
        uniform = [page(i) for i in range(10)]
        chosen = self.h['select_coverage'](uniform, [], [], 10, .2, .2)
        self.assertEqual(chosen, uniform)

    def test_coverage_deduplicates_examples_eligible_for_multiple_categories(self):
        shared = page('shared', short=True, login=True)
        chosen = self.h['select_coverage']([shared] + [page(i) for i in range(10)],
                                          [shared], [shared], 10, .2, .2)
        self.assertEqual(sum(r['sha256'] == 'shared' for r in chosen), 1)
        self.assertEqual(len(chosen), 10)

    def test_test_selection_has_no_training_coverage_quota(self):
        uniform = [page(i) for i in range(10)]
        chosen = self.h['select_coverage'](uniform, [page('extra-short', short=True)],
                                          [page('extra-login', login=True)], 10, 0, 0)
        self.assertEqual(chosen, uniform)

    def test_reservoir_samples_beyond_first_rows(self):
        bucket, rng = [], random.Random(42)
        for count in range(1, 101):
            self.h['reservoir_add'](bucket, count, count, 10, rng)
        self.assertEqual(len(bucket), 10)
        self.assertGreater(max(bucket), 50)

    def test_shard_sampling_spans_entire_source_split(self):
        calls = []
        self.h.update({
            'HfApi': lambda: SimpleNamespace(list_repo_files=lambda *args, **kw: [f'data/train-{i:03}.parquet' for i in range(10)]),
            'hf_hub_download': lambda dataset, shard, **kw: shard,
            'sample_shard': lambda local, count, seed, enrich: calls.append(local) or [],
            'print': lambda *args: None,
        })
        self.h['sample_split']('train', 100, 4, True)
        self.assertEqual(calls, [f'data/train-{i:03}.parquet' for i in (0, 3, 6, 9)])

    def test_conflicting_labels_for_identical_content_are_removed(self):
        rows = [page('a', 0), page('a', 1), page('b', 0), page('b', 0), page('c', 1)]
        result = self.h['deduplicate'](rows)
        self.assertEqual({r['sha256'] for r in result}, {'b', 'c'})

    def test_host_split_preserves_mixed_label_groups(self):
        rows = [page(f'{i}-{label}', label, host=f'h{i}.test') for i in range(10) for label in (0, 1)]
        train, val = self.h['split_hosts'](rows, 3, 42)
        self.h['assert_separate']({'train': train, 'val': val})
        self.assertEqual(Counter(r['label_id'] for r in val), {0: 3, 1: 3})
        self.assertEqual(len(train) + len(val), len(rows))

    def test_split_check_rejects_shared_host_and_content(self):
        train = [page('a', 0), page('b', 1)]
        for bad_test in ([page('c', 0, host='a.test'), page('d', 1)],
                         [page('a', 0, host='different.test'), page('d', 1)]):
            with self.assertRaises(ValueError):
                self.h['assert_separate']({'train': train, 'test': bad_test})

    def test_shared_encoder_uses_same_padding_and_token_budget(self):
        calls = []
        self.h['encode_page']({'nodes': [['hello']], 'xpaths': [['/html/body/p']]},
                              lambda **kw: calls.append(kw))
        self.assertEqual(calls[0]['padding'], 'max_length')
        self.assertEqual(calls[0]['max_length'], 512)
        self.assertTrue(calls[0]['truncation'])


if __name__ == '__main__':
    unittest.main()
