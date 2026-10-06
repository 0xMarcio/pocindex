from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import update_cves as updater


class DeltaRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state.json'
        self.state.write_text('{"cvelist_fetch_time":"2026-08-01T00:00:00Z"}')
        self.patcher = patch.object(updater, 'STATE_FILE', self.state)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.log = [dict(fetchTime=t, new=[], updated=[]) for t in
                    ['2026-10-06T22:00:00Z', '2026-09-06T22:07:00Z']]

    def test_gap_fails_without_advancing_checkpoint(self):
        old = self.state.read_bytes()
        with patch.object(updater, 'http_json', return_value=self.log), \
                patch.object(updater, 'fetch_records') as fetch:
            with self.assertRaisesRegex(RuntimeError, 'retention gap.*catch-up-dir'):
                updater.load_incremental_records(set())
        fetch.assert_not_called()
        self.assertEqual(self.state.read_bytes(), old)

    def test_missing_or_invalid_state_fails_before_network(self):
        for content in (None, '{', '[]', '{}', '{"cvelist_fetch_time":null}',
                        '{"cvelist_fetch_time":"nonsense"}'):
            with self.subTest(content=content):
                if content is None:
                    self.state.unlink()
                else:
                    self.state.write_text(content)
                with patch.object(updater, 'http_json') as fetch:
                    with self.assertRaises(RuntimeError):
                        updater.load_incremental_records(set())
                fetch.assert_not_called()
                self.assertEqual(self.state.read_text() if self.state.exists() else None, content)

    def test_explicit_bootstrap_reads_all_retained_batches(self):
        self.state.unlink()
        for index, batch in enumerate(self.log):
            batch['new'] = [{'cveId': f'CVE-2026-{1234 + index}', 'githubLink': f'https://example.com/{index}.json'}]
        with patch.object(updater, 'http_json', return_value=self.log), \
                patch.object(updater, 'fetch_records', return_value={}) as fetch:
            _, _, checkpoint = updater.load_incremental_records(set(), bootstrap=True)
        self.assertEqual(set(fetch.call_args.args[0]), {'CVE-2026-1234', 'CVE-2026-1235'})
        self.assertEqual(checkpoint, self.log[0]['fetchTime'])
        self.assertFalse(self.state.exists())

    def test_bootstrap_cannot_reset_existing_or_corrupt_state(self):
        for content in ('{"cvelist_fetch_time":"2026-08-01T00:00:00Z"}', '{'):
            self.state.write_text(content)
            with patch.object(updater, 'http_json') as fetch:
                with self.assertRaises(RuntimeError):
                    updater.load_incremental_records(set(), bootstrap=True)
            fetch.assert_not_called()
            self.assertEqual(self.state.read_text(), content)

    def test_bootstrap_checkpoint_is_written_only_after_success(self):
        self.state.unlink()
        options = dict(bootstrap_delta=True, catch_up_dir=None, backfill_dir=None, year=None,
                       lookback_days=3, years=2, all_years=False, cve=[], skip_github=True,
                       skip_cvelist=False, cvelist_dir=None, refresh_headers=False)
        for dry_run, failure in ((False, True), (True, False), (False, False)):
            with patch.object(updater, 'parse_args', return_value=argparse.Namespace(**options, dry_run=dry_run)), \
                    patch.object(updater, 'http_json', return_value=self.log), \
                    patch.object(updater, 'reconcile_inventory', return_value=(0, 0),
                                 side_effect=RuntimeError('ingestion failed') if failure else None), \
                    patch.object(updater, 'append_inventory', return_value=0), \
                    patch.object(updater, 'refresh_record_headers', return_value=0), \
                    patch.object(updater, 'record_dates', return_value=0):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, 'ingestion failed'):
                        updater.main()
                else:
                    self.assertEqual(updater.main(), 0)
            if failure or dry_run:
                self.assertFalse(self.state.exists())
        self.assertEqual(updater.load_state(), self.log[0]['fetchTime'])

    def test_oldest_boundary_is_covered_and_offsets_compare_as_instants(self):
        self.log[0]['updated'] = [{'cveId': 'CVE-2026-1234', 'githubLink': 'https://example.com/new.json'}]
        with patch.object(updater, 'http_json', return_value=self.log):
            changes, newest = updater.delta_changes('2026-09-07T00:07:00+02:00')
        self.assertEqual(changes, {'CVE-2026-1234': 'https://example.com/new.json'})
        self.assertEqual(newest, self.log[0]['fetchTime'])

    def test_invalid_or_unordered_log_fails(self):
        for log in [list(reversed(self.log)), [{'fetchTime': ''}]]:
            with self.subTest(log=log), patch.object(updater, 'http_json', return_value=log):
                with self.assertRaises(RuntimeError):
                    updater.delta_changes(None, bootstrap=True)

    def snapshot(self):
        base = self.root / 'snapshot' / 'cves'
        base.mkdir(parents=True)
        (base / 'deltaLog.json').write_text(json.dumps(self.log))
        for cid, changed in [('CVE-2026-1234', '2026-09-01T00:00:00Z'),
                             ('CVE-2026-1235', '2026-07-01T00:00:00Z')]:
            path = base / '2026' / '1xxx' / (cid + '.json')
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(json.dumps({'cveMetadata': {'cveId': cid, 'state': 'REJECTED', 'dateUpdated': changed}}))
        self.commit_snapshot(base.parent)
        return base.parent

    def commit_snapshot(self, root):
        for command in (['init', '-q'], ['add', 'cves'],
                        ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit', '-qm', 'Snapshot fixture']):
            subprocess.run(['git', '-C', str(root), *command], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_catch_up_includes_records_older_than_retained_log(self):
        snapshot = self.snapshot()
        with patch.object(updater, 'load_blacklist', return_value=[]):
            records, refs, checkpoint = updater.load_catch_up_records(snapshot)
        self.assertEqual(set(records), {'CVE-2026-1234'})
        self.assertEqual(refs, {})
        self.assertEqual(checkpoint, self.log[0]['fetchTime'])
        self.assertEqual(updater.load_state(), '2026-08-01T00:00:00Z')

    def test_success_only_advances_to_snapshot_checkpoint_and_dry_run_does_not(self):
        snapshot = self.snapshot()
        options = dict(catch_up_dir=snapshot, backfill_dir=None, year=None, lookback_days=3,
                       years=2, all_years=False, cve=[], skip_github=True, skip_cvelist=False,
                       cvelist_dir=None, refresh_headers=False)
        old = self.state.read_bytes()
        for dry_run in [True, False]:
            with patch.object(updater, 'parse_args', return_value=argparse.Namespace(**options, dry_run=dry_run)), \
                    patch.object(updater, 'http_json', side_effect=AssertionError('catch-up must use local records')), \
                    patch.object(updater, 'reconcile_inventory', return_value=(0, 0)), \
                    patch.object(updater, 'append_inventory', return_value=0), \
                    patch.object(updater, 'refresh_record_headers', return_value=0), \
                    patch.object(updater, 'record_dates', return_value=0):
                self.assertEqual(updater.main(), 0)
            if dry_run:
                self.assertEqual(self.state.read_bytes(), old)
        self.assertEqual(updater.load_state(), self.log[0]['fetchTime'])

    def test_extracted_directory_cannot_advance_checkpoint(self):
        checkout = self.snapshot()
        extracted = self.root / 'extracted'
        shutil.copytree(checkout, extracted, ignore=shutil.ignore_patterns('.git'))
        with self.assertRaisesRegex(RuntimeError, 'Git checkout'):
            updater.load_catch_up_records(extracted)
        self.assertEqual(updater.load_state(), '2026-08-01T00:00:00Z')

    def test_missing_tracked_record_or_changed_delta_log_fails(self):
        snapshot = self.snapshot()
        missing = snapshot / 'cves/2026/1xxx/CVE-2026-1235.json'
        saved = missing.read_bytes()
        missing.unlink()
        with self.assertRaisesRegex(RuntimeError, 'missing, dirty or sparse'):
            updater.load_catch_up_records(snapshot)
        missing.write_bytes(saved)
        log = snapshot / 'cves/deltaLog.json'
        log.write_text(json.dumps([{'fetchTime': '2026-10-07T00:00:00Z'}]))
        with self.assertRaisesRegex(RuntimeError, 'missing, dirty or sparse'):
            updater.load_catch_up_records(snapshot)
        self.assertEqual(updater.load_state(), '2026-08-01T00:00:00Z')

    def test_untracked_record_is_not_part_of_pinned_snapshot(self):
        snapshot = self.snapshot()
        extra = snapshot / 'cves/2026/1xxx/CVE-2026-9999.json'
        extra.write_text('{}')
        records, _, _ = updater.load_catch_up_records(snapshot)
        self.assertNotIn(extra.stem, records)

    def test_bad_snapshot_leaves_checkpoint_untouched(self):
        snapshot = self.snapshot()
        (snapshot / 'cves/2026/1xxx/CVE-2026-1234.json').write_text('{}')
        old = self.state.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'Invalid catch-up'):
            updater.load_catch_up_records(snapshot)
        self.assertEqual(self.state.read_bytes(), old)


if __name__ == '__main__':
    unittest.main()
