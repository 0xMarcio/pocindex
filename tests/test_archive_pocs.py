from __future__ import annotations

import copy
import gzip
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import archive_pocs as archive
import build_site
import releases

URL = 'https://github.com/owner/poc'
CVE = 'CVE-2026-1234'


def snapshot(url=URL, stamp=None):
    stamp = stamp or datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    return {'url': archive.snapshot_url(url, stamp), 'timestamp': stamp, 'verified_at': archive.now()}


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.target = {'original': URL, 'cves': [CVE], 'priority': archive.now()}
        self.rows = {}
        self.client = MagicMock()
        self.client.lookup.return_value = None
        self.client.submit.return_value = {'job_id': 'pending-123'}
        p = patch.object(archive.link_health, 'unavailable', return_value=False)
        self.dead = p.start()
        self.addCleanup(p.stop)

    def test_inventory_limits_cve_year_and_preserves_source_paths(self):
        ledger = {
            'old': {'url': URL + '-old', 'cve': 'CVE-2025-1234'},
            'new': {'url': URL, 'cve': CVE, 'head': 'b' * 40, 'sha': 'a' * 40,
                    'commit_verified': True, 'paths': ['wrong.py'], 'history_paths': ['PoC x.py']},
            'future': {'url': URL, 'cve': 'CVE-2027-4567'},
            'bad': {'url': URL + '-blocked', 'cve': CVE},
            'excluded': {'url': URL + '-excluded', 'cve': CVE},
            'withdrawn': {'url': URL + '-withdrawn', 'cve': CVE, 'gone': '2026-01-01'},
        }
        with patch.object(releases, 'load_ledger', return_value=ledger), \
                patch.object(build_site, 'load_blacklist', return_value={'owner/poc-blocked'}), \
                patch.object(build_site, 'load_source_exclusions', return_value={(CVE, 'owner/poc-excluded')}):
            result = archive.inventory()
        self.assertEqual(len(result), 2)
        self.assertEqual(set(result[URL]['cves']), {CVE, 'CVE-2027-4567'})
        raw = next(v for v in result.values() if v.get('parent'))
        self.assertTrue(raw['original'].endswith('/' + 'a' * 40 + '/PoC%20x.py'))

    def test_snapshot_validation_rejects_fake_hosts_invalid_dates_and_private_urls(self):
        good = snapshot()
        self.assertTrue(archive.valid_snapshot({'snapshot': good}))
        for url in ('http://localhost/a', 'http://127.0.0.1/a', 'http://169.254.169.254/a',
                    'https://user:password@example.com/a', 'javascript:alert(1)', 'https://host.internal/a'):
            self.assertFalse(archive.public_url(url), url)
        for bad in ({**good, 'url': good['url'].replace('web.archive.org', 'web.archive.org.evil.example')},
                    {**good, 'timestamp': '20260231000000'}, {**good, 'verified_at': ''}):
            self.assertFalse(archive.valid_snapshot({'snapshot': bad}))

    def test_first_observation_does_not_disqualify_older_public_captures(self):
        ledger = [{'url': URL, 'cve': CVE, 'seen': '2026-10-21T12:00:00Z'},
                  {'url': URL + '-dated', 'cve': CVE, 'seen': '2026-10-21T12:00:00Z',
                   'source': '2026-05-13'}]
        with patch.object(archive, 'eligible_ledger', return_value=ledger):
            result = archive.inventory()
        self.assertNotIn('not_before', result[URL])
        self.assertEqual(result[URL + '-dated']['not_before'], '2026-05-13T00:00:00Z')

    def test_pinned_file_urls_preserve_bytes_without_additional_github_queries(self):
        parent = URL + '/blob/' + 'b' * 40 + '/path/PoC%20file.py#example'
        with patch.object(archive, 'eligible_ledger', return_value=[{'url': parent, 'cve': CVE}]):
            result = archive.inventory()
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'b' * 40 + '/path/PoC%20file.py'
        self.assertEqual(result[raw]['parent'], archive.identity(parent))
        self.assertEqual(result[raw]['parent_original'], parent)

    def test_lookup_rejects_capture_of_a_different_url(self):
        client = archive.Client()
        snap = snapshot(URL + '-other')
        response = {'archived_snapshots': {'closest': {**snap, 'status': '200', 'available': True}}}
        with patch.object(client, 'json', return_value=response):
            self.assertIsNone(client.lookup(URL))

    def test_existing_capture_is_verified_without_resubmission(self):
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))
        self.client.submit.assert_not_called()

    def test_pending_job_is_checkpointed_and_polled_without_duplicate_submission(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['job_id'], 'pending-123')
        self.client.status.return_value = {'status': 'pending'}
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.client.lookup.assert_called_once_with(URL)
        self.assertEqual(self.rows[URL]['attempts'], 1)

    def test_submission_budget_is_saved_before_the_network_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            def interrupted(*args, **kwargs):
                row = archive.load_records(path)[URL]
                self.assertEqual(row['submissions']['count'], 1)
                self.assertTrue(row['submitted_at'])
                self.assertTrue(row['lookup_required'])
                raise KeyboardInterrupt()
            self.client.submit.side_effect = interrupted
            with self.assertRaises(KeyboardInterrupt):
                archive.process(URL, self.target, self.rows, self.client, capture=True, directory=path)
            self.assertEqual(archive.load_records(path)[URL]['submissions']['count'], 1)

    def test_success_requires_replay_verification(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        snap = snapshot()
        self.client.status.return_value = {'status': 'success', 'timestamp': snap['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['status'], 'available')
        self.assertNotIn('job_id', self.rows[URL])
        self.assertEqual(archive.published_snapshots(self.rows, manifests={})[URL]['url'], snap['url'])

    def test_refused_submission_restores_budget_but_timeout_requires_recovery(self):
        for reason in ('transport-ConnectionRefusedError', 'transport-TimeoutError'):
            with self.subTest(reason=reason):
                rows = {URL: {**self.target, 'attempts': 6}}
                self.client.submit.side_effect = archive.ArchiveError(reason)
                with self.assertRaises(archive.ArchiveError):
                    archive.process(URL, self.target, rows, self.client, capture=True)
                row = rows[URL]
                self.assertEqual(row['attempts'], 6)
                self.assertLessEqual(row['next_check_at'], archive.after(3600))
                self.assertEqual(row['submissions']['count'], int(reason.endswith('TimeoutError')))
                self.assertEqual(bool(row.get('lookup_required')), reason.endswith('TimeoutError'))

    def test_uncertain_raw_submission_is_looked_up_before_retry(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        target = {**self.target, 'original': raw, 'parent': URL}
        self.rows[raw] = {**target, 'lookup_required': True}
        self.client.lookup.return_value = snapshot(raw)
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(raw, target, self.rows, self.client, capture=True)
        self.client.lookup.assert_called_once_with(raw)
        self.client.submit.assert_not_called()
        self.assertTrue(archive.valid_snapshot(self.rows[raw]))
        self.assertNotIn('lookup_required', self.rows[raw])

    def test_candidate_expiry_uses_observation_age_not_capture_date(self):
        for age, expired in ((0, False), (-49 * 3600, True)):
            with self.subTest(age=age):
                row = {**self.target, 'candidate': snapshot(stamp='20260101000000'),
                       'candidate_seen_at': archive.after(age), 'verify_attempts': 3}
                with patch.object(archive, 'verify_snapshot', side_effect=archive.ArchiveError('replay-http-404')):
                    with self.assertRaises(archive.ArchiveError):
                        archive.verify_candidate(row)
                self.assertEqual('candidate' not in row, expired)
                self.assertEqual(bool(row.get('lookup_required')), expired)
                self.assertNotIn('bad_capture', row)

    def test_uncertain_submission_does_not_loop_on_an_invalid_existing_capture(self):
        target = {**self.target, 'not_before': archive.now()}
        self.rows[URL] = {**target, 'lookup_required': True}
        self.client.lookup.return_value = snapshot(stamp='20260101000000')
        archive.process(URL, target, self.rows, self.client, capture=True)
        self.assertNotIn('lookup_required', self.rows[URL])
        archive.process(URL, target, self.rows, self.client, capture=True)
        self.client.lookup.assert_called_once()
        self.client.submit.assert_called_once_with(URL, retry=True)

    def test_rediscovered_expired_capture_cannot_restart_verification_forever(self):
        snap = snapshot()
        self.rows[URL] = {**self.target, 'lookup_required': True, 'expired_capture': snap['timestamp']}
        self.client.lookup.return_value = snap
        with patch.object(archive, 'verify_snapshot') as verify:
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        verify.assert_not_called()
        self.assertNotIn('candidate', self.rows[URL])
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once_with(URL, retry=True)

    def test_expired_job_recovers_by_lookup(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.status.side_effect = archive.ArchiveError('http-404')
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertNotIn('job_id', self.rows[URL])
        self.client.submit.assert_called_once()

    def test_expired_job_cannot_resubmit_when_capture_slots_are_full(self):
        self.rows[URL] = {**self.target, 'job_id': 'old', 'submitted_at': archive.after(-7200)}
        archive.process(URL, self.target, self.rows, self.client, capture=True, allow_submit=False)
        self.client.submit.assert_not_called()
        self.assertEqual(self.rows[URL]['status'], 'queued')
        self.assertNotIn('job_id', self.rows[URL])

    def test_refresh_error_keeps_previous_good_capture(self):
        old = snapshot(stamp='20260101000000')
        self.rows[URL] = {**self.target, 'snapshot': old, 'job_id': 'pending-123', 'attempts': 1}
        self.client.status.return_value = {'status': 'error', 'status_ext': 'error:read-timeout'}
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['snapshot'], old)
        self.assertEqual(archive.published_snapshots(self.rows, manifests={})[URL]['url'], old['url'])

    def test_unverified_terminal_job_never_resubmits_in_a_loop(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot', return_value=False):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.assertNotIn('job_id', self.rows[URL])
        self.assertNotIn('candidate', self.rows[URL])
        self.assertGreater(self.rows[URL]['next_check_at'], archive.now())
        self.assertFalse(archive.valid_snapshot(self.rows[URL]))

    def test_transient_replay_failure_retains_candidate_without_resubmission(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot', side_effect=archive.ArchiveError('replay-http-404')):
            with self.assertRaises(archive.ArchiveError):
                archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertIn('candidate', self.rows[URL])
        self.assertNotIn('job_id', self.rows[URL])
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))

    def test_expired_jobs_do_not_reserve_a_capture_slot(self):
        self.rows[URL] = {**self.target, 'job_id': 'old-job', 'submitted_at': archive.after(-7200)}
        self.assertFalse(archive.active_job(self.rows[URL]))
        archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.client.status.assert_not_called()
        self.client.lookup.assert_called_once_with(URL)
        self.assertNotIn('job_id', self.rows[URL])

    def test_dead_original_with_good_capture_clears_stale_work(self):
        self.rows[URL] = {**self.target, 'snapshot': snapshot(), 'job_id': 'stale',
                          'candidate': snapshot(), 'submitted_at': archive.after(-7200)}
        self.dead.return_value = True
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertNotIn('job_id', self.rows[URL])
        self.assertNotIn('candidate', self.rows[URL])
        self.assertEqual(self.rows[URL]['status'], 'available')

    def test_fragments_never_enter_capture_identity_or_poison_a_shard(self):
        original = URL + '#poc'
        target = {**self.target, 'original': original}
        self.rows[URL] = {**target, 'job_id': 'job', 'submitted_at': archive.now()}
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': original}
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, target, self.rows, self.client, capture=True)
        self.assertNotIn('#', self.rows[URL]['snapshot']['url'])
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))
        with tempfile.TemporaryDirectory() as directory:
            archive.save_records(self.rows, {URL}, Path(directory))
            self.assertEqual(archive.load_records(Path(directory)), self.rows)

    def test_repeated_unverifiable_capture_gets_increasing_backoff(self):
        self.rows[URL] = {**self.target, 'attempts': 7, 'candidate': snapshot()}
        with patch.object(archive, 'verify_snapshot', return_value=False):
            archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.assertGreater(self.rows[URL]['next_check_at'], archive.after(6 * 3600))

    def test_redirect_homepage_and_capture_predating_poc_are_not_published(self):
        for target, captured in ((self.target, snapshot('https://github.com/')),
                                 ({**self.target, 'not_before': archive.now()}, snapshot(stamp='20260101000000'))):
            rows = {URL: {**target, 'candidate': captured}}
            with patch.object(archive, 'verify_snapshot') as replay:
                archive.process(URL, target, rows, self.client, capture=False)
            replay.assert_not_called()
            self.assertFalse(archive.valid_snapshot(rows[URL]))

    def test_account_errors_are_separate_from_target_errors(self):
        self.assertEqual(archive.service_error('error:max-daily-bandwidth').cooldown, 86400)
        for reason in ('error:filesize-limit', 'error:bandwidth-limit-exceeded',
                       'error:too-many-daily-captures', 'error:soft-time-limit-exceeded'):
            self.assertIsNone(archive.service_error(reason), reason)

    def test_daily_submission_budget_is_durable_and_first_capture_is_retained(self):
        self.rows[URL] = {**self.target, 'submissions': {'date': archive.now()[:10], 'count': 2}}
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_not_called()
        old = snapshot(stamp='20260101000000')
        self.rows[URL].update(snapshot=old, candidate=snapshot())
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['snapshot'], old)

    def test_source_snapshots_are_attached_to_their_published_parent(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/PoC.py'
        rows = {raw: {'original': raw, 'parent': URL, 'snapshot': snapshot(raw)}}
        result = archive.published_snapshots(rows, {URL}, manifests={})
        self.assertEqual(result[URL]['files'][0]['original'], raw)
        self.assertEqual(archive.published_snapshots(rows, set(), manifests={}), {})

    def test_source_file_can_recover_a_dead_parent_without_a_page_capture(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/PoC.py'
        rows = {raw: {'original': raw, 'parent': URL, 'cves': [CVE], 'snapshot': snapshot(raw)}}
        self.dead.return_value = True
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL, 'field': 'nuclei'}]):
            self.assertEqual(archive.archived_fallbacks(rows)[CVE], [('nuclei', rows[raw]['snapshot']['url'])])

    def test_dead_parent_fallback_respects_current_source_selection(self):
        from archive_sources import SCAN_VERSION
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/lib.py'
        rows = {raw: {'original': raw, 'parent': URL, 'cves': [CVE], 'snapshot': snapshot(raw)}}
        manifests = {URL: {'complete': True, 'scan_version': SCAN_VERSION, 'revision': 'a' * 40,
                           'files': [{'path': 'poc.py'}]}}
        self.dead.return_value = True
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL}]), \
                patch.object(archive, 'load_source_manifests', return_value=manifests):
            self.assertEqual(archive.published_snapshots(rows, {URL}), {})
            self.assertEqual(archive.archived_fallbacks(rows).get(CVE, []), [])

    def test_dead_repo_files_remain_one_poc_with_all_saved_files(self):
        raws = ['https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/' + p
                for p in ('README.md', 'lib.py', 'poc.py')]
        rows = {raw: {'original': raw, 'parent': URL, 'cves': [CVE], 'snapshot': snapshot(raw)} for raw in raws}
        self.dead.return_value = True
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL}]), \
                patch.object(archive, 'load_source_manifests', return_value={}):
            fallback = archive.archived_fallbacks(rows)[CVE]
        self.assertEqual(fallback, [('poc', rows[raws[-1]]['snapshot']['url'])])
        published = archive.published_snapshots(rows, {URL, raws[-1]}, manifests={})
        self.assertEqual({r['original'] for r in published[raws[-1]]['files']}, set(raws))

    def test_saved_file_cve_correction_applies_without_recapture(self):
        from archive_sources import SCAN_VERSION
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        correct = 'CVE-2026-5678'
        rows = {raw: {'original': raw, 'parent': URL, 'cves': [CVE], 'snapshot': snapshot(raw)}}
        manifests = {URL: {'complete': True, 'scan_version': SCAN_VERSION, 'revision': 'a' * 40,
                           'files': [{'path': 'poc.py', 'cves': [correct]}]}}
        self.dead.return_value = True
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': cve, 'url': URL} for cve in (CVE, correct)]), \
                patch.object(archive, 'load_source_manifests', return_value=manifests):
            fallback = archive.archived_fallbacks(rows)
        self.assertFalse(fallback.get(CVE))
        self.assertEqual(fallback[correct], [('poc', rows[raw]['snapshot']['url'])])

    def test_snapshot_original_alias_keeps_saved_files_on_dead_repo_page(self):
        import build_pages
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        capture = snapshot('http://www.github.com/Owner/PoC')
        rows = {URL: {'original': URL, 'snapshot': capture},
                raw: {'original': raw, 'parent': URL, 'snapshot': snapshot(raw)}}
        published = archive.published_snapshots(rows, {URL}, manifests={})
        self.assertEqual(len(build_pages.shown_files(capture['url'], published)), 1)

    def test_live_pinned_file_can_be_captured_after_branch_link_dies(self):
        parent = URL + '/blob/main/poc.py'
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        target = {'original': raw, 'cves': [CVE], 'priority': '', 'parent': parent,
                  'parents': {parent: parent}, 'expected_blobs': ['b' * 40], 'strict_blobs': True}
        self.rows[raw] = {**target, 'unavailable_since': '2026-01-01T00:00:00Z'}
        self.dead.side_effect = lambda url: url == parent
        archive.process(raw, target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once_with(raw, retry=False)
        self.assertNotIn('unavailable_since', self.rows[raw])

    def test_empty_dead_link_lookups_back_off_and_recovery_clears_backoff(self):
        self.dead.return_value = True
        for delay in (3600, 6 * 3600, 86400, 3 * 86400, 30 * 86400, 30 * 86400):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
            self.assertGreaterEqual(self.rows[URL]['next_check_at'], archive.after(delay - 5))
        self.client.submit.assert_not_called()
        live = URL + '-live'
        targets = {URL: {**self.target, 'priority': '2099'}, live: {**self.target, 'original': live, 'priority': '2000'}}
        self.rows[URL]['next_check_at'] = ''
        self.assertEqual(archive.select_targets(targets, self.rows, capture=True)[0], live)
        self.dead.return_value = False
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertNotIn('empty_lookups', self.rows[URL])
        self.client.submit.assert_called_once_with(URL, retry=False)

    def test_invalid_dead_link_capture_keeps_lookup_backoff(self):
        self.dead.return_value = True
        self.client.lookup.return_value = snapshot(stamp='20250101000000')
        with patch.object(archive, 'verify_snapshot', return_value=False):
            for count, delay in ((1, 3600), (2, 6 * 3600)):
                archive.process(URL, self.target, self.rows, self.client, capture=True)
                self.assertEqual(self.rows[URL]['empty_lookups'], count)
                self.assertGreaterEqual(self.rows[URL]['next_check_at'], archive.after(delay - 5))
        self.client.submit.assert_not_called()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertNotIn('empty_lookups', self.rows[URL])

    def test_recovered_original_keeps_archive_until_it_is_reimported(self):
        self.dead.return_value = False
        self.rows[URL] = {**self.target, 'snapshot': snapshot()}
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL, 'gone_reason': 'unavailable'}]):
            self.assertEqual(len(archive.archived_fallbacks(self.rows)[CVE]), 1)

    def test_managed_fallback_does_not_redate_or_remove_legacy_archive_links(self):
        managed = snapshot()['url']
        legacy = archive.snapshot_url(URL + '-legacy', '20200101000000')
        with patch.object(archive, 'load_records', return_value={URL: {**self.target, 'snapshot': snapshot()}}):
            self.assertEqual(releases.published_pairs([{'cve': CVE, 'poc': [managed, legacy]}]), [(CVE, legacy)])
        old = releases.record({}, CVE, URL, observed_at='2026-01-01T00:00:00Z')
        self.dead.return_value = True
        ledger = releases.reconcile({releases.key(CVE, URL): old}, [], observed_at='2026-02-01T00:00:00Z')
        row = ledger[releases.key(CVE, URL)]
        self.assertEqual(row['seen'], '2026-01-01T00:00:00Z')
        self.assertEqual(row['gone_reason'], 'unavailable')

    def test_trending_observation_does_not_withdraw_recovered_archive_fallback(self):
        identity = releases.key(CVE, URL)
        ledger = releases.reconcile({}, [(CVE, URL)], observed_at='2026-01-01T00:00:00Z')
        self.dead.return_value = True
        ledger = releases.reconcile(ledger, [], observed_at='2026-02-01T00:00:00Z')
        self.dead.return_value = False
        releases.record(ledger, CVE, URL, {'repo': 123}, observed_at='2026-03-01T00:00:00Z')
        ledger = releases.reconcile(ledger, [], observed_at='2026-03-01T00:00:00Z')
        self.assertEqual(ledger[identity]['gone_reason'], 'unavailable')
        self.assertEqual(ledger[identity]['gone'], '2026-02-01T00:00:00Z')
        with patch.object(archive, 'eligible_ledger', return_value=list(ledger.values())):
            fallback = archive.archived_fallbacks(records={URL: {**self.target, 'snapshot': snapshot()}})
        self.assertTrue(fallback[CVE])
        ledger = releases.reconcile(ledger, [(CVE, URL)], observed_at='2026-03-01T00:00:00Z')
        self.assertNotIn('gone', ledger[identity])
        self.assertEqual(ledger[identity]['seen'], '2026-01-01T00:00:00Z')

    def test_dead_original_is_only_looked_up_and_blacklist_cannot_be_bypassed(self):
        self.dead.return_value = True
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_not_called()
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL}]):
            self.assertEqual(len(archive.archived_fallbacks(self.rows)[CVE]), 1)
        self.assertFalse(archive.archived_fallbacks(self.rows, blacklist={'owner/poc'}))
        self.assertFalse(archive.archived_fallbacks(self.rows, exclusions={(CVE, 'owner/poc')}))
        self.rows[URL]['parent'] = URL + '-parent'
        self.assertFalse(archive.archived_fallbacks(self.rows))

    def test_cooldown_and_checkpoints_survive_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'incoming', root / 'current'
            incoming = {URL: {**self.target, 'checked_at': archive.now(), 'status': 'retry'}}
            existing = {URL: {**self.target, 'checked_at': '2026-01-01', 'snapshot': snapshot()}}
            archive.save_records(incoming, {URL}, source)
            archive.save_records(existing, {URL}, destination)
            control = {'retry_after': archive.after(300), 'reason': 'http-429'}
            (source / 'control.json').write_text(json.dumps(control))
            with patch.object(sys, 'argv', ['archive', '--directory', str(destination), '--merge-from', str(source)]):
                self.assertEqual(archive.main(), 0)
            self.assertTrue(archive.valid_snapshot(archive.load_records(destination)[URL]))
            self.assertEqual(json.loads((destination / 'control.json').read_text()), control)

    def test_quota_and_retry_after_are_respected(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'json', return_value={'daily_captures': 30000, 'daily_captures_limit': 30000, 'available': 3}):
            with self.assertRaises(archive.ArchiveError) as result:
                client.capacity()
            self.assertEqual(result.exception.cooldown, 86400)
        self.assertEqual(archive.retry_delay('1200'), 1200)
        self.assertGreaterEqual(archive.retry_delay('invalid'), 300)
        opener = MagicMock()
        opener.open.side_effect = HTTPError('https://web.archive.org/save', 429, 'wait', {'Retry-After': '600'}, None)
        with patch.object(archive.request, 'build_opener', return_value=opener):
            with self.assertRaises(archive.ArchiveError) as result:
                client.submit(URL)
            self.assertEqual(result.exception.cooldown, 600)

    def test_capture_uses_only_explicit_url_and_never_archives_errors(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'json', return_value={'job_id': '1'}) as send:
            client.submit(URL)
        payload = send.call_args.args[1]
        self.assertEqual(payload['capture_all'], '0')
        self.assertEqual(payload['capture_outlinks'], '0')
        self.assertEqual(payload['if_not_archived_within'], '30d')

    def test_live_page_reuses_existing_snapshot_in_capture_mode(self):
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))
        self.client.submit.assert_not_called()

    def test_negative_lookup_is_immediately_ready_for_capture(self):
        archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.assertEqual(self.rows[URL]['next_check_at'], '')
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.lookup.assert_called_once()
        self.client.submit.assert_called_once()

    def test_transport_error_is_not_an_account_cooldown(self):
        from urllib.error import URLError
        opener = MagicMock()
        opener.open.side_effect = URLError(ConnectionResetError())
        with patch.object(archive.request, 'build_opener', return_value=opener):
            with self.assertRaises(archive.ArchiveError) as result:
                archive.Client().lookup(URL)
        self.assertEqual(result.exception.cooldown, 0)
        self.assertEqual(str(result.exception), 'transport-ConnectionResetError')

    def test_old_unseen_pages_and_files_cannot_be_starved_by_new_pages(self):
        targets = {f'{URL}/{i}': {**self.target, 'priority': '2026-10-22'} for i in range(100)}
        targets[URL] = {**self.target, 'priority': ''}
        targets['file'] = {**self.target, 'parent': URL, 'priority': '2026-01-01'}
        selected = archive.select_targets(targets, {})
        self.assertIn(URL, selected[:4])
        self.assertIn('file', selected[:4])
        self.assertEqual(len(selected), len(set(selected)))

    def test_lookup_sweep_continues_after_one_connection_failure(self):
        urls = [URL + str(i) for i in range(3)]
        targets = {u: {**self.target, 'original': u} for u in urls}
        def lookup(url):
            if url == urls[0]:
                raise archive.ArchiveError('transport-ConnectionResetError')
            return snapshot(url)
        self.client.lookup.side_effect = lookup
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, 'verify_snapshot', return_value=True):
            archive.lookup_pages(targets, self.rows, self.client, Path(directory), 3, 10)
            self.assertEqual(len(archive.load_records(Path(directory))), 3)
            self.assertEqual(sum(archive.valid_snapshot(r) for r in self.rows.values()), 2)
            self.assertFalse((Path(directory) / 'lookup-control.json').exists())

    def test_capacity_uses_documented_millisecond_cache_buster(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'json', return_value={'available': 3}) as call, patch.object(archive.time, 'time', return_value=1234.5):
            self.assertEqual(client.capacity(), 3)
        call.assert_called_once_with(archive.API + '/status/user?_t=1234500', auth=True)

    def test_completed_jobs_waiting_for_status_do_not_occupy_available_slots(self):
        clock, visited = [0.0], []
        base = datetime.now(timezone.utc).replace(microsecond=0)
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        targets = {raw: {**self.target, 'original': raw, 'parent': URL}}
        pending = {URL + str(i): {**self.target, 'original': URL + str(i), 'job_id': f'job-{i}',
                                  'submitted_at': archive.now(), 'next_check_at': ''} for i in range(3)}
        targets.update({k: {**self.target, 'original': k} for k in pending})
        def process(key, target, rows, client, **kwargs):
            visited.append(key)
            clock[0] += 5
            rows.setdefault(key, dict(target)).update(next_check_at=archive.after(3600), status='pending')
        with tempfile.TemporaryDirectory() as directory:
            archive.save_records(pending, set(pending), Path(directory))
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(archive, 'now', side_effect=lambda: (base + timedelta(seconds=clock[0])).strftime('%Y-%m-%dT%H:%M:%SZ')), \
                    patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(archive.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--limit', '1', '--max-seconds', '60']):
                self.assertEqual(archive.main(), 0)
        self.assertIn(raw, visited)

    def test_capture_slots_are_consumed_and_refreshed_before_more_submissions(self):
        clock, checked, submitted = [100.0], [], []
        base = datetime.now(timezone.utc).replace(microsecond=0)
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/'
        targets = {raw + name: {**self.target, 'original': raw + name, 'parent': URL} for name in ('a.py', 'b.py')}
        def capacity(client):
            checked.append(clock[0])
            return 1 if len(checked) in {2, 4} else 0
        def process(key, target, rows, client, **kwargs):
            self.assertTrue(kwargs['allow_submit'])
            submitted.append(clock[0])
            client.last_submit = clock[0]
            rows[key] = {**target, 'status': 'available', 'next_check_at': archive.after(3600)}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', autospec=True, side_effect=capacity), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(archive, 'now', side_effect=lambda: (base + timedelta(seconds=clock[0] - 100)).strftime('%Y-%m-%dT%H:%M:%SZ')), \
                    patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(archive.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--limit', '2', '--max-seconds', '240']):
                self.assertEqual(archive.main(), 0)
        self.assertEqual(checked, [100, 130, 160, 190])
        self.assertEqual(submitted, [130, 190])

    def test_raw_verification_has_priority_without_starving_page_captures(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/'
        targets = {raw + str(i) + '.py': {**self.target, 'original': raw + str(i) + '.py', 'parent': URL} for i in range(5)}
        targets.update({URL + str(i): {**self.target, 'original': URL + str(i)} for i in range(2)})
        rows = {key: {**target, 'candidate': snapshot(key),
                      'next_check_at': archive.after(-10 if target.get('parent') else -3600)} for key, target in targets.items()}
        visited = []
        def process(key, target, state, client, **kwargs):
            visited.append(key)
            state[key] = {**target, 'status': 'available', 'next_check_at': archive.after(3600)}
        with tempfile.TemporaryDirectory() as directory:
            archive.save_records(rows, set(rows), Path(directory))
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--max-seconds', '120']):
                self.assertEqual(archive.main(), 0)
        self.assertEqual([bool(targets[k].get('parent')) for k in visited], [True, True, True, True, False, True, False])

    def test_uncertain_file_submission_resumes_instead_of_waiting_behind_new_files(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/'
        targets = {raw + str(i) + '.py': {**self.target, 'original': raw + str(i) + '.py', 'parent': URL} for i in range(20)}
        uncertain = raw + 'uncertain.py'
        targets[uncertain] = {**self.target, 'original': uncertain, 'parent': URL}
        rows = {uncertain: {**targets[uncertain], 'lookup_required': True, 'submitted_at': archive.after(-7200)}}
        visited = []
        def process(key, target, state, client, **kwargs):
            visited.append(key)
            state[key] = {**target, 'status': 'available', 'next_check_at': archive.after(3600)}
        with tempfile.TemporaryDirectory() as directory:
            archive.save_records(rows, set(rows), Path(directory))
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--limit', '1', '--max-seconds', '120']):
                self.assertEqual(archive.main(), 0)
        self.assertIn(uncertain, visited[:2])

    def test_target_access_failure_does_not_masquerade_as_bad_credentials(self):
        client = archive.Client('dummy', 'dummy')
        opener = MagicMock()
        opener.open.side_effect = HTTPError(archive.API, 401, 'target access denied', {}, None)
        with patch.object(archive.request, 'build_opener', return_value=opener), patch.object(client, 'account', return_value={'available': 0}):
            with self.assertRaises(archive.ArchiveError) as result:
                client.submit(URL)
        self.assertFalse(result.exception.fatal)
        self.assertEqual(str(result.exception), 'target-http-401')

    def test_capacity_reports_available_slots_without_counting_local_jobs(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'account', return_value={'available': 0, 'processing': 3}):
            self.assertEqual(client.capacity(), 0)
        with patch.object(client, 'account', return_value={'available': 3, 'processing': 0}):
            self.assertEqual(client.capacity(), 3)

    def test_capacity_failure_keeps_verification_running_until_repeated(self):
        pending = URL + '-pending'
        targets = {key: {**self.target, 'original': key} for key in (URL, pending)}
        for failures in (1, 3):
            clock, visited = [100.0], []
            def process(key, target, rows, client, **kwargs):
                visited.append(key)
                rows[key] = {**target, 'status': 'available'}
            errors = [archive.ArchiveError('transport-ConnectionRefusedError') for _ in range(failures)]
            with self.subTest(failures=failures), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                archive.save_records({pending: {**targets[pending], 'candidate': snapshot(pending)}}, {pending}, path)
                with patch.object(archive, 'inventory', return_value=targets), \
                        patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                        patch.object(archive.Client, 'capacity', side_effect=errors + [3]) as capacity, \
                        patch.object(archive, 'process', side_effect=process), \
                        patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                        patch.object(archive.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                        patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--limit', '1', '--max-seconds', '180']):
                    self.assertEqual(archive.main(), 0)
                self.assertEqual(visited[0], pending)
                self.assertEqual((path / 'control.json').exists(), failures == 3)
                self.assertEqual(capacity.call_count, 2 if failures == 1 else 3)

    def test_pending_recovery_obeys_host_block_and_does_not_resubmit_old_revision(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        target = {**self.target, 'original': raw, 'parent': URL}
        for blocked in (True, False):
            targets = {URL: self.target, **({raw: target} if blocked else {})}
            rows = {raw: {**target, 'lookup_required': True},
                    URL: {**self.target, 'next_check_at': archive.after(86400)}}
            if blocked:
                other = raw.replace('poc.py', 'other.py')
                rows[other] = {**target, 'original': other, 'host_retry_after': archive.after(86400)}
            clock = [100.0]
            with self.subTest(blocked=blocked), tempfile.TemporaryDirectory() as directory:
                archive.save_records(rows, set(rows), Path(directory))
                with patch.object(archive, 'inventory', return_value=targets), \
                        patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                        patch.object(archive.Client, 'lookup', return_value=None) as lookup, \
                        patch.object(archive.Client, 'submit') as submit, \
                        patch.object(archive.Client, 'capacity', return_value=3), \
                        patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                        patch.object(archive.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                        patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--max-seconds', '60']):
                    self.assertEqual(archive.main(), 0)
                lookup.assert_called_once_with(raw)
                submit.assert_not_called()
                self.assertEqual(archive.load_records(Path(directory))[raw]['status'], 'queued')

    def test_pending_work_is_paced_and_cannot_exceed_submission_limit(self):
        clock, submitted, checked = [100.0], [], []
        targets = {URL + str(i): {**self.target, 'original': URL + str(i)} for i in range(50)}
        rows = {k: {**t, 'lookup_required': True} for k, t in targets.items()}
        def process(key, target, state, client, **kwargs):
            checked.append(clock[0])
            state[key] = {**target, 'status': 'not-found'}
            if kwargs['allow_submit']:
                clock[0] += max(0, client.interval - (clock[0] - client.last_submit))
                client.last_submit = clock[0]
                submitted.append(clock[0])
        with tempfile.TemporaryDirectory() as directory:
            archive.save_records(rows, set(rows), Path(directory))
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(archive.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--limit', '2', '--max-seconds', '120']):
                self.assertEqual(archive.main(), 0)
        self.assertEqual(len(submitted), 2)
        self.assertGreaterEqual(submitted[1] - submitted[0], archive.CAPTURE_INTERVAL)
        self.assertLessEqual(len(checked), 120 / archive.PENDING_INTERVAL)
        self.assertTrue(all(b - a >= archive.PENDING_INTERVAL for a, b in zip(checked, checked[1:])))

    def test_lookup_verifies_raw_backlog_before_discovering_more_pages(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        targets = {URL: self.target, raw: {**self.target, 'original': raw, 'parent': URL}}
        self.rows[raw] = {**targets[raw], 'candidate': snapshot(raw)}
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, 'verify_snapshot', return_value=True) as verify:
            archive.lookup_pages(targets, self.rows, self.client, Path(directory), 1, 10)
        verify.assert_called_once()
        self.client.lookup.assert_not_called()
        self.assertTrue(archive.valid_snapshot(self.rows[raw]))

    def test_paused_verification_backlog_does_not_grow_or_get_reprocessed(self):
        self.client.replay_retry_after = archive.after(900)
        targets = {URL: self.target, URL + '-new': {**self.target, 'original': URL + '-new'}}
        self.rows[URL] = {**self.target, 'candidate': snapshot()}
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, 'verify_snapshot') as verify:
            archive.lookup_pages(targets, self.rows, self.client, Path(directory), 1, 10)
        verify.assert_not_called()
        self.client.lookup.assert_not_called()
        self.assertNotIn('checked_at', self.rows[URL])

    def test_queued_lookup_observes_rate_limit_after_waiting_for_its_slot(self):
        client = archive.Client()
        opener = MagicMock()
        opener.open.side_effect = HTTPError(archive.AVAILABILITY, 429, 'rate limit', {'Retry-After': '600'}, None)
        with patch.object(archive.request, 'build_opener', return_value=opener), patch.object(archive.time, 'sleep'):
            with self.assertRaisesRegex(archive.ArchiveError, 'http-429'):
                client.lookup(URL)
            self.assertGreater(client.lookup_retry_after, archive.after(590))
            client.lookup_retry_after = ''
            def block_during_wait(seconds):
                client.lookup_retry_after = archive.after(600)
            with patch.object(archive.time, 'sleep', side_effect=block_during_wait):
                with self.assertRaisesRegex(archive.ArchiveError, 'lookup-cooldown'):
                    client.lookup(URL + '-second')
        opener.open.assert_called_once()

    def test_queued_replay_observes_cooldown_without_consuming_a_verification_attempt(self):
        client = archive.Client()
        row = {**self.target, 'candidate': snapshot()}
        def block_during_wait(seconds):
            client.replay_retry_after = archive.after(600)
        with patch.object(archive.time, 'sleep', side_effect=block_during_wait), \
                patch.object(archive.request, 'build_opener') as opener:
            archive.verify_candidate(row, client)
        opener.assert_not_called()
        self.assertIn('candidate', row)
        self.assertEqual(row['verify_attempts'], 0)
        self.assertEqual(row['next_check_at'], client.replay_retry_after)

    def test_capture_loop_does_not_rewrite_paused_replay_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            rows = {URL: {**self.target, 'candidate': snapshot(), 'next_check_at': ''}}
            archive.save_records(rows, set(rows), path)
            (path / 'replay-control.json').write_text(json.dumps({'retry_after': archive.after(600)}))
            with patch.object(archive, 'inventory', return_value={URL: self.target}), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive, 'process') as process, \
                    patch.object(archive.Client, 'capacity') as capacity, \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--max-seconds', '60']):
                self.assertEqual(archive.main(), 0)
            process.assert_not_called()
            capacity.assert_not_called()
            self.assertEqual(rows, archive.load_records(path))

    def test_source_captures_use_http_without_browser_behaviors(self):
        client = archive.Client('dummy', 'dummy')
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        with patch.object(client, 'json', return_value={'job_id': '1'}) as send:
            client.submit(raw)
        payload = send.call_args.args[1]
        self.assertEqual(payload['force_get'], '1')
        self.assertEqual(payload['js_behavior_timeout'], '0')
        self.assertEqual(payload['if_not_archived_within'], '36500d')

    def test_file_backfill_gets_most_slots_without_starving_old_or_recent_pages(self):
        targets = {f'file-{i}': {**self.target, 'parent': f'repo-{i}'} for i in range(200)}
        targets.update({f'page-{i}': {**self.target, 'priority': f'2026-{i:04}'} for i in range(200)})
        selected = archive.select_targets(targets, {}, capture=True)
        self.assertEqual(sum(bool(targets[k].get('parent')) for k in selected[:100]), 80)
        self.assertIn('page-0', selected[:10])
        self.assertIn('page-199', selected[:10])
        self.assertEqual(len(selected), len(targets))

    def test_verified_immutable_files_do_not_consume_recapture_slots(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        target = {**self.target, 'original': raw, 'parent': URL}
        rows = {raw: {**target, 'snapshot': snapshot(raw), 'next_check_at': archive.after(-1)}}
        self.assertEqual(archive.select_targets({raw: target, URL: self.target}, rows, capture=True), [URL])
        self.assertIn(raw, archive.select_targets({raw: target}, rows))

    def test_file_queue_balances_recent_and_old_repos_and_preserves_path_rank(self):
        targets = {
            'a-readme': {**self.target, 'parent': 'old', 'priority': '2026-01', 'rank': 1},
            'b-poc': {**self.target, 'parent': 'old', 'priority': '2026-01', 'rank': 0},
            'c-poc': {**self.target, 'parent': 'new', 'priority': '2026-10', 'rank': 0},
        }
        self.assertEqual(archive.select_targets(targets, {}, capture=True), ['c-poc', 'b-poc', 'a-readme'])

    def test_short_cooldown_resumes_within_the_same_batch(self):
        clock, visited = [0.0], []
        base = datetime.now(timezone.utc).replace(microsecond=0)
        def process(key, target, rows, client, **kwargs):
            visited.append(clock[0])
            rows[key] = {**target, 'status': 'not-found'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'control.json').write_text(json.dumps({'retry_after': (base + timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%SZ')}))
            with patch.object(archive, 'inventory', return_value={URL: self.target}), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(archive, 'now', side_effect=lambda: (base + timedelta(seconds=clock[0])).strftime('%Y-%m-%dT%H:%M:%SZ')), \
                    patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(archive.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1', '--max-seconds', '20']):
                self.assertEqual(archive.main(), 0)
            self.assertEqual(visited, [5])

    def test_batch_stops_submitting_while_pending_jobs_drain(self):
        clock, visited = [0.0], []
        def process(key, target, rows, client, *, allow_submit, **kwargs):
            visited.append((key, allow_submit))
            if len(visited) == 1:
                rows[key] = {**target, 'job_id': 'job-1', 'submitted_at': archive.now(), 'status': 'pending'}
                clock[0] = 15
            else:
                rows[key] = {**target, 'status': 'available', 'snapshot': snapshot(target['original'])}
        with tempfile.TemporaryDirectory() as directory:
            targets = {k: {**self.target, 'original': k} for k in (URL, URL + '-other')}
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', directory, '--max-seconds', '20']):
                self.assertEqual(archive.main(), 0)
        self.assertEqual(len(visited), 2)
        self.assertEqual(visited[0], (visited[1][0], True))
        self.assertFalse(visited[1][1])

    def test_replay_backoff_keeps_completed_jobs_without_blocking_new_files(self):
        self.client.replay_retry_after = archive.after(900)
        self.rows[URL] = {**self.target, 'job_id': 'job-1', 'submitted_at': archive.now()}
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot') as verify:
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        verify.assert_not_called()
        self.assertIn('candidate', self.rows[URL])
        self.assertNotIn('job_id', self.rows[URL])
        self.assertFalse(archive.valid_snapshot(self.rows[URL]))
        target = {**self.target, 'original': URL + '-file', 'parent': URL}
        archive.process(target['original'], target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once_with(target['original'], retry=False)

    def test_failures_on_independent_endpoints_do_not_trip_capture_breaker(self):
        client = archive.Client()
        for i in range(4):
            client.operation = 'replay'
            client.failure(str(i), archive.ArchiveError('replay-URLError'))
        client.operation = 'capture'
        self.assertEqual(client.failure('new', archive.ArchiveError('transport-TimeoutError')).cooldown, 0)

    def test_lookup_respects_capture_throttle_before_replaying_candidates(self):
        client = archive.Client()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            retry = archive.after(600)
            (path / 'control.json').write_text(json.dumps({'retry_after': retry, 'reason': 'http-429'}))
            with patch.object(client, 'lookup', return_value=snapshot()), patch.object(archive, 'verify_snapshot') as verify:
                archive.lookup_pages({URL: self.target}, self.rows, client, path, 1, 10)
            verify.assert_not_called()
            row = archive.load_records(path)[URL]
            self.assertIn('candidate', row)
            self.assertEqual(row['next_check_at'], retry)
            self.assertFalse(archive.valid_snapshot(row))

    def test_throttling_slows_submissions_across_restarts(self):
        intervals = []
        def process(key, target, rows, client, *, capture, directory=None, allow_submit=True):
            rows[key] = {**target, 'status': 'retry'}
            client.operation = 'capture'
            intervals.append(client.interval)
            raise archive.ArchiveError('http-429', cooldown=600)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            control = path / 'control.json'
            control.write_text(json.dumps({'retry_after': archive.after(-1), 'reason': 'http-429', 'capture_interval': 30}))
            with patch.object(archive, 'inventory', return_value={URL: self.target}), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3) as capacity, \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1', '--max-seconds', '2']):
                self.assertEqual(archive.main(), 0)
                state = json.loads(control.read_text())
                self.assertEqual(intervals, [30])
                self.assertEqual(state['capture_interval'], 60)
                self.assertGreater(state['retry_after'], archive.after(590))
                capacity.reset_mock()
                self.assertEqual(archive.main(), 0)
                capacity.assert_not_called()

    def test_newer_negative_checkpoint_cannot_discard_a_verified_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'source', Path(directory) / 'destination'
            archive.save_records({URL: {**self.target, 'snapshot': snapshot(), 'checked_at': '2026-10-21T10:00:00Z'}}, {URL}, source)
            archive.save_records({URL: {**self.target, 'status': 'retry', 'checked_at': '2026-10-21T11:00:00Z'}}, {URL}, destination)
            with patch.object(sys, 'argv', ['archive_pocs', '--directory', str(destination), '--merge-from', str(source)]):
                archive.main()
            self.assertTrue(archive.valid_snapshot(archive.load_records(destination)[URL]))

    def test_checkpoint_merge_keeps_slower_pacing_with_equal_cooldowns(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'source', Path(directory) / 'destination'
            source.mkdir()
            destination.mkdir()
            state = {'retry_after': archive.after(300), 'reason': 'http-429'}
            (source / 'control.json').write_text(json.dumps({**state, 'capture_interval': 60}))
            (destination / 'control.json').write_text(json.dumps({**state, 'capture_interval': 30}))
            with patch.object(sys, 'argv', ['archive_pocs', '--directory', str(destination), '--merge-from', str(source)]):
                archive.main()
            self.assertEqual(json.loads((destination / 'control.json').read_text())['capture_interval'], 60)

    def test_checkpoint_merge_keeps_newer_healthy_pacing(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'source', Path(directory) / 'destination'
            source.mkdir()
            destination.mkdir()
            state = {'retry_after': archive.after(300), 'reason': 'http-429'}
            (source / 'control.json').write_text(json.dumps({**state, 'capture_interval': 45, 'pacing_updated_at': '2026-10-22T00:00:00Z'}))
            (destination / 'control.json').write_text(json.dumps({**state, 'capture_interval': 60, 'pacing_updated_at': '2026-10-21T00:00:00Z'}))
            with patch.object(sys, 'argv', ['archive_pocs', '--directory', str(destination), '--merge-from', str(source)]):
                archive.main()
            merged = json.loads((destination / 'control.json').read_text())
            self.assertEqual(merged['capture_interval'], 45)
            self.assertEqual(merged['retry_after'], state['retry_after'])

    def test_healthy_captures_gradually_restore_pacing_without_reusing_credit(self):
        intervals = []
        def process(key, target, rows, client, **kwargs):
            intervals.append(client.interval)
            rows[key] = {**target, 'status': 'not-found'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            rows = {URL + str(i): {**self.target, 'original': URL + str(i), 'parent': URL,
                                   'submitted_at': archive.after(-300), 'status': 'available', 'snapshot': snapshot(URL + str(i))}
                    for i in range(10)}
            archive.save_records(rows, set(rows), path)
            control = path / 'control.json'
            control.write_text(json.dumps({'retry_after': archive.after(-600), 'reason': 'http-429', 'capture_interval': 60}))
            with patch.object(archive, 'inventory', return_value={URL: self.target}), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=3), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1', '--max-seconds', '20']):
                archive.main()
                archive.main()
            self.assertEqual(intervals, [45, 45])
            self.assertEqual(json.loads(control.read_text())['capture_interval'], 45)

    def test_lookup_cooldown_does_not_block_pinned_source_submissions(self):
        self.client.lookup_retry_after = archive.after(300)
        target = {**self.target, 'parent': URL + '/parent'}
        archive.process(URL, target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.client.lookup.assert_not_called()

    def test_replay_redirect_to_another_original_is_not_a_snapshot_of_this_poc(self):
        snap = snapshot()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.url = snap['url'].replace(snap['timestamp'] + '/', snap['timestamp'] + 'id_/') + '-other'
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(archive.request, 'build_opener', return_value=opener):
            self.assertFalse(archive.verify_snapshot(snap, URL))

    def test_looked_up_new_page_and_small_repositories_keep_capture_slots(self):
        targets = {f'file-{i}': {**self.target, 'parent': 'large'} for i in range(70)}
        targets['small'] = {**self.target, 'parent': 'small-repo'}
        targets[URL] = self.target
        targets['old'] = {**self.target, 'priority': ''}
        rows = {URL: {**self.target, 'checked_at': archive.now(), 'lookup_checked_at': archive.now()}}
        selected = archive.select_targets(targets, rows, capture=True)
        self.assertIn(URL, selected[:4])
        self.assertIn('small', selected[:4])

    def test_repeated_transport_errors_trip_a_service_breaker(self):
        client = archive.Client()
        for i in range(5):
            with patch.object(archive.time, 'monotonic', return_value=i * 90):
                result = client.failure(str(i % 3), archive.ArchiveError('transport-ConnectionResetError'))
            self.assertEqual(result.cooldown, 900 if i == 4 else 0)
        client.responded()
        self.assertEqual(client.failure('new', archive.ArchiveError('transport-TimeoutError')).cooldown, 0)

    def test_host_daily_capture_limit_is_shared_with_other_urls(self):
        row = {}
        archive.capture_failure(row, 'error:too-many-daily-captures-host')
        self.assertGreaterEqual(row['host_retry_after'], archive.after(86390))

    def test_successful_status_polls_do_not_clear_submission_failures(self):
        client = archive.Client()
        for i in range(5):
            client.operation = 'capture'
            result = client.failure(str(i), archive.ArchiveError('transport-ConnectionRefusedError'))
            self.assertEqual(result.cooldown, 900 if i == 4 else 0)
            client.operation = 'capture-status'
            client.responded()

    def test_replay_connection_failures_are_not_treated_as_http_responses(self):
        client = archive.Client()
        client.operation = 'replay'
        for i in range(5):
            result = client.failure(str(i), archive.ArchiveError('replay-RemoteDisconnected'))
        self.assertEqual(result.cooldown, 900)

    def test_availability_breaker_does_not_pause_capture_api(self):
        for operation in ('availability', 'replay'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                self.client.lookup_retry_after = ''
                self.client.replay_retry_after = ''
                self.client.operation = operation
                self.client.lookup.side_effect = archive.ArchiveError('service-transport-failures', cooldown=900)
                archive.lookup_pages({URL: self.target}, {}, self.client, Path(directory), 1, 10)
                self.assertEqual((Path(directory) / 'lookup-control.json').exists(), operation == 'availability')
                self.assertFalse((Path(directory) / 'control.json').exists())
                self.assertEqual((Path(directory) / 'replay-control.json').exists(), operation == 'replay')

    def test_capture_limit_exits_without_waiting_for_an_unrelated_host_cooldown(self):
        blocked = 'https://example.com/poc'
        targets = {u: {**self.target, 'original': u} for u in (URL, URL + '-other', blocked)}
        def process(key, target, rows, client, *, capture, directory=None, allow_submit=True):
            rows[key] = {**target, 'status': 'not-found'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            archive.save_records({blocked: {**targets[blocked], 'host_retry_after': archive.after(86400)}}, {blocked}, path)
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=2), \
                    patch.object(archive, 'process', side_effect=process) as visit, \
                    patch.object(archive.time, 'sleep', side_effect=AssertionError('Unexpected idle wait')), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1']):
                self.assertEqual(archive.main(), 0)
                self.assertEqual(visit.call_count, 1)

    def test_capture_loop_serves_new_targets_and_keeps_candidate_backoff(self):
        pending = URL + '-pending'
        target = {**self.target, 'original': pending}
        visited = []
        def process(key, target, rows, client, *, capture, directory=None, allow_submit=True):
            visited.append(key)
            if key == pending:
                rows[key]['next_check_at'] = archive.after(3600)
                raise archive.ArchiveError('replay-URLError')
            rows[key] = {**target, 'status': 'not-found'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            archive.save_records({pending: {**target, 'candidate': snapshot(pending), 'next_check_at': ''}}, {pending}, path)
            with patch.object(archive, 'inventory', return_value={URL: self.target, pending: target}), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=2), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1', '--max-seconds', '2']):
                self.assertEqual(archive.main(), 0)
            saved = archive.load_records(path)[pending]
        self.assertEqual(visited, [URL, pending])
        self.assertGreater(saved['next_check_at'], archive.after(3500))

    def test_shared_file_is_published_under_each_allowed_parent(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        other = URL + '/blob/main/poc.py'
        rows = {raw: {'original': raw, 'snapshot': snapshot(raw), 'parent': URL,
                      'parents': {URL: URL, other: other}}}
        published = archive.published_snapshots(rows, allowed={URL, other}, manifests={})
        self.assertEqual(published[URL]['files'], published[other]['files'])

    def test_reviewed_manifest_hides_unrelated_files_without_erasing_historical_captures(self):
        from archive_sources import SCAN_VERSION
        base = 'https://raw.githubusercontent.com/owner/poc/'
        poc, library, historical = [base + revision * 40 + '/' + path
                                    for revision, path in [('a', 'poc.py'), ('a', 'lib.py'), ('b', 'old-poc.py')]]
        rows = {key: {'original': key, 'snapshot': snapshot(key), 'parent': URL} for key in (poc, library, historical)}
        manifest = {URL: {'complete': True, 'scan_version': SCAN_VERSION, 'revision': 'a' * 40,
                          'files': [{'path': 'poc.py'}]}}
        published = archive.published_snapshots(rows, allowed={URL}, manifests=manifest)
        self.assertEqual({r['original'] for r in published[URL]['files']}, {poc, historical})
        self.assertNotIn(library, published)
        self.assertTrue(archive.valid_snapshot(rows[library]))

    def test_rejected_unchanged_blob_at_older_revision_stays_hidden(self):
        from archive_sources import SCAN_VERSION
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'b' * 40 + '/lib.py'
        rows = {raw: {'original': raw, 'parent': URL, 'expected_blobs': ['c' * 40], 'snapshot': snapshot(raw)}}
        manifests = {URL: {'complete': True, 'scan_version': SCAN_VERSION, 'revision': 'a' * 40,
                           'files': [{'path': 'poc.py', 'oid': 'd' * 40}],
                           'checked_oids': {'lib.py': 'c' * 40, 'poc.py': 'd' * 40}}}
        self.assertEqual(archive.published_snapshots(rows, {URL}, manifests=manifests), {})

    def test_large_legacy_manifest_waits_for_rescan_before_queuing_files(self):
        from archive_sources import SCAN_VERSION
        manifest = {URL: {'scan_version': SCAN_VERSION - 1, 'candidate_files': 101, 'repository': 'owner/poc',
                          'revision': 'a' * 40, 'files': [{'path': 'library.py', 'oid': 'b' * 40}]}}
        with patch.object(archive, 'eligible_ledger', return_value=[{'url': URL, 'cve': CVE}]), \
                patch.object(archive, 'load_source_manifests', return_value=manifest):
            self.assertEqual(set(archive.inventory()), {URL})

    def test_completed_capture_verification_is_not_starved_by_new_jobs(self):
        saved, active = URL + '-saved', URL + '-active'
        targets = {key: {**self.target, 'original': key} for key in (URL, saved, active)}
        rows = {saved: {**targets[saved], 'candidate': snapshot(saved), 'next_check_at': archive.after(-3600)},
                active: {**targets[active], 'job_id': 'job-1', 'submitted_at': archive.now(), 'next_check_at': archive.after(-10)}}
        for slots in (3, 0):
            visited, clock = [], [100.0]
            def process(key, target, state, client, **kwargs):
                visited.append(key)
                clock[0] += 30
                state[key] = {**target, 'status': 'available', 'next_check_at': archive.after(3600)}
            with self.subTest(slots=slots), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                archive.save_records(rows, set(rows), path)
                with patch.object(archive, 'inventory', return_value=targets), \
                        patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                        patch.object(archive.Client, 'capacity', side_effect=lambda: slots if not visited else 3), \
                        patch.object(archive, 'process', side_effect=process), \
                        patch.object(archive.time, 'monotonic', side_effect=lambda: clock[0]), \
                        patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1', '--max-seconds', '120']):
                    self.assertEqual(archive.main(), 0)
            self.assertEqual(visited[0], active)
            self.assertIn(saved, visited)

    def test_replay_rejects_login_shells_errors_and_external_redirects(self):
        snap = snapshot()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.url = snap['url'].replace(snap['timestamp'] + '/', snap['timestamp'] + 'id_/')
        response.headers = {'Content-Type': 'text/html'}
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(archive.request, 'build_opener', return_value=opener):
            for body in (b'', b'<title>404 Not Found</title>', b'<title>Sign in to GitHub</title>'):
                response.read.return_value = body
                self.assertFalse(archive.verify_snapshot(copy.deepcopy(snap), URL))
                self.assertFalse(archive.verify_snapshot(copy.deepcopy(snap), 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'))
            response.read.return_value = b'<title>PoC for CVE-2026-4044</title><article>research</article>'
            self.assertTrue(archive.verify_snapshot(snap, URL))
            self.assertFalse(archive.verify_snapshot(snap, 'https://hackerone.com/reports/1234'))
        redirect = archive.ReplayRedirect()
        self.assertIsNone(redirect.redirect_request(None, None, 302, '', {}, 'http://127.0.0.1/private'))
        self.assertIsNone(archive.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://archive.org/'))

    def test_gzip_replay_is_decoded_before_content_and_hash_validation(self):
        response = io.BytesIO(gzip.compress(b'<title>Sign in to GitHub</title>'))
        response.headers = {'Content-Encoding': 'gzip'}
        self.assertEqual(archive.response_bytes(response, 1000), b'<title>Sign in to GitHub</title>')
        response = io.BytesIO(gzip.compress(b'x' * 1001))
        response.headers = {'Content-Encoding': 'gzip'}
        with self.assertRaisesRegex(archive.ArchiveError, 'too-large'):
            archive.response_bytes(response, 1000)

    def test_corrupt_compressed_responses_are_target_errors(self):
        for body in (b'not-gzip', gzip.compress(b'poc')[:-8], b'\x1f\x8b\x08\x00' + b'\x00' * 6 + b'\x07'):
            with self.subTest(body=body):
                response = io.BytesIO(body)
                response.headers = {'Content-Encoding': 'gzip'}
                with self.assertRaisesRegex(archive.ArchiveError, 'invalid-compressed-response'):
                    archive.response_bytes(response, 1000)

    def test_corrupt_replay_is_replaced_instead_of_reusing_the_failed_capture(self):
        snap = snapshot()
        response = io.BytesIO(gzip.compress(b'poc')[:-8])
        response.headers = {'Content-Encoding': 'gzip'}
        response.status = 200
        response.url = snap['url'].replace(snap['timestamp'] + '/', snap['timestamp'] + 'id_/')
        opener = MagicMock()
        opener.open.return_value = response
        row = {**self.target, 'candidate': snap}
        with patch.object(archive.request, 'build_opener', return_value=opener):
            archive.verify_candidate(row)
        self.assertTrue(row['bad_capture'])
        self.assertNotIn('candidate', row)
        self.assertFalse(archive.valid_snapshot(row))


if __name__ == '__main__':
    unittest.main()
