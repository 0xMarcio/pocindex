from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_cves


class DiscoveryStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name, path in {
            "CVES": self.root / "cves", "STATE_FILE": self.root / "delta.json",
            "DISCOVERY_STATE_FILE": self.root / "discovery.json",
        }.items():
            self.stack.enter_context(patch.object(update_cves, name, path, create=True))

    def main(self, **options):
        args = dict(backfill_dir=None, year=None, lookback_days=3, years=2, all_years=False,
                    cve=[], skip_github=False, skip_cvelist=True, dry_run=False,
                    cvelist_dir=None, refresh_headers=False)
        args.update(options)
        self.stack.enter_context(patch.object(update_cves, "parse_args", return_value=argparse.Namespace(**args)))
        for name, value in {"reconcile_inventory": (0, 0), "append_inventory": 0,
                            "refresh_record_headers": 0, "record_dates": 0}.items():
            self.stack.enter_context(patch.object(update_cves, name, return_value=value))
        return update_cves.main()

    def test_backfill_does_not_advance_global_delta(self):
        update_cves.STATE_FILE.write_text('{"cvelist_fetch_time":"2026-09-01"}')
        with patch.object(update_cves, "load_backfill_records", return_value=({}, {}, {})), \
                patch.object(update_cves, "newest_delta_time", return_value="2026-10-06"):
            self.main(backfill_dir=self.root, year=2010, skip_cvelist=False, skip_github=True)
        self.assertEqual(json.loads(update_cves.STATE_FILE.read_text())["cvelist_fetch_time"], "2026-09-01")

    def test_filtered_run_does_not_advance_global_delta(self):
        with patch.object(update_cves, "load_incremental_records", return_value=({}, {}, "2026-10-06")):
            self.main(cve=["CVE-2026-1234"], skip_cvelist=False, skip_github=True)
        self.assertFalse(update_cves.STATE_FILE.exists())

    def test_outage_search_resumes_each_year_with_overlap(self):
        windows = []
        def search(client, terms, qualifier, start, end):
            windows.append((terms, qualifier, start, end))
            return []
        with patch.object(update_cves, "search_range", side_effect=search):
            update_cves.discover_github_pocs("token", years=[2026, 2025], lookback_days=3,
                backfill=False, cve_filter=set(), window_end=date(2026, 10, 6),
                checkpoints={"2026": "2026-09-01", "2025": "2026-10-05"})
        self.assertEqual({start for terms, _, start, _ in windows if "2026" in terms}, {date(2026, 8, 29)})
        self.assertEqual({start for terms, _, start, _ in windows if "2025" in terms}, {date(2026, 10, 2)})
        self.assertEqual({end for _, _, _, end in windows}, {date(2026, 10, 6)})

    def test_transient_metadata_failure_is_not_not_found(self):
        with patch.object(update_cves, "http_json", side_effect=TimeoutError("API unavailable")):
            with self.assertRaisesRegex(RuntimeError, "API unavailable"):
                update_cves.fetch_missing_records(["CVE-2026-1234"], {})

    def test_not_found_and_rejected_records_are_not_transient_failures(self):
        cve = "CVE-2026-1234"
        for payload in [None, {"cveMetadata": {"cveId": cve, "state": "REJECTED"}}]:
            with self.subTest(payload=payload), patch.object(update_cves, "http_json", return_value=payload):
                records = {}
                update_cves.fetch_missing_records([cve], records)
                self.assertEqual(records, {cve: payload} if payload else {})

    def test_malformed_metadata_and_partial_search_fail(self):
        with patch.object(update_cves, "http_json", return_value={"message": "try again"}):
            with self.assertRaises(RuntimeError):
                update_cves.fetch_missing_records(["CVE-2026-1234"], {})
        payload = {"data": {"search": {"repositoryCount": 1, "nodes": []}, "rateLimit": {"remaining": 100}}}
        with patch.object(update_cves, "http_json", return_value=payload):
            with self.assertRaises(RuntimeError):
                update_cves.GitHubClient("token").search_page("query")

    def test_checkpoint_commits_after_ingestion_only(self):
        with patch.object(update_cves, "discover_github_pocs", return_value={}) as discover:
            self.main()
        state = json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())
        end = discover.call_args.kwargs["window_end"].isoformat()
        self.assertEqual(state["years"], {str(year): end for year in discover.call_args.kwargs["years"]})

    def test_failed_ingestion_dry_run_and_filtered_run_preserve_checkpoint(self):
        original = '{"years":{"2025":"2026-09-01"},"pending":{}}'
        update_cves.DISCOVERY_STATE_FILE.write_text(original)
        for options, failure in [({}, True), ({"dry_run": True}, False), ({"cve": ["CVE-2026-1234"]}, False)]:
            with self.subTest(options=options), patch.object(update_cves, "discover_github_pocs", return_value={}), \
                    patch.object(update_cves, "sync_markdown", side_effect=RuntimeError("write failed") if failure else None,
                                 return_value=(update_cves.SyncStats(), {}, {})):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, "write failed"):
                        self.main(**options)
                else:
                    self.main(**options)
                self.assertEqual(update_cves.DISCOVERY_STATE_FILE.read_text(), original)

    def test_missing_search_results_abort_before_checkpoint(self):
        client = update_cves.GitHubClient("token")
        with patch.object(client, "search_page", return_value={
            "repositoryCount": 2, "nodes": [{"nameWithOwner": "owner/poc"}],
            "pageInfo": {"hasNextPage": False},
        }):
            with self.assertRaisesRegex(RuntimeError, "only 1 of 2"):
                list(update_cves.search_range(client, "CVE", "pushed", date(2026, 9, 1), date(2026, 10, 6)))

    def test_reserved_candidate_waits_until_due_and_rejection_clears_it(self):
        cve = "CVE-2026-1234"
        link = "https://github.com/example/CVE-2026-1234"
        record = {"cveMetadata": {"cveId": cve, "state": "RESERVED"}}
        with patch.object(update_cves, "discover_github_pocs", return_value={cve: [link]}), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "http_json") as fetch:
            self.main()
            fetch.assert_not_called()
        state = json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())
        self.assertEqual(state["pending"][cve]["status"], "RESERVED")
        state["pending"][cve]["checked"] = "2020-01-01"
        update_cves.DISCOVERY_STATE_FILE.write_text(json.dumps(state))
        record["cveMetadata"]["state"] = "REJECTED"
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"], {})
        self.assertFalse((update_cves.CVES / "2026" / f"{cve}.md").exists())

    def test_unpublished_links_retry_after_checkpoint_has_advanced(self):
        cve = "CVE-2026-1234"
        link = "https://github.com/example/CVE-2026-1234"
        with patch.object(update_cves, "discover_github_pocs", return_value={cve: [link]}), \
                patch.object(update_cves, "http_json", return_value=None):
            self.main()
        state = json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())
        self.assertEqual(state["pending"][cve]["github"], [link])
        state["pending"][cve]["checked"] = "2020-01-01"
        update_cves.DISCOVERY_STATE_FILE.write_text(json.dumps(state))
        record = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
                  "containers": {"cna": {"descriptions": [{"lang": "en", "value": "A vulnerability"}]}}}
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        self.assertIn(link, (update_cves.CVES / "2026" / f"{cve}.md").read_text())
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"], {})

    def test_local_backfill_uses_the_workflow_utc_retry_day(self):
        record_state = self.root / "records.json"
        with patch.object(update_cves, "RECORD_STATE_FILE", record_state), \
                patch.object(update_cves, "load_record_state", return_value={}), \
                patch.object(update_cves, "http_json", return_value=None), \
                patch.object(update_cves, "record_dates", return_value=0), \
                patch.object(update_cves, "date", wraps=date) as local_date, \
                patch.object(update_cves, "datetime", wraps=datetime) as utc_clock:
            local_date.today.return_value = date(2026, 10, 7)
            utc_clock.now.return_value = datetime(2026, 10, 6, 22, 15, tzinfo=timezone.utc)
            update_cves.ensure_cve_entries(["CVE-2026-1234"], dry_run=False)
        self.assertEqual(json.loads(record_state.read_text())["CVE-2026-1234"]["checked"], "2026-10-06")


if __name__ == "__main__":
    unittest.main()
