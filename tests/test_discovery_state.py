from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_cves
import build_site


class DiscoveryStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name, path in {
            "CVES": self.root / "cves", "INDEX": self.root / "index", "STATE_FILE": self.root / "delta.json",
            "DISCOVERY_STATE_FILE": self.root / "discovery.json",
            "RECORD_STATE_FILE": self.root / "records.json", "DATES_FILE": self.root / "dates.json",
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
        with patch.object(update_cves, "search_range", side_effect=search), \
                patch.object(update_cves.source_artifacts, "pending_reviewed_names", return_value=[]):
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

    def test_missing_record_uses_real_identifier_status(self):
        cve = "CVE-2026-104100"
        for status in ("RESERVED", "REJECTED"):
            with self.subTest(status=status), patch.object(update_cves, "http_json", side_effect=[
                None, {"cve_id": cve, "state": status},
            ]):
                records = {}
                created, unavailable = update_cves.ensure_cve_entries([cve], dry_run=False, records=records)
            self.assertEqual(records[cve]["cveMetadata"]["state"], status)
            path = update_cves.CVES / "2026" / f"{cve}.md"
            self.assertEqual(update_cves.markdown_record_status(path.read_text()), status)
            self.assertEqual(unavailable, {cve} if status == "REJECTED" else set())
            update_cves.RECORD_STATE_FILE.unlink()

    def test_unallocated_id_is_queued_without_page_and_retried_daily(self):
        cve = "CVE-2025-4162026"
        missing = HTTPError("url", 404, "not found", {}, io.BytesIO(b'{"error":"CVE_ID_NOT_FOUND"}'))
        with patch.object(update_cves, "http_json", side_effect=[None, missing]):
            created, unavailable = update_cves.ensure_cve_entries([cve], dry_run=False)
        self.assertEqual(created, set())
        self.assertEqual(unavailable, {cve})
        self.assertFalse((update_cves.CVES / "2025" / f"{cve}.md").exists())
        self.assertEqual(update_cves.load_record_state()[cve]["status"], "ABSENT")
        now = datetime(2026, 10, 21, 15, tzinfo=timezone.utc)
        self.assertFalse(update_cves.retry_record({"status": "ABSENT", "checked": "2026-10-21T12:00:00Z"}, now))
        self.assertTrue(update_cves.retry_record({"status": "ABSENT", "checked": "2026-10-20T12:00:00Z"}, now))

    def test_status_service_outage_still_publishes_source_links(self):
        cve = "CVE-2026-104100"
        with patch.object(update_cves, "http_json", side_effect=[None, TimeoutError("status outage")]):
            created, unavailable = update_cves.ensure_cve_entries([cve], dry_run=False)
        self.assertEqual(created, {cve})
        self.assertEqual(unavailable, set())

    def test_unfetched_provisional_metadata_is_due_immediately(self):
        cve = "CVE-2026-104100"
        update_cves.ensure_cve_entries([cve], dry_run=False, fetch_missing=False)
        self.assertTrue(update_cves.retry_record(update_cves.load_record_state()[cve], datetime.now(timezone.utc)))

    def test_invalid_zero_padded_identifiers_are_not_cves(self):
        self.assertFalse(update_cves.is_valid_cve("CVE-2026-01234"))
        self.assertTrue(update_cves.is_valid_cve("CVE-2026-0123"))

    def test_hourly_metadata_enrichment_imports_new_cna_poc_references(self):
        cve = "CVE-2026-104100"
        url = "https://github.com/researcher/widget-poc"
        record = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"}, "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": "Official details"}],
            "references": [{"url": url, "tags": ["exploit"]}],
        }}}
        update_cves.ensure_cve_entries([cve], dry_run=False, fetch_missing=False)
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "reference_url_is_live", return_value=True), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        text = (update_cves.CVES / "2026" / f"{cve}.md").read_text()
        self.assertIn(url, update_cves.section_links(text, "#### Reference"))
        self.assertNotIn("### Description\n\n\n", text)

    def test_metadata_enrichment_does_not_restore_dead_delta_references(self):
        cve = "CVE-2026-104100"
        url = "https://github.com/researcher/removed-poc"
        record = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"}, "containers": {"cna": {
            "references": [{"url": url, "tags": ["exploit"]}],
        }}}
        with patch.object(update_cves, "load_incremental_records", return_value=({cve: record}, {cve: [url]}, "t")), \
                patch.object(update_cves, "reference_url_is_live", return_value=False) as check:
            self.main(skip_cvelist=False, skip_github=True)
        check.assert_called_once_with(url)
        self.assertFalse((update_cves.CVES / "2026" / f"{cve}.md").exists())

    def test_hourly_enrichment_checks_new_references_before_publication(self):
        cve = "CVE-2026-104100"
        url = "https://github.com/researcher/removed-poc"
        record = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"}, "containers": {"cna": {
            "references": [{"url": url, "tags": ["exploit"]}],
        }}}
        update_cves.ensure_cve_entries([cve], dry_run=False, fetch_missing=False)
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "reference_url_is_live", return_value=False), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        text = (update_cves.CVES / "2026" / f"{cve}.md").read_text()
        self.assertNotIn(url, update_cves.section_links(text, "#### Reference"))

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
        def complete(*args, **kwargs):
            kwargs["completed_years"].update(kwargs["years"])
            return {}
        with patch.object(update_cves, "discover_github_pocs", side_effect=complete) as discover:
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

    def test_reserved_candidate_is_visible_before_enrichment_and_rejection_withdraws_it(self):
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
        path = update_cves.CVES / "2026" / f"{cve}.md"
        self.assertIn(link, path.read_text())
        self.assertIn(update_cves.PENDING_DESCRIPTION, path.read_text())
        records = json.loads(update_cves.RECORD_STATE_FILE.read_text())
        records[cve]["checked"] = "2020-01-01"
        update_cves.RECORD_STATE_FILE.write_text(json.dumps(records))
        record["cveMetadata"]["state"] = "REJECTED"
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"], {})
        self.assertEqual(update_cves.markdown_record_status(path.read_text()), "REJECTED")
        self.assertIn(link, path.read_text())

    def test_unpublished_links_retry_after_checkpoint_has_advanced(self):
        cve = "CVE-2026-1234"
        link = "https://github.com/example/CVE-2026-1234"
        with patch.object(update_cves, "discover_github_pocs", return_value={cve: [link]}), \
                patch.object(update_cves, "http_json", return_value=None):
            self.main()
        state = json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())
        self.assertEqual(state["pending"][cve]["github"], [link])
        records = json.loads(update_cves.RECORD_STATE_FILE.read_text())
        records[cve]["checked"] = "2020-01-01"
        update_cves.RECORD_STATE_FILE.write_text(json.dumps(records))
        record = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
                  "containers": {"cna": {"descriptions": [{"lang": "en", "value": "A vulnerability"}]}}}
        with patch.object(update_cves, "discover_github_pocs", return_value={}), \
                patch.object(update_cves, "http_json", return_value=record):
            self.main()
        self.assertIn(link, (update_cves.CVES / "2026" / f"{cve}.md").read_text())
        self.assertIn("A vulnerability", (update_cves.CVES / "2026" / f"{cve}.md").read_text())
        self.assertNotIn(update_cves.PENDING_DESCRIPTION, (update_cves.CVES / "2026" / f"{cve}.md").read_text())
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"], {})

    def test_local_backfill_records_a_utc_timestamp(self):
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
        self.assertEqual(json.loads(record_state.read_text())["CVE-2026-1234"]["checked"], "2026-10-06T22:15:00+00:00")

    def test_pending_metadata_retries_within_the_same_utc_day(self):
        now = datetime(2026, 10, 21, 14, 5, tzinfo=timezone.utc)
        for checked, due in (("2026-10-21", True), ("2026-10-21T13:00:00Z", True),
                             ("2026-10-21T13:45:00+00:00", False), ("2026-10-21T15:00:00+02:00", True)):
            with self.subTest(checked=checked):
                self.assertEqual(update_cves.retry_record({"checked": checked, "status": "UNAVAILABLE"}, now), due)
        self.assertFalse(update_cves.retry_record({"status": "REJECTED"}, now))

    def test_php2shell_pending_candidates_are_published_without_github_or_nvd(self):
        ids = ["CVE-2026-109618", "CVE-2026-109619"]
        link = "https://github.com/example/php2shell-poc"
        update_cves.DISCOVERY_STATE_FILE.write_text(json.dumps({"years": {"2026": "2026-10-20"}, "pending": {
            cve: {"github": [link], "references": [], "status": "UNAVAILABLE", "checked": "2026-10-21"}
            for cve in ids
        }}))
        with patch.object(update_cves, "discover_github_pocs") as search, \
                patch.object(update_cves, "http_json", return_value=None):
            self.assertEqual(self.main(skip_github=True, pending_only=True), 0)
        search.assert_not_called()
        with patch.object(build_site, "CVES", update_cves.CVES), \
                patch.object(build_site, "load_metadata", return_value={}), \
                patch.object(build_site, "load_dates", return_value={}), \
                patch("archive_pocs.load_records", return_value={}), \
                patch.object(build_site, "load_verified_references", return_value=set()):
            entries, _ = build_site.build_cve_list(set())
        self.assertEqual({row["cve"] for row in entries}, set(ids))
        self.assertTrue(all(row["metadata_pending"] and row["poc"] == [link] for row in entries))
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["years"], {"2026": "2026-10-20"})

    def test_metadata_outage_preserves_successful_records_and_publishes_pending_links(self):
        ready, pending = "CVE-2026-109618", "CVE-2026-109619"
        record = {"cveMetadata": {"cveId": ready, "state": "PUBLISHED"},
                  "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Official details"}]}}}
        def fetch(url, **kwargs):
            if url.endswith(ready):
                return record
            raise TimeoutError("CVE service unavailable")
        with patch.object(update_cves, "discover_github_pocs", return_value={
            cve: [f"https://github.com/example/{cve}"] for cve in [ready, pending]
        }), patch.object(update_cves, "http_json", side_effect=fetch):
            self.assertEqual(self.main(), 1)
        self.assertIn("Official details", (update_cves.CVES / "2026" / f"{ready}.md").read_text())
        self.assertIn(update_cves.PENDING_DESCRIPTION, (update_cves.CVES / "2026" / f"{pending}.md").read_text())
        self.assertEqual(set(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"]), {pending})

    def test_partial_discovery_publishes_links_without_advancing_failed_year(self):
        cve = "CVE-2026-109618"
        update_cves.DISCOVERY_STATE_FILE.write_text('{"years":{"2026":"2026-10-20"},"pending":{}}')
        def discover(*args, **kwargs):
            kwargs["failures"].append("GitHub search: HTTP 502")
            kwargs["completed_years"].add(2025)
            return {cve: [f"https://github.com/example/{cve}"]}
        with patch.object(update_cves, "discover_github_pocs", side_effect=discover), \
                patch.object(update_cves, "http_json", return_value=None):
            self.assertEqual(self.main(), 1)
        state = json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())
        self.assertEqual(state["years"]["2026"], "2026-10-20")
        self.assertIn("2025", state["years"])
        self.assertIn(cve, state["pending"])
        self.assertTrue((update_cves.CVES / "2026" / f"{cve}.md").exists())

    def test_one_failed_search_does_not_discard_other_queries(self):
        cve = "CVE-2026-109618"
        name = f"example/{cve}"
        repo = {"nameWithOwner": name, "url": f"https://github.com/{name}", "description": "PoC"}
        def search(client, terms, *args):
            if '"CVE-2026" exploit' in terms:
                raise RuntimeError("HTTP 502")
            return [repo] if "2026" in terms else []
        failures, completed = [], set()
        with patch.object(update_cves, "search_range", side_effect=search), \
                patch.object(update_cves.source_artifacts, "load_reviews", return_value=[]), \
                patch.object(update_cves.source_artifacts, "pending_reviewed_names", return_value=[]), \
                patch.object(update_cves, "attach_source_artifacts"), \
                patch.object(update_cves.GitHubClient, "fetch_readmes", return_value=(
                    {name}, {name: f"Proof of concept for {cve}"}, {name: [{"name": "poc.py"}]})):
            links = update_cves.discover_github_pocs("token", years=[2026, 2025], lookback_days=1,
                backfill=False, cve_filter=set(), failures=failures, completed_years=completed)
        self.assertEqual(links, {cve: [repo["url"]]})
        self.assertEqual(completed, {2025})
        self.assertEqual(len(failures), 1)

    def test_failed_reviewed_replay_keeps_successful_search_results(self):
        cve, name = "CVE-2026-109618", "researcher/widget-poc"
        candidate = {"nameWithOwner": name, "url": f"https://github.com/{name}",
                     "description": f"PoC for {cve}"}
        failures, completed = [], set()
        with patch.object(update_cves, "search_range", return_value=[candidate]), \
                patch.object(update_cves.source_artifacts, "load_reviews", return_value=[{"cve": cve}]), \
                patch.object(update_cves.source_artifacts, "pending_reviewed_names", return_value=["other/reviewed"]), \
                patch.object(update_cves.source_artifacts, "reviewed_cves", return_value={cve}), \
                patch.object(update_cves, "http_json", side_effect=TimeoutError("replay unavailable")), \
                patch.object(update_cves, "attach_source_artifacts"), \
                patch.object(update_cves.GitHubClient, "fetch_readmes", return_value=(
                    {name}, {name: f"PoC for {cve}"}, {name: [{"name": "poc.py"}]})):
            found = update_cves.discover_github_pocs("token", years=[2026], lookback_days=1,
                backfill=False, cve_filter=set(), failures=failures, completed_years=completed)
        self.assertEqual(found, {cve: [candidate["url"]]})
        self.assertEqual(completed, set())
        self.assertIn("replay unavailable", failures[0])

    def test_enrichment_preserves_curated_links_and_updates_placeholder(self):
        cve = "CVE-2026-109618"
        path = update_cves.CVES / "2026" / f"{cve}.md"
        path.parent.mkdir(parents=True)
        path.write_text(update_cves.build_markdown(cve, update_cves.pending_details(),
            ["https://github.com/example/php2shell"], []) + "\n#### Nuclei\n- https://example.com/template.yaml\n")
        with patch.object(update_cves, "http_json", return_value=None):
            update_cves.ensure_cve_entries([cve], dry_run=False)
        details = update_cves.CVEDetails("Official description", ["PHP"], [], [], title="PHP vulnerability")
        update_cves.refresh_record_header(path, details, {}, dry_run=False)
        text = path.read_text()
        self.assertIn("Official description", text)
        self.assertIn("https://github.com/example/php2shell", text)
        self.assertIn("#### Nuclei\n- https://example.com/template.yaml", text)
        self.assertNotIn(update_cves.PENDING_DESCRIPTION, text)
        self.assertEqual(update_cves.markdown_record_status(text), "PUBLISHED")

    def test_cached_rejected_identifier_is_not_republished(self):
        cve = "CVE-2026-109618"
        update_cves.RECORD_STATE_FILE.write_text(json.dumps({cve: {"status": "REJECTED", "checked": "2026-10-21"}}))
        with patch.object(update_cves, "discover_github_pocs", return_value={cve: ["https://github.com/example/poc"]}), \
                patch.object(update_cves, "http_json") as fetch:
            self.main()
        fetch.assert_not_called()
        self.assertFalse((update_cves.CVES / "2026" / f"{cve}.md").exists())
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"], {})

    def test_filtered_pending_recovery_leaves_other_candidates_queued(self):
        wanted, other = "CVE-2026-109618", "CVE-2026-109619"
        pending = {c: {"github": ["https://github.com/example/poc"], "references": [],
                       "status": "UNAVAILABLE", "checked": "2026-10-21"} for c in [wanted, other]}
        update_cves.DISCOVERY_STATE_FILE.write_text(json.dumps({"years": {}, "pending": pending}))
        with patch.object(update_cves, "http_json", return_value=None):
            self.main(skip_github=True, pending_only=True, cve=[wanted])
        self.assertTrue((update_cves.CVES / "2026" / f"{wanted}.md").exists())
        self.assertFalse((update_cves.CVES / "2026" / f"{other}.md").exists())
        self.assertEqual(json.loads(update_cves.DISCOVERY_STATE_FILE.read_text())["pending"][other], pending[other])

    def test_cve_feed_outage_does_not_block_github_publication_or_advance_delta(self):
        cve = "CVE-2026-109618"
        update_cves.STATE_FILE.write_text('{"cvelist_fetch_time":"2026-10-20T00:00:00Z"}')
        with patch.object(update_cves, "load_incremental_records", side_effect=TimeoutError("CVE feed unavailable")), \
                patch.object(update_cves, "discover_github_pocs", return_value={cve: ["https://github.com/example/poc"]}), \
                patch.object(update_cves, "http_json", return_value=None):
            self.assertEqual(self.main(skip_cvelist=False), 1)
        self.assertTrue((update_cves.CVES / "2026" / f"{cve}.md").exists())
        self.assertEqual(json.loads(update_cves.STATE_FILE.read_text())["cvelist_fetch_time"], "2026-10-20T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
