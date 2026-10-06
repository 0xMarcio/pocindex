from __future__ import annotations

import hashlib
import http.client
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_site
import sync_reference_pocs as sync
import update_cves

CVE = "CVE-2020-18305"
URL = "https://gist.github.com/researcher/1fe3fe58dd275edb77dcbe890fce2f2c"
TEXT = "id: CVE-2020-18305\nrequests:\n  - raw: GET /app/filelist/ HTTP/1.1\n"
DIGEST = hashlib.sha256(TEXT.encode()).hexdigest()
REVIEW = {"cve": CVE, "url": URL, "artifact": "file:poc.yaml", "sha256": DIGEST,
          "evidence": "Raw HTTP reproduction of the privileged filelist request"}


def feed(references):
    return {"format": "NVD_CVE", "version": "2.0", "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": CVE, "references": references}}]}


class ReferencePoCTests(unittest.TestCase):
    def test_truncated_http_response_preserves_approval_and_checks_sibling(self):
        sibling = URL.replace("researcher/", "second/")
        for failure in (http.client.IncompleteRead(b"partial"), http.client.BadStatusLine("bad")):
            state = {"candidates": {CVE: [URL, sibling]}, "checks": {}}
            with patch.object(sync, "fetch_artifacts", side_effect=[failure, {"file:poc.yaml": TEXT}]) as fetch:
                failures = sync.refresh_checks(state, [REVIEW], limit=2, days=7, cache=Path("unused"), dry_run=True)
            self.assertEqual(failures, 1)
            self.assertEqual(fetch.call_count, 2)
            self.assertIn("error", state["checks"][URL])
            self.assertIn("digests", state["checks"][sibling])
            self.assertEqual(sync.approvals([REVIEW], state["candidates"], state["checks"], {CVE: [URL]}), {CVE: [URL]})

    def test_nvd_tag_cannot_restore_withdrawn_reviewed_approval(self):
        metadata = {CVE: {"advisories": [[URL, ["Exploit"]]]}}
        previous = {CVE: [URL]}
        revoked = sync.approvals([REVIEW], previous, {URL: {"digests": {}}}, previous)
        self.assertEqual(revoked, {})
        with patch.object(build_site, "load_managed_references", return_value={(CVE, build_site.link_key(URL))}):
            self.assertFalse(build_site.reference_is_verified_poc(CVE, URL, metadata, set()))
        self.assertTrue(build_site.reference_is_verified_poc(CVE, URL, metadata, {(CVE, build_site.link_key(URL))}))
        with patch.object(build_site, "load_managed_references", return_value=set()):
            self.assertTrue(build_site.reference_is_verified_poc(CVE, URL, metadata, set()))
        other = "https://example.org/exploit.py"
        self.assertTrue(build_site.reference_is_verified_poc(CVE, other, {CVE: {"advisories": [[other, ["Exploit"]]]}}, set()))

    def test_reviewed_wrong_cve_exclusion_overrides_all_approval_paths(self):
        url = "http://seclists.org/fulldisclosure/2024/Feb/14"
        wrong, correct = "CVE-2024-23749", "CVE-2024-25004"
        self.assertIn((wrong, url), sync.load_exclusions())
        self.assertFalse(build_site.reference_is_verified_poc(wrong, url, {wrong: {"advisories": [[url, ["Exploit"]]]}}, {(wrong, url)}))
        self.assertTrue(build_site.reference_is_verified_poc(correct, url, {}, {(correct, url)}))
        self.assertIn((correct, url), {(row["cve"], row["url"]) for row in sync.load_reviews()})

    def test_malformed_exclusion_registry_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reviews.json"
            for payload in ([], {}, {"version": 1, "exclusions": [{}]}):
                path.write_text(json.dumps(payload))
                with self.assertRaises(ValueError):
                    sync.load_exclusions(path)

    def test_published_cve_omits_wrong_cve_legacy_reference(self):
        cve = "CVE-2024-23749"
        wrong = "http://seclists.org/fulldisclosure/2024/Feb/14"
        right = "http://seclists.org/fulldisclosure/2024/Feb/13"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "2024" / f"{cve}.md"
            path.parent.mkdir()
            path.write_text(f"### Description\nKiTTY command injection.\n\n#### Reference\n- {wrong}\n- {right}\n")
            with patch.object(build_site, "CVES", root), \
                    patch.object(build_site, "load_dates", return_value={}), \
                    patch.object(build_site, "load_metadata", return_value={cve: {"advisories": [[wrong, ["Exploit"]], [right, ["Exploit"]]]}}), \
                    patch.object(build_site, "load_verified_references", return_value={(cve, wrong), (cve, right)}):
                entries, _ = build_site.build_cve_list(set())
        self.assertEqual(entries[0]["poc"], [right])

    def test_exact_nvd_association_and_reviewed_hash_are_required(self):
        candidates = sync.feed_candidates(feed([
            {"url": URL, "tags": ["Exploit"]},
            {"url": URL + "/other", "tags": ["Exploit"]},
            {"url": "https://packetstormsecurity.com/files/123/poc", "tags": ["Exploit"]},
        ]))
        self.assertEqual(candidates, {CVE: [URL]})
        checks = {URL: {"digests": {"file:poc.yaml": DIGEST}}}
        self.assertEqual(sync.approvals([], candidates, checks, {}), {})
        self.assertEqual(sync.approvals([REVIEW], candidates, checks, {}), {CVE: [URL]})
        self.assertEqual(sync.approvals([{**REVIEW, "cve": "CVE-2015-0235"}], candidates, checks, {}), {})
        self.assertEqual(sync.feed_candidates(feed([{"url": URL, "tags": ["Third Party Advisory"]}])), {CVE: []})

    def test_header_only_or_unrelated_page_poc_is_never_auto_approved(self):
        for cve, text in [
            ("CVE-2009-3621", "Reproducer:\nhttps://example.org/external.c\n#include <stdio.h>\n"),
            ("CVE-2015-0235", "CVE-2020-28010\nProof of concept:\n/usr/sbin/exim4 -R payload\n"),
        ]:
            digest = hashlib.sha256(text.encode()).hexdigest()
            self.assertEqual(sync.approvals([], {cve: [URL]}, {URL: {"digests": {"pre:0": digest}}}, {}), {})

    def test_changed_content_withdraws_only_current_source_approval(self):
        previous = {CVE: [URL]}
        checks = {URL: {"digests": {"file:poc.yaml": "changed"}}}
        self.assertEqual(sync.approvals([REVIEW], {CVE: [URL]}, checks, previous), {})
        checks[URL]["error"] = "HTTP 503"
        self.assertEqual(sync.approvals([REVIEW], {CVE: [URL]}, checks, previous), previous)
        self.assertEqual(sync.approvals([REVIEW], {CVE: []}, checks, previous), {})
        self.assertEqual(sync.approvals([], {CVE: [URL]}, checks, previous), {})

    def test_partial_gist_response_is_an_error(self):
        for payload in [{}, {"files": {"poc.py": {"truncated": True, "content": "partial"}}},
                        {"truncated": True, "files": {}}]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                sync.gist_artifacts(payload)
        self.assertEqual(sync.gist_artifacts({"files": {"poc.yaml": {"content": TEXT}}}), {"file:poc.yaml": TEXT})

    def test_html_identity_ignores_page_chrome_but_preserves_payload(self):
        before = b'<header>old</header><pre>GET /?x=&lt;script&gt;\r\n</pre>'
        after = b'<header>new</header><pre>GET /?x=&lt;script&gt;\r\n</pre>'
        self.assertEqual(sync.html_artifacts(before), {"pre:0": "GET /?x=<script>"})
        self.assertEqual(sync.html_artifacts(before), sync.html_artifacts(after))

    def test_block_or_unparsed_html_retains_prior_approval(self):
        url = "https://seclists.org/fulldisclosure/2020/May/2"
        review = {**REVIEW, "url": url, "artifact": "pre:0"}
        for body in (b"<html>Checking your browser</html>", b"<pre>Access denied</pre>", b"<!--X-Body-of-Message--><pre>truncated"):
            state = {"candidates": {CVE: [url]}, "checks": {}}
            with patch.object(sync, "fetch_artifacts", side_effect=lambda _: sync.mail_artifacts(url, body)):
                sync.refresh_checks(state, [review], limit=1, days=7, cache=Path("unused"), dry_run=True)
            self.assertEqual(sync.approvals([review], state["candidates"], state["checks"], {CVE: [url]}), {CVE: [url]})
        body = b"<!--X-Body-of-Message--><pre>revised payload</pre><!--X-Body-of-Message-End-->"
        self.assertEqual(sync.mail_artifacts(url, body)["pre:0"], "revised payload")
        with self.assertRaises(ValueError):
            sync.mail_artifacts("https://openwall.com/lists/oss-security/2020/01/01/1", b"<pre>Access denied</pre>")

    def test_archive_message_preserves_payload_split_into_tt_tags(self):
        url = "https://seclists.org/fulldisclosure/2024/Sep/23"
        body = b"<header>chrome</header><!--X-Body-of-Message--><pre>POST /request\n</pre><tt>payload=&lt;value&gt;</tt><pre>End</pre><!--X-Body-of-Message-End--><footer>chrome</footer>"
        artifacts = sync.mail_artifacts(url, body)
        self.assertEqual(artifacts["pre:0"], "POST /request")
        self.assertEqual(artifacts["mail:body"], "POST /request\n\npayload=<value>\nEnd")

    def test_checks_removed_from_all_candidates_are_pruned(self):
        state = {"candidates": {}, "checks": {URL: {"digests": {"file:poc.yaml": DIGEST}}}}
        sync.refresh_checks(state, [REVIEW], limit=1, days=7, cache=Path("unused"), dry_run=True)
        self.assertEqual(state["checks"], {})

    def test_failed_fetch_preserves_prior_approval_and_queue_resumes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"candidates": {CVE: [URL]}, "checks": {URL: {"checked": "2020-01-01", "digests": {"file:poc.yaml": DIGEST}}}}
            with patch.object(sync, "QUEUE", root / "queue.json"), patch.object(sync, "fetch_artifacts", side_effect=TimeoutError("timeout")):
                sync.refresh_checks(state, [REVIEW], limit=1, days=7, cache=root / "cache", dry_run=False)
            self.assertEqual(sync.approvals([REVIEW], state["candidates"], state["checks"], {CVE: [URL]}), {CVE: [URL]})
            self.assertIn("error", json.loads((root / "queue.json").read_text())["checks"][URL])
            with patch.object(sync, "QUEUE", root / "queue.json"), patch.object(sync, "fetch_artifacts", return_value={"file:poc.yaml": TEXT}) as fetch:
                sync.refresh_checks(state, [REVIEW], limit=1, days=7, cache=root / "cache", dry_run=False)
                fetch.assert_called_once_with(URL)
                sync.refresh_checks(state, [REVIEW], limit=1, days=7, cache=root / "cache", dry_run=False)
                fetch.assert_called_once()
            self.assertEqual((root / "cache" / (DIGEST + ".txt")).read_text(), TEXT)

    def test_successful_404_withdraws_approval_but_503_does_not(self):
        for code in (404, 410, 503):
            state = {"candidates": {CVE: [URL]}, "checks": {}}
            with patch.object(sync, "fetch_artifacts", side_effect=HTTPError(URL, code, "failure", {}, None)):
                sync.refresh_checks(state, [REVIEW], limit=1, days=7, cache=Path("unused"), dry_run=True)
            result = sync.approvals([REVIEW], state["candidates"], state["checks"], {CVE: [URL]})
            self.assertEqual(result, {CVE: [URL]} if code == 503 else {})

    def test_budget_expiry_preserves_unchecked_approval_and_partial_progress(self):
        second = URL.replace("researcher/", "second/")
        review = {**REVIEW, "url": second}
        old_check = {"checked": "2000-01-01", "digests": {"file:poc.yaml": DIGEST}}
        state = {"candidates": {CVE: [URL, second]}, "checks": {second: old_check.copy()}}
        with patch.object(sync.time, "monotonic", side_effect=[0, 0, 2]):
            budget = sync.Budget(1)
            with patch.object(sync, "fetch_artifacts", return_value={"file:poc.yaml": TEXT}) as fetch:
                with self.assertRaises(sync.BudgetExpired):
                    sync.refresh_checks(state, [REVIEW, review], limit=2, days=7,
                                        cache=Path("unused"), dry_run=True, budget=budget)
        fetch.assert_called_once_with(URL, budget=budget)
        self.assertEqual(state["checks"][second], old_check)
        self.assertNotIn("error", state["checks"][second])
        self.assertEqual(sync.approvals([REVIEW, review], state["candidates"], state["checks"], {CVE: [second]}), {CVE: sorted([URL, second])})

    def test_main_budget_expiry_keeps_prior_approval_and_saved_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue, ledger = root / "queue.json", root / "verified.json"
            state = {"candidates": {CVE: [URL]}, "checks": {URL: {"checked": "2000-01-01", "digests": {"file:poc.yaml": DIGEST}}}}
            queue.write_text(json.dumps(state))
            ledger.write_text(json.dumps({CVE: [URL]}))
            with patch.object(sys, "argv", ["sync", "--max-seconds", "1"]), \
                    patch.object(sync, "QUEUE", queue), patch.object(sync, "VERIFIED", ledger), \
                    patch.object(sync, "load_reviews", return_value=[REVIEW]), \
                    patch.object(sync, "load_feeds", return_value={}), \
                    patch.object(sync, "fetch_artifacts", side_effect=sync.BudgetExpired), \
                    patch.object(update_cves, "ensure_cve_entries") as ensure:
                self.assertEqual(sync.main(), 0)
            self.assertEqual(json.loads(queue.read_text()), state)
            self.assertEqual(json.loads(ledger.read_text()), {CVE: [URL]})
            ensure.assert_not_called()

    def test_network_read_is_bounded_and_clears_alarm(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"body"
        with patch.object(sync.time, "monotonic", return_value=0), \
                patch.object(sync.request, "urlopen", return_value=response) as fetch, \
                patch.object(sync.signal, "signal"), patch.object(sync.signal, "setitimer") as timer:
            self.assertEqual(sync.Budget(180).read("https://example.com"), b"body")
        fetch.assert_called_once_with("https://example.com", timeout=10)
        self.assertEqual(timer.call_args_list[0].args, (sync.signal.ITIMER_REAL, 10))
        self.assertEqual(timer.call_args_list[-1].args, (sync.signal.ITIMER_REAL, 0))

    def test_official_record_is_reused_without_threaded_network_retries(self):
        record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
                  "containers": {"cna": {"descriptions": [{"lang": "en", "value": "A vulnerability"}]}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = sync.Budget(180)
            args = SimpleNamespace(record_states=None, cvelist_dir=None, dry_run=True)
            with patch.object(update_cves, "CVES", root / "cves"), \
                    patch.object(update_cves, "DATES_FILE", root / "dates.json"), \
                    patch.object(update_cves, "load_record_state", return_value={}), \
                    patch.object(update_cves, "load_kev", return_value={}), \
                    patch.object(budget, "read", return_value=json.dumps(record).encode()) as read, \
                    patch.object(update_cves, "fetch_records", side_effect=AssertionError("unbounded retry")) as fetch:
                self.assertEqual(sync.published_entries({CVE: [URL]}, {}, args, budget), {CVE: [URL]})
            read.assert_called_once()
            fetch.assert_not_called()
            self.assertFalse((root / "cves").exists())

    def test_incomplete_feed_is_rejected(self):
        for payload in [[], {}, {**feed([]), "totalResults": 2},
                        {**feed([]), "totalResults": 2, "vulnerabilities": feed([])["vulnerabilities"] * 2}]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                sync.feed_candidates(payload)

    def test_independent_verified_ledger_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared, owned = root / "shared.txt", root / "owned.json"
            shared.write_text(f"{CVE} - {URL}\n")
            owned.write_text(json.dumps({CVE: [URL], "CVE-2013-2492": [URL]}))
            with patch.object(build_site, "VERIFIED_REFERENCES", shared), patch.object(build_site, "REVIEWED_REFERENCES", owned):
                build_site.load_verified_references.cache_clear()
                self.assertEqual(len(build_site.load_verified_references()), 2)
                owned.write_text("{}")
                build_site.load_verified_references.cache_clear()
                self.assertEqual(build_site.load_verified_references(), {(CVE, build_site.link_key(URL))})
                self.assertTrue(build_site.reference_is_verified_poc(CVE, URL, {}, build_site.load_verified_references()))
            build_site.load_verified_references.cache_clear()
            self.assertEqual(shared.read_text(), f"{CVE} - {URL}\n")

    def test_main_does_not_admit_reserved_cve_or_write_during_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            statuses = root / "states.json"
            statuses.write_text(json.dumps({CVE: "RESERVED"}))
            state = {"candidates": {CVE: [URL]}, "checks": {URL: {"checked": datetime.now(timezone.utc).date().isoformat(), "digests": {"file:poc.yaml": DIGEST}}}}
            queue, ledger = root / "queue.json", root / "verified.json"
            queue.write_text(json.dumps(state))
            original = queue.read_bytes()
            with patch.object(sys, "argv", ["sync", "--dry-run", "--record-states", str(statuses)]), \
                    patch.object(sync, "QUEUE", queue), patch.object(sync, "VERIFIED", ledger), \
                    patch.object(sync, "load_reviews", return_value=[REVIEW]), \
                    patch.object(sync, "load_feeds", return_value={}), \
                    patch.object(update_cves, "ensure_cve_entries", return_value=(set(), set())) as ensure, \
                    patch.object(update_cves, "append_inventory") as append:
                self.assertEqual(sync.main(), 0)
                self.assertEqual(ensure.call_args.args[0], {})
                self.assertEqual(append.call_args.args[1], {})
            self.assertEqual(queue.read_bytes(), original)
            self.assertFalse(ledger.exists())


if __name__ == "__main__":
    unittest.main()
