from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import unquote
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import source_artifacts as artifacts
import update_cves

CVE = "CVE-2024-28000"
REVISION = "a" * 40
NEXT_REVISION = "b" * 40
SOURCE = b"package main\n// reviewed LiteSpeed reproduction fixture\nfunc main() {}\n"


def review(cve=CVE, repository="researcher/CVE-2024-28000", path="expl/main.go", source=SOURCE):
    return {"id": "review-fixture", "cve": cve, "repository": repository, "path": path,
            "revision": REVISION, "sha256": hashlib.sha256(source).hexdigest(),
            "review_basis": "Test source/product review", "official_state": "PUBLISHED",
            "official_record_revision": "c" * 40, "official_record_sha256": "d" * 64,
            "released_at": None}


def repository(name="researcher/CVE-2024-28000", revision=REVISION):
    return {"nameWithOwner": name, "description": "Exploit lab", "isFork": False,
            "defaultBranchRef": {"target": {"oid": revision}},
            "root": {"entries": [{"name": "expl", "type": "tree"}]},
            "readmeMd": {"text": f"PoC for {CVE}. Run expl/main.go."}}


class ArtifactGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.reviews = Path(self.temp.name) / "reviews.json"
        self.candidates = Path(self.temp.name) / "candidates.json"
        self.write_reviews([review()])
        self.budget_patch = patch.object(artifacts, "_AUTOMATIC_BUDGET", None)
        self.budget_patch.start()
        self.addCleanup(self.budget_patch.stop)

    def write_reviews(self, rows):
        self.reviews.write_text(json.dumps({"version": 1, "reviews": rows}))

    def fetcher(self, files):
        tree = []
        blobs = {}
        for path, raw in files.items():
            oid = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            tree.append({"path": path, "type": "blob", "mode": "100644", "size": len(raw), "sha": oid})
            blobs[oid] = {"encoding": "base64", "content": base64.b64encode(raw).decode()}
        def get(url, **kwargs):
            if "/contents/" in url:
                path = unquote(url.split("/contents/", 1)[1].split("?", 1)[0])
                entry = next((row for row in tree if row["path"] == path), None)
                return {**entry, **blobs[entry["sha"]], "type": "file"} if entry else None
            if "/git/trees/" in url:
                return {"tree": tree, "truncated": False}
            if "/git/blobs/" in url:
                return blobs[url.rsplit("/", 1)[1]]
            self.fail(f"Unexpected network request: {url}")
        return Mock(side_effect=get)

    def inspect(self, repo, fetch, persist=True):
        return artifacts.inspect_repository(repo, artifacts.identity_cves(repo["nameWithOwner"]),
                                            repo["readmeMd"]["text"], fetch, {},
                                            reviews_path=self.reviews, candidates_path=self.candidates,
                                            persist=persist)

    def test_rejected_nested_lab_becomes_qualified_only_after_byte_verification(self):
        repo = repository()
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2024, []), set())
        repo["_source_artifacts"] = self.inspect(repo, self.fetcher({"expl/main.go": SOURCE}))
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2024, []), {CVE})
        self.assertEqual(artifacts.approved_artifact_links(repo, CVE),
                         [f"https://github.com/researcher/CVE-2024-28000/blob/{REVISION}/expl/main.go"])
        for blocked in (["researcher/cve-2024-28000"],):
            self.assertEqual(update_cves.qualifying_repo_cves(repo, 2024, blocked), set())
        repo["isFork"] = True
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2024, []), set())

    def test_discovery_returns_pinned_artifact_links(self):
        repo = repository()
        repo["url"] = "https://github.com/" + repo["nameWithOwner"]
        name = repo["nameWithOwner"]
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates), \
                patch.object(update_cves, "http_json", self.fetcher({"expl/main.go": SOURCE})), \
                patch.object(update_cves, "load_blacklist", return_value=[]), \
                patch.object(update_cves, "search_range", return_value=[repo]), \
                patch.object(update_cves.GitHubClient, "fetch_readmes", return_value=(
                    {name}, {name: repo["readmeMd"]["text"]}, {name: repo["root"]["entries"]})):
            result = update_cves.discover_github_pocs("token", years=[2024], lookback_days=3,
                                                    backfill=False, cve_filter=set(), artifact_cache_write=False)
        self.assertEqual(result[CVE], [f"https://github.com/{name}/blob/{REVISION}/expl/main.go"])
        self.assertFalse(self.candidates.exists())

    def test_bare_placeholders_do_not_trigger_nested_api_work(self):
        repo = repository()
        repo["nameWithOwner"] = "unknown/CVE-2024-28000"
        repo["readmeMd"] = {"text": "Soon"}
        repo["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
        with patch.object(update_cves, "http_json", side_effect=AssertionError("bare repository")):
            update_cves.attach_source_artifacts(repo, {}, [], persist=False)
        self.assertNotIn("_source_artifacts", repo)

    def test_reviewed_identity_can_correct_a_misnamed_repository(self):
        wrong_name = "researcher/CVE-2024-29000"
        self.write_reviews([review(repository=wrong_name)])
        repo = repository(wrong_name)
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates), \
                patch.object(update_cves, "http_json", self.fetcher({"expl/main.go": SOURCE})):
            update_cves.attach_source_artifacts(repo, {}, [], cves={CVE}, persist=False)
            self.assertIn(CVE, update_cves.qualifying_repo_cves(repo, 2024, []))
        self.assertEqual(repo["_source_artifacts"][0].repository, wrong_name)

    def test_reviewed_exclusions_do_not_blacklist_correct_cve(self):
        for name in ["1nzag/CVE-2022-0995", "AndreevSemen/CVE-2022-0995", "Bonfee/CVE-2022-0995"]:
            repo = repository(name)
            repo["readmeMd"]["text"] = "CVE-2022-0995 exploit using the technique from CVE-2021-22555."
            repo["root"] = {"entries": [{"name": "exploit.c", "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(repo, 2021, []), set())
            self.assertIn("CVE-2022-0995", update_cves.qualifying_repo_cves(repo, 2022, []))
        repo = repository("MRdark-ops/CVE-2026-19660-exploit")
        repo["root"] = {"entries": [{"name": "poc.py", "type": "blob"}]}
        self.assertNotIn("CVE-2026-19660", update_cves.qualifying_repo_cves(repo, 2026, []))

    def test_shared_ingestion_rejects_only_reviewed_bad_pairs(self):
        cve = "CVE-2026-19660"
        good = "https://github.com/murrez/CVE-2026-19660"
        bad = "https://github.com/MRdark-ops/CVE-2026-19660-exploit"
        root = Path(self.temp.name) / "cves"
        path = root / "2026" / (cve + ".md")
        path.parent.mkdir(parents=True)
        path.write_text("#### Reference\nNo PoCs from references.\n\n#### Github\n- " + good + "\n")
        with patch.object(update_cves, "CVES", root):
            _, github, references = update_cves.sync_markdown({}, {cve: [good, bad]}, {cve: [bad]}, dry_run=False)
        self.assertEqual(github[cve], [good])
        self.assertEqual(references[cve], [])
        self.assertNotIn(bad, path.read_text())

    def test_remote_json_cannot_assert_review(self):
        repo = repository()
        repo["_source_artifacts"] = [review()]
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2024, []), set())

    def test_path_move_within_reviewed_repo_preserves_original_source_context(self):
        repo = repository()
        found = self.inspect(repo, self.fetcher({"src/poc/main.go": SOURCE}))
        self.assertEqual({r.cve for r in found}, {CVE})
        self.assertIsNone(found[0].released_at)
        self.assertEqual(found[0].path, "expl/main.go")
        self.assertEqual(found[0].revision, REVISION)
        wrong = repository("other/CVE-2024-4890-analysis")
        self.assertEqual(self.inspect(wrong, self.fetcher({"src/poc/main.go": SOURCE})), ())

    def test_foreign_identical_harness_without_reviewed_siblings_is_not_approved(self):
        repo = repository("copy/CVE-2024-28000-lab")
        self.assertEqual(self.inspect(repo, self.fetcher({"expl/main.go": SOURCE})), ())
        row = json.loads(self.candidates.read_text())["repositories"][repo["nameWithOwner"].lower()]
        self.assertEqual(row["status"], "needs_review")

    def test_unreviewed_code_is_captured_without_blob_content_and_retried_at_new_revision(self):
        repo = repository()
        unreviewed = self.fetcher({"expl/main.go": b"package main\n// version-only scanner\n"})
        self.assertEqual(self.inspect(repo, unreviewed), ())
        saved = self.candidates.read_text()
        self.assertNotIn("version-only scanner", saved)
        self.assertEqual(json.loads(saved)["repositories"][repo["nameWithOwner"].lower()]["status"], "needs_review")
        no_network = Mock(side_effect=AssertionError("unchanged revision should be cached"))
        self.assertEqual(self.inspect(repo, no_network), ())
        repo["defaultBranchRef"]["target"]["oid"] = NEXT_REVISION
        self.assertEqual(len(self.inspect(repo, self.fetcher({"expl/main.go": SOURCE}))), 1)

    def test_same_bytes_do_not_churn_pinned_links_after_unrelated_commit(self):
        repo = repository()
        first = self.inspect(repo, self.fetcher({"poc/main.go": SOURCE}))[0]
        repo["defaultBranchRef"]["target"]["oid"] = NEXT_REVISION
        second = self.inspect(repo, self.fetcher({"poc/main.go": SOURCE}))[0]
        self.assertEqual(first.url, second.url)
        original = repository(revision=NEXT_REVISION)
        self.assertEqual(self.inspect(original, self.fetcher({"expl/main.go": SOURCE}))[0].revision, REVISION)

    def test_new_review_rescans_previously_unresolved_same_revision(self):
        raw = b"package main\n// independently reviewed new source\n"
        repo = repository()
        self.assertEqual(self.inspect(repo, self.fetcher({"expl/main.go": raw})), ())
        self.write_reviews([review(source=raw)])
        self.assertEqual(len(self.inspect(repo, self.fetcher({"expl/main.go": raw}))), 1)

    def test_transport_failure_and_blob_mismatch_do_not_cache_rejection(self):
        repo = repository()
        with self.assertRaisesRegex(RuntimeError, "rate limited"):
            self.inspect(repo, Mock(side_effect=RuntimeError("rate limited")))
        self.assertFalse(self.candidates.exists())
        fetch = self.fetcher({"expl/main.go": SOURCE})
        original = fetch.side_effect
        def corrupt(url, **kwargs):
            result = original(url, **kwargs)
            if "/git/blobs/" in url or "/contents/" in url:
                return {**result, "encoding": "base64", "content": base64.b64encode(b"X" * len(SOURCE)).decode()}
            return result
        fetch.side_effect = corrupt
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            self.inspect(repo, fetch)
        self.assertFalse(self.candidates.exists())

    def test_file_budget_resumes_without_permanently_missing_a_later_payload(self):
        repo = repository()
        files = {f"poc/{n:02}.go": b"package main\n// unreviewed helper\n" for n in range(8)}
        files["poc/00.go"] = b"binary\0fixture"
        files["poc/99.go"] = SOURCE
        with patch.object(artifacts, "MAX_FILES", 8):
            self.assertEqual(self.inspect(repo, self.fetcher(files)), ())
            found = self.inspect(repo, self.fetcher(files))
        self.assertEqual([item.path for item in found], ["expl/main.go"])

    def test_incomplete_scan_resumes_after_an_earlier_positive(self):
        second = "CVE-2024-29000"
        name = f"researcher/{CVE}_{second}"
        self.write_reviews([review(repository=name), review(second, repository=name, path="poc/second.go", source=SOURCE + b"// second\n")])
        repo = repository(name)
        files = {"expl/main.go": SOURCE, "poc/second.go": SOURCE + b"// second\n"}
        with patch.object(artifacts, "MAX_FILES", 1):
            first = self.inspect(repo, self.fetcher(files))
            self.assertEqual({item.cve for item in first}, {CVE})
            fetch = self.fetcher(files)
            second_pass = self.inspect(repo, fetch)
        self.assertTrue(fetch.called)
        self.assertEqual({item.cve for item in second_pass}, {CVE, second})

    def test_incomplete_tree_is_pending_and_retried_after_revision_changes(self):
        for tree in [{"tree": [], "truncated": True},
                     {"tree": [{"path": "extra"}] * (artifacts.MAX_TREE + 1), "truncated": False}]:
            with self.subTest(truncated=tree["truncated"]):
                self.candidates.unlink(missing_ok=True)
                fetch = Mock(side_effect=lambda url, **kw: None if "/contents/" in url else tree)
                self.assertEqual(self.inspect(repository(), fetch), ())
                row = json.loads(self.candidates.read_text())["repositories"][repository()["nameWithOwner"].lower()]
                self.assertFalse(row["scan_complete"])
                self.assertEqual(row["status"], "tree_limited")
                self.assertEqual(self.inspect(repository(), Mock(side_effect=AssertionError("same limited revision"))), ())
                self.assertEqual(len(self.inspect(repository(revision=NEXT_REVISION), self.fetcher({"expl/main.go": SOURCE}))), 1)

    def test_known_reviewed_path_avoids_even_an_enormous_tree(self):
        fetch = self.fetcher({"expl/main.go": SOURCE})
        self.assertEqual(len(self.inspect(repository(), fetch)), 1)
        self.assertEqual(fetch.call_count, 1)
        self.assertIn("/contents/expl/main.go?ref=", fetch.call_args.args[0])

    def test_empty_repository_and_unreviewed_candidates_spend_no_rest_quota(self):
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates), \
                patch.object(update_cves, "http_json", side_effect=AssertionError("REST quota spent")):
            empty = repository()
            empty["defaultBranchRef"] = None
            empty["root"] = None
            update_cves.attach_source_artifacts(empty, {}, [])
            for number in range(1000):
                update_cves.attach_source_artifacts(repository(f"unknown{number}/{CVE}"), {}, [])
        self.assertFalse(self.candidates.exists())

    def test_legacy_empty_repository_head_conflict_is_not_transport_failure(self):
        repo = repository()
        del repo["defaultBranchRef"]
        fetch = Mock(side_effect=HTTPError("url", 409, "Git Repository is empty", {}, None))
        self.assertEqual(self.inspect(repo, fetch), ())
        self.assertEqual(fetch.call_count, 1)

    def test_unrelated_review_changes_do_not_invalidate_cached_evidence(self):
        repo = repository()
        self.assertEqual(len(self.inspect(repo, self.fetcher({"expl/main.go": SOURCE}))), 1)
        self.write_reviews([review(), review(repository="another/" + CVE)])
        self.assertEqual(len(self.inspect(repo, Mock(side_effect=AssertionError("unrelated review")))), 1)

    def test_global_budget_retains_partial_evidence_then_resumes(self):
        second = "CVE-2024-29000"
        name = f"researcher/{CVE}_{second}"
        self.write_reviews([review(repository=name), review(second, repository=name, path="poc/second.go", source=SOURCE + b"second")])
        repo = repository(name)
        files = {"expl/main.go": SOURCE, "poc/second.go": SOURCE + b"second"}
        def run(budget, fetch):
            return artifacts.inspect_repository(repo, {CVE, second}, "", fetch, {}, reviews_path=self.reviews,
                                                candidates_path=self.candidates, budget=budget)
        first = self.fetcher(files)
        self.assertEqual({a.cve for a in run(artifacts.InspectionBudget(1), first)}, {CVE})
        self.assertEqual(first.call_count, 1)
        row = json.loads(self.candidates.read_text())["repositories"][name.lower()]
        self.assertFalse(row["scan_complete"])
        self.assertEqual(row["status"], "budget_deferred")
        fetch = self.fetcher(files)
        self.assertEqual({a.cve for a in run(artifacts.InspectionBudget(1), fetch)}, {CVE, second})
        self.assertEqual(fetch.call_count, 1)

    def test_elapsed_time_budget_defers_without_network(self):
        fetch = Mock(side_effect=AssertionError("time budget expired"))
        result = artifacts.inspect_repository(repository(), {CVE}, "", fetch, {}, reviews_path=self.reviews,
                                              candidates_path=self.candidates,
                                              budget=artifacts.InspectionBudget(seconds=0))
        self.assertEqual(result, ())
        row = json.loads(self.candidates.read_text())["repositories"][repository()["nameWithOwner"].lower()]
        self.assertFalse(row["scan_complete"])
        self.assertEqual(row["status"], "budget_deferred")

    def test_quota_exhaustion_is_durable_but_other_transport_errors_propagate(self):
        repo = repository()
        fetch = Mock(side_effect=HTTPError("url", 403, "quota", {"X-RateLimit-Remaining": "0"}, None))
        budget = artifacts.InspectionBudget(3)
        result = artifacts.inspect_repository(repo, {CVE}, "", fetch, {}, reviews_path=self.reviews,
                                              candidates_path=self.candidates, budget=budget)
        self.assertEqual(result, ())
        self.assertTrue(budget.exhausted)
        self.assertEqual(json.loads(self.candidates.read_text())["repositories"][repo["nameWithOwner"].lower()]["status"], "rate_limited")
        self.assertEqual(len(self.inspect(repo, self.fetcher({"expl/main.go": SOURCE}))), 1)

    def test_pending_reviewed_repository_replays_outside_push_window(self):
        repo = repository()
        repo["url"] = "https://github.com/" + repo["nameWithOwner"]
        name = repo["nameWithOwner"]
        artifacts.inspect_repository(repo, {CVE}, "", Mock(side_effect=AssertionError("zero budget")), {},
                                     reviews_path=self.reviews, candidates_path=self.candidates,
                                     budget=artifacts.InspectionBudget(0))
        fetch = self.fetcher({"expl/main.go": SOURCE})
        def responses(url, **kwargs):
            if url == update_cves.GITHUB_GRAPHQL_URL:
                return {"data": {"repo0": repo, "rateLimit": {"remaining": 100}}}
            return fetch(url, **kwargs)
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates), \
                patch.object(update_cves, "http_json", side_effect=responses), \
                patch.object(update_cves, "load_blacklist", return_value=[]), \
                patch.object(update_cves, "search_range", return_value=[]), \
                patch.object(update_cves.GitHubClient, "fetch_readmes", return_value=(
                    {name}, {name: repo["readmeMd"]["text"]}, {name: repo["root"]["entries"]})):
            result = update_cves.discover_github_pocs("token", years=[2024], lookback_days=3,
                                                    backfill=False, cve_filter=set())
            self.assertEqual(artifacts.pending_reviewed_names(), [])
        self.assertEqual(result[CVE], [f"https://github.com/{name}/blob/{REVISION}/expl/main.go"])

    def test_single_cve_caller_preserves_other_pending_reviews(self):
        second = "CVE-2024-29000"
        name = f"researcher/{CVE}_{second}"
        self.write_reviews([review(repository=name), review(second, repository=name, path="poc/second.go", source=SOURCE + b"second")])
        repo = repository(name)
        fetch = self.fetcher({"expl/main.go": SOURCE, "poc/second.go": SOURCE + b"second"})
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates), \
                patch.object(artifacts, "MAX_FILES", 1), patch.object(update_cves, "http_json", fetch):
            update_cves.attach_source_artifacts(repo, {}, [], cves={CVE, second})
            self.assertEqual({a.cve for a in repo["_source_artifacts"]}, {CVE})
            update_cves.attach_source_artifacts(repo, {}, [], cves={CVE})
        self.assertEqual({a.cve for a in repo["_source_artifacts"]}, {CVE, second})
        row = json.loads(self.candidates.read_text())["repositories"][name.lower()]
        self.assertEqual(set(row["cves"]), {CVE, second})
        self.assertTrue(row["scan_complete"])

    def test_unavailable_pending_rows_rotate_without_false_completion(self):
        names = ["first/" + CVE, "second/" + CVE]
        self.write_reviews([review(repository=name) for name in names])
        for name in names:
            artifacts._save_candidate(self.candidates, name, {"scan_complete": False, "last_checked_at": "2020"})
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates):
            self.assertEqual(artifacts.pending_reviewed_names(1), [names[0].lower()])
            artifacts.mark_pending_checked([names[0]])
            self.assertEqual(artifacts.pending_reviewed_names(1), [names[1].lower()])
        rows = json.loads(self.candidates.read_text())["repositories"]
        self.assertTrue(all(row["scan_complete"] is False for row in rows.values()))

    def test_pending_limit_applies_after_cve_scope_filter(self):
        names = ["older/CVE-2020-1234", "current/" + CVE]
        self.write_reviews([review("CVE-2020-1234", names[0]), review(repository=names[1])])
        for index, name in enumerate(names):
            artifacts._save_candidate(self.candidates, name, {"scan_complete": False, "last_checked_at": str(index)})
        with patch.object(artifacts, "REVIEWS", self.reviews), patch.object(artifacts, "CANDIDATES", self.candidates):
            self.assertEqual(artifacts.pending_reviewed_names(1, cves={CVE}), [names[1].lower()])

    def test_dry_run_preserves_candidate_state(self):
        self.inspect(repository(), self.fetcher({"expl/main.go": SOURCE}), persist=False)
        self.assertFalse(self.candidates.exists())

    def test_cve_identity_is_exact_and_directory_only_does_not_qualify(self):
        self.assertEqual(artifacts.identity_cves("owner/CVE-2024-280001"), {"CVE-2024-280001"})
        self.assertEqual(self.inspect(repository(), self.fetcher({})), ())
        self.assertFalse(artifacts.valid_path("poc/"))
        self.assertFalse(artifacts.valid_path("../poc.py"))

    def test_collection_exceptions_match_path_author_and_exact_bytes(self):
        chain = [review("CVE-2018-15705", "tenable/poc", "chain.py"),
                 review("CVE-2018-15707", "tenable/poc", "chain.py")]
        self.assertEqual(artifacts.approved_cves_for_artifact("Tenable/poc", "chain.py", SOURCE, reviews=chain),
                         {"CVE-2018-15705", "CVE-2018-15707"})
        for repo, path, raw in [("other/poc", "chain.py", SOURCE), ("tenable/poc", "other.py", SOURCE),
                                ("tenable/poc", "chain.py", SOURCE + b" ")]:
            self.assertEqual(artifacts.approved_cves_for_artifact(repo, path, raw, reviews=chain), set())

    def test_registry_keeps_release_dates_unknown_and_has_all_reviewed_pairs(self):
        rows = artifacts.load_reviews()
        self.assertGreaterEqual(len(rows), 79)
        self.assertEqual(sum(r["repository"] == "tenable/poc" for r in rows), 5)
        self.assertTrue(all("released_at" in r for r in rows))
        self.assertEqual(len({r["id"] for r in rows}), len(rows))
        for excluded in ["nekr0ff/needrestart-sudo-escalate-cve-2024-4890", "uky007/CVE-2025-62215_analysis",
                         "iqx6889/CVE-2026-52813-Gogs-RCE", "fevar54/CVE-2025-48595-Android-Framework-Integer-Overflow-"]:
            self.assertFalse(any(r["repository"] == excluded for r in rows))


if __name__ == "__main__":
    unittest.main()
