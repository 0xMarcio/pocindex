from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("getTrending", str(ROOT / ".github" / "getTrending.py"))
trending = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trending)
sys.path.insert(0, str(ROOT / "scripts"))

import sync_collections
import build_site

NOW = datetime.now(timezone.utc)
CVE = f"CVE-{NOW.year}-21589"
ALIAS = re.compile(r'(r\d+): repository\(owner: "[^"]*", name: "([^"]*)"\)')
EMPTY = {"readmeMd": {"text": "Soon"}, "root": {"entries": [{"name": "README.md", "type": "blob"}]}}


def stamp(days: float) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def repo(full_name: str, created: object, stars: int = 0, description: str = "Proof of concept") -> dict:
    return {
        "full_name": full_name,
        "name": full_name.split("/", 1)[1],
        "html_url": f"https://github.com/{full_name}",
        "description": description,
        "stargazers_count": stars,
        "created_at": created,
        "pushed_at": stamp(0.1),
    }


def gate(query: str, token: str) -> dict:
    """GraphQL content for the real PoC gate: a README and an exploit at the root."""
    return {
        alias: {
            "readmeMd": {"text": f"Proof of concept for {name}"},
            "root": {"entries": [{"name": "exploit.py", "type": "blob"}]},
        }
        for alias, name in ALIAS.findall(query)
    }


def shipped(names: list[str], token: str, paths: dict | None = None) -> dict[str, str]:
    return {name: stamp(0.2) for name in names}


def released(rows, token, paths, ledger):
    for item in rows:
        value = item.get("first_artifact_at", item.get("created_at"))
        item.update(_released=value if trending.releases.timestamp(value) else None, _basis="commit")


def run_landed(rows: list[dict], dates: dict[str, str]) -> tuple[list[str], list[str]]:
    """Run the landed lane over search rows. A repository with a code date in
    dates carries an exploit; any other is an empty placeholder the real gate
    rejects. Returns the listed names and every name the gate was asked about."""
    asked: list[str] = []

    def graphql(query: str, token: str) -> dict:
        found = gate(query, token)
        for alias, name in ALIAS.findall(query):
            asked.append(name)
            if name not in dates:
                found[alias] = EMPTY
        return found

    def released_dates(rows, token, paths, ledger):
        for row in rows:
            row.update(_released=dates[row["name"]], _basis="commit")

    with patch.multiple(trending, search=lambda query, **kwargs: (len(rows), rows), load_reviews=lambda: [], graphql=graphql, release_dates=released_dates,
                        published_repositories=lambda rows: rows), \
            redirect_stdout(io.StringIO()):
        listed = trending.just_landed("", {})
    return [found["name"] for found in listed], asked


def pushed_rows(owner: str, first: int, count: int, created: float, newest: float) -> list[dict]:
    """Repositories created days ago, last pushed from newest days ago, older by
    a quarter hour each."""
    return [
        dict(repo(f"{owner}/CVE-2025-{first + i}", stamp(created)), pushed_at=stamp(newest + 0.01 * i))
        for i in range(count)
    ]


class JustLandedTests(unittest.TestCase):
    def test_lists_new_repositories_for_any_cve_year_once(self) -> None:
        rows = [
            repo("example/CVE-2019-0708-poc", stamp(1)),
            dict(repo("example/CVE-2021-44228-rce", stamp(400)), first_artifact_at=stamp(0.5)),
            repo("example/cve-exploits", stamp(1), description="Exploit for CVE-2021-44228"),
            repo("example/CVE-2024-1111", None),
            repo("example/CVE-2024-2222", "last week"),
            repo(f"Example/{CVE}", stamp(1), stars=5),
            repo(f"example/{CVE.lower()}", stamp(1)),
        ]
        queries: list[str] = []

        def search(query: str, **kwargs) -> tuple[int, list[dict]]:
            queries.append(query)
            return len(rows), rows

        with patch.multiple(trending, search=search, load_reviews=lambda: [], graphql=gate, release_dates=released, published_repositories=lambda rows: rows), \
                redirect_stdout(io.StringIO()):
            landed = trending.just_landed("", {})

        self.assertCountEqual(
            [found["full_name"] for found in landed],
            ["example/CVE-2019-0708-poc", "example/CVE-2021-44228-rce", "example/cve-exploits", f"Example/{CVE}"],
        )
        self.assertEqual(len(queries), 5)
        self.assertTrue(any("in:readme" in query for query in queries))
        self.assertIn("pushed:>=", queries[0])
        self.assertNotRegex(queries[0], r"created:|language:|stars:|CVE-\d{4}")

    def test_empty_placeholders_cannot_crowd_out_fresh_pocs(self) -> None:
        empty = pushed_rows("spam", 5000, 45, created=1, newest=0.01)
        real = pushed_rows("acme", 1000, 12, created=3, newest=1)
        listed, asked = run_landed(empty + real, {row["name"]: row["pushed_at"] for row in real})
        self.assertEqual(listed, [row["name"] for row in real[:trending.LANDED_ROWS]])
        self.assertEqual(len(asked), len(empty + real))

    def test_judging_stops_once_no_later_push_can_place(self) -> None:
        rows = pushed_rows("acme", 1000, 30, created=3, newest=0.01)
        listed, asked = run_landed(rows, {row["name"]: row["pushed_at"] for row in rows})
        self.assertEqual(listed, [row["name"] for row in rows[:trending.LANDED_ROWS]])
        self.assertEqual(len(asked), trending.LANDED_BATCH)

    def test_a_later_push_that_can_still_place_is_judged(self) -> None:
        # The newest pushes only touched paperwork; their code is days old.
        touched = pushed_rows("acme", 1000, 20, created=6, newest=0.01)
        newer = pushed_rows("acme", 2000, 10, created=3, newest=1)
        dates = {row["name"]: stamp(5) for row in touched}
        dates.update({row["name"]: row["pushed_at"] for row in newer})
        listed, asked = run_landed(touched + newer, dates)
        self.assertEqual(listed, [row["name"] for row in newer])
        self.assertEqual(len(asked), 30)

    def test_judging_is_capped(self) -> None:
        rows = pushed_rows("spam", 5000, trending.LANDED_LIMIT + 50, created=3, newest=0.001)
        self.assertEqual(run_landed(rows, {}), ([], [row["name"] for row in rows[:trending.LANDED_LIMIT]]))

    def test_one_failed_search_keeps_the_other_searches_candidates(self) -> None:
        rows = pushed_rows("acme", 1000, 3, created=3, newest=0.01)

        def search(query: str, **kwargs) -> tuple[int, list[dict]]:
            if "reproducer" in query:
                raise RuntimeError("GitHub returned incomplete results")
            return len(rows), rows

        with patch.multiple(trending, search=search, load_reviews=lambda: [], graphql=gate, release_dates=released,
                            published_repositories=lambda rows: rows, INCOMPLETE=[], SUMMARY=[]), \
                redirect_stdout(io.StringIO()) as log, redirect_stderr(io.StringIO()) as errors:
            listed = trending.just_landed("", {})
            lanes = list(trending.INCOMPLETE)
        self.assertCountEqual([row["full_name"] for row in listed], [row["full_name"] for row in rows])
        self.assertEqual(lanes, ["just landed"])
        self.assertIn("reproducer in:readme: RuntimeError: GitHub returned incomplete results", log.getvalue())
        self.assertIn("Traceback", errors.getvalue())

    def test_spent_budget_stops_judging_and_keeps_the_rows_already_found(self) -> None:
        real = pushed_rows("acme", 1000, 5, created=3, newest=0.01)
        empty = pushed_rows("spam", 5000, 30, created=1, newest=0.06)
        asked: list[str] = []

        def graphql(query: str, token: str) -> dict:
            if asked:
                raise trending.OutOfTime("time budget spent before a GitHub GraphQL query")
            found = gate(query, token)
            for alias, name in ALIAS.findall(query):
                asked.append(name)
                if name.startswith("CVE-2025-5"):
                    found[alias] = EMPTY
            return found

        with patch.multiple(trending, search=lambda query, **kwargs: (35, real + empty), load_reviews=lambda: [],
                            graphql=graphql, release_dates=released, published_repositories=lambda rows: rows,
                            INCOMPLETE=[], SUMMARY=[]), \
                redirect_stdout(io.StringIO()) as log:
            listed = trending.just_landed("", {})
            lanes = list(trending.INCOMPLETE)
        self.assertCountEqual([row["name"] for row in listed], [row["name"] for row in real])
        self.assertEqual((len(asked), lanes), (trending.LANDED_BATCH, ["just landed"]))
        self.assertIn("kept 5 rows from 20 judged candidates", log.getvalue())

    def test_readme_only_cve_is_classified_for_the_requested_year(self) -> None:
        candidate = repo("researcher/widget-poc", stamp(1), stars=100)
        content = {"readmeMd": {"text": f"PoCs for {CVE}. Related CVE-2025-9999."},
                   "root": {"entries": [{"name": "poc.py", "type": "blob"}]}}
        with patch.object(trending, "graphql", return_value={"r0": content}):
            accepted, paths = trending.qualifying_repositories([{**candidate, "_year": NOW.year}], "test")
        self.assertEqual([row["cve"] for row in accepted], [CVE])
        self.assertIn("poc.py", paths[candidate["full_name"]])

    def test_description_cve_does_not_bypass_defensive_checker_gate(self) -> None:
        candidate = repo("researcher/widget-checker", stamp(1), stars=500,
                         description=f"Version checker for {CVE}")
        content = {"readmeMd": {"text": f"Checks installed version for {CVE}"},
                   "root": {"entries": [{"name": "check.py", "type": "blob"}]}}
        with patch.object(trending, "graphql", return_value={"r0": content}):
            accepted, _ = trending.qualifying_repositories([candidate], "test")
        self.assertEqual(accepted, [])

    def test_topic_only_cve_is_classified_with_the_same_poc_gate(self):
        candidate = repo('researcher/widget-poc', stamp(1), stars=5, description='Proof of concept')
        candidate['topics'] = [CVE.lower()]
        content = {'readmeMd': {'text': 'Reproduction instructions'},
                   'root': {'entries': [{'name': 'poc.py', 'type': 'blob'}]}}
        with patch.object(trending, 'graphql', return_value={'r0': content}):
            accepted, _ = trending.qualifying_repositories([candidate], 'test')
        self.assertEqual([row['cve'] for row in accepted], [CVE])
        candidate = repo('researcher/widget-checker', stamp(1), stars=5, description='Version checker')
        candidate['topics'] = [CVE.lower()]
        with patch.object(trending, 'graphql', return_value={'r0': content}):
            accepted, _ = trending.qualifying_repositories([candidate], 'test')
        self.assertEqual(accepted, [])

    def test_preferred_readme_retains_its_real_release_path(self):
        candidate = repo('researcher/widget-poc', stamp(1), stars=5)
        content = {'root': {'entries': [{'name': 'Readme.md', 'type': 'blob'}]},
                   'readmeTitle': {'text': f'PoC for {CVE}:\n```sh\ncurl -d "trigger=1" http://localhost/\n```'}}
        with patch.object(trending, 'graphql', return_value={'r0': content}) as fetch:
            accepted, paths = trending.qualifying_repositories([candidate], 'test')
        fetch.assert_called_once()
        self.assertIn('HEAD:Readme.md', fetch.call_args.args[0])
        self.assertEqual([row['cve'] for row in accepted], [CVE])
        self.assertEqual(paths[candidate['full_name']], ['Readme.md'])

    def test_collection_metadata_cannot_assign_shared_stars_to_one_cve(self) -> None:
        candidate = repo("researcher/mixed-pocs", stamp(1), stars=900,
                         description=f"Research PoCs including {CVE}")
        content = {"readmeMd": {"text": f"PoCs for {CVE}. " + " ".join(
            f"CVE-{year}-1234" for year in range(2019, 2025))},
            "root": {"entries": [{"name": "exploit.py", "type": "blob"}]}}
        with patch.object(trending, "graphql", return_value={"r0": content}):
            accepted, paths = trending.qualifying_repositories([candidate], "test")
        self.assertEqual((accepted, paths), ([], {}))

    def test_dedicated_cve_with_related_references_keeps_its_homepage_row(self) -> None:
        candidate = repo(f"researcher/{CVE}", stamp(1), stars=900)
        content = {"readmeMd": {"text": f"PoC for {CVE}. Related: " + " ".join(
            f"CVE-{year}-1234" for year in range(2019, 2025))},
            "root": {"entries": [{"name": "exploit.py", "type": "blob"}]}}
        with patch.object(trending, "graphql", return_value={"r0": content}):
            accepted, _ = trending.qualifying_repositories([candidate], "test")
        self.assertEqual([row["cve"] for row in accepted], [CVE])

    def test_collection_can_publish_a_reviewed_artifact_without_shared_stars(self) -> None:
        from source_artifacts import ArtifactEvidence
        candidate = repo("researcher/mixed-pocs", stamp(1), stars=900)
        artifact = ArtifactEvidence(CVE, candidate["full_name"], "specific/reproduce.py",
                                    "a" * 40, "b" * 64, "test-review")
        content = {"readmeMd": {"text": f"PoCs for {CVE}. " + " ".join(
            f"CVE-{year}-1234" for year in range(2019, 2025))},
            "root": {"entries": [{"name": "specific", "type": "tree"}]}}
        def attach(target, *args, **kwargs):
            target["_source_artifacts"] = (artifact,)
        with patch.object(trending, "graphql", return_value={"r0": content}), \
                patch.object(trending, "attach_source_artifacts", side_effect=attach):
            accepted, paths = trending.qualifying_repositories([candidate], "test")
        self.assertEqual(accepted[0]["cve"], CVE)
        self.assertEqual(accepted[0]["_artifact_url"], artifact.url)
        self.assertEqual(paths[candidate["full_name"]], [artifact.path])

    def test_landed_readme_cve_follows_artifact_then_first_mention(self) -> None:
        candidate = repo("researcher/widget-poc", stamp(1), stars=100)
        for path, expected in [("poc.py", CVE), ("CVE-2025-9999.py", "CVE-2025-9999")]:
            content = {"readmeMd": {"text": f"PoCs for {CVE}. Related CVE-2025-9999."},
                       "root": {"entries": [{"name": path, "type": "blob"}]}}
            with patch.object(trending, "graphql", return_value={"r0": content}):
                accepted, _ = trending.qualifying_repositories([dict(candidate)], "test")
            self.assertEqual(accepted[0]["cve"], expected)

    def test_cve_identity_never_truncates_long_or_malformed_numbers(self) -> None:
        self.assertEqual(trending.cve_of({"name": "CVE-2026-12345678"}), "CVE-2026-12345678")
        self.assertEqual(trending.cve_of({"name": "CVE-2026-10961x"}), "")
        self.assertEqual(trending.cve_of({"name": "CVE-2026-01234"}), "")

    def test_readme_noise_cannot_displace_metadata_candidates(self) -> None:
        noise = [repo(f"notes/project-{i}", stamp(1), description="General examples")
                 for i in range(trending.LANDED_LIMIT + 10)]
        real = dict(repo(f"researcher/{CVE}", stamp(1)), pushed_at=stamp(0.5))
        listed, _ = run_landed([*noise, real], {real["name"]: stamp(0.6)})
        self.assertEqual(listed, [real["name"]])

    def test_reviewed_alias_is_searched_without_a_cve_in_its_name(self) -> None:
        row = repo("researcher/widget-alias", stamp(1))
        def search(query):
            return (1, [row]) if 'user:researcher' in query else (0, [])
        with patch.object(trending, "load_reviews", return_value=[{"cve": CVE, "repository": row["full_name"]}]), \
                patch.object(trending, "search", side_effect=search):
            _, found = trending.search_candidates(f"CVE-{NOW.year}", "stars:>2")
        self.assertEqual(found, [row])


class ReleaseEvidenceTests(unittest.TestCase):
    def test_publication_check_uses_the_real_helper_contract(self):
        rows = [repo("example/CVE-2024-1234", stamp(1))]
        with patch.object(trending, "ensure_cve_entries", autospec=True, return_value=(set(), set())) as ensure:
            self.assertEqual(trending.published_repositories(rows), rows)
        ensure.assert_called_once_with({"CVE-2024-1234"}, dry_run=False)

    def test_existing_rejected_records_are_excluded_before_publication(self):
        import build_site
        rows = [repo("owner/CVE-1999-1056", stamp(1)), repo("owner/CVE-2024-1234", stamp(1))]
        with patch.object(build_site, "load_metadata", return_value={"CVE-1999-1056": {"rejected": True}}), \
                patch.object(trending, "ensure_cve_entries", autospec=True, return_value=(set(), set())) as ensure:
            self.assertEqual(trending.published_repositories(rows), rows[1:])
        ensure.assert_called_once_with({"CVE-2024-1234"}, dry_run=False)

    def test_history_budget_defers_without_inventing_dates_and_resumes_later(self):
        rows = [dict(repo(f"owner/CVE-2024-{number}", stamp(50)), revision="a" * 40) for number in (1234, 1235)]
        paths = {row["full_name"]: ["exploit.py"] for row in rows}
        ledger = trending.releases.Ledger()
        evidence = {"commit": stamp(1), "commit_verified": True, "created": stamp(50),
                    "history_version": trending.releases.HISTORY_VERSION}
        with patch.object(trending.releases, "current_repository_evidence", return_value=evidence) as inspect:
            with patch.object(trending, "HISTORY_REMAINING", 1):
                trending.release_dates(rows, "test", paths, ledger)
            first = ledger[trending.releases.key("CVE-2024-1234", rows[0]["html_url"])]
            pending = ledger[trending.releases.key("CVE-2024-1235", rows[1]["html_url"])]
            self.assertEqual(first["released"], stamp(1))
            self.assertIsNone(pending["released"])
            self.assertNotIn("checked", pending)
            with patch.object(trending, "HISTORY_REMAINING", 1):
                trending.release_dates(rows, "test", paths, ledger)
            self.assertEqual(inspect.call_count, 2)
            self.assertTrue(all(row["released"] == stamp(1) for row in ledger.values()))

    def test_history_that_cannot_finish_within_the_budget_waits_for_the_next_run(self):
        row = dict(repo("owner/CVE-2024-1234", stamp(50)), revision="a" * 40)
        ledger = trending.releases.Ledger()
        with patch.object(trending.releases, "current_repository_evidence") as inspect, \
                patch.multiple(trending, HISTORY_REMAINING=40,
                               DEADLINE=trending.time.monotonic() + trending.HISTORY_SECONDS / 2):
            trending.release_dates([row], "test", {row["full_name"]: ["exploit.py"]}, ledger)
        inspect.assert_not_called()
        held = ledger[trending.releases.key("CVE-2024-1234", row["html_url"])]
        self.assertIsNone(held["released"])
        self.assertNotIn("checked", held)

    def test_qualified_observation_keeps_tombstone_until_publication(self):
        row = dict(repo("owner/CVE-2024-1234", stamp(50)), revision="a" * 40)
        ledger = trending.releases.Ledger()
        original = trending.releases.record(ledger, "CVE-2024-1234", row["html_url"],
                                           {"commit": stamp(1), "commit_verified": True,
                                            "history_version": trending.releases.HISTORY_VERSION})
        original["gone"] = stamp(0.5)
        original["gone_reason"] = "unavailable"
        seen = original["seen"]
        with patch.object(trending.releases, "current_repository_evidence") as inspect:
            trending.release_dates([row], "test", {row["full_name"]: ["exploit.py"]}, ledger)
        inspect.assert_not_called()
        restored = ledger[trending.releases.key("CVE-2024-1234", row["html_url"])]
        self.assertEqual(restored["gone_reason"], "unavailable")
        self.assertIn("gone", restored)
        self.assertEqual((restored["seen"], restored["released"]), (seen, stamp(1)))
        ledger = trending.releases.reconcile(ledger, [("CVE-2024-1234", row["html_url"])])
        published = ledger[trending.releases.key("CVE-2024-1234", row["html_url"])]
        self.assertNotIn("gone", published)
        self.assertEqual((published["seen"], published["released"]), (seen, stamp(1)))

    def test_same_head_failure_cools_down_without_turning_created_into_release(self):
        row = dict(repo("owner/CVE-2024-1234", stamp(1)), revision="a" * 40)
        ledger = trending.releases.Ledger()
        evidence = {"created": stamp(1), "error": "temporary timeout"}
        with patch.object(trending.releases, "current_repository_evidence", return_value=evidence) as inspect, \
                patch.object(trending, "HISTORY_REMAINING", 40):
            trending.release_dates([row], "test", {row["full_name"]: ["exploit.py"]}, ledger)
            trending.release_dates([row], "test", {row["full_name"]: ["exploit.py"]}, ledger)
        self.assertEqual(inspect.call_count, 1)
        held = ledger[trending.releases.key("CVE-2024-1234", row["html_url"])]
        self.assertIsNone(held["released"])
        self.assertEqual(held["basis"], "pending")

    def test_failed_old_method_refresh_cools_down_without_discarding_valid_date(self):
        row = dict(repo("owner/CVE-2024-1234", stamp(50)), revision="a" * 40)
        paths = {row["full_name"]: ["exploit.py"]}
        ledger = trending.releases.Ledger()
        original = trending.releases.record(ledger, "CVE-2024-1234", row["html_url"],
                    {"commit": stamp(20), "commit_verified": True,
                     "history_version": trending.releases.HISTORY_VERSION - 1})
        identity = trending.releases.key("CVE-2024-1234", row["html_url"])
        provenance = original["seen"], original["released"], original["basis"]
        with patch.object(trending.releases, "current_repository_evidence", return_value={"error": "timeout"}) as inspect, \
                patch.multiple(trending, HISTORY_REMAINING=40, HISTORY_RETRY_HOURS=4):
            trending.release_dates([row], "test", paths, ledger)
            ledger[identity]["checked"] = stamp(1 / 24)
            trending.release_dates([row], "test", paths, ledger)
            self.assertEqual(inspect.call_count, 1)
            self.assertEqual(ledger[identity]["checked"], stamp(1 / 24))
            with patch.object(trending, "HISTORY_RETRY_HOURS", 0):
                trending.release_dates([row], "test", paths, ledger)
            self.assertEqual(inspect.call_count, 2)
            row["revision"] = "b" * 40
            trending.release_dates([row], "test", paths, ledger)
            self.assertEqual(inspect.call_count, 3)
            ledger[identity]["checked"] = stamp(1)
            trending.release_dates([row], "test", paths, ledger)
            self.assertEqual(inspect.call_count, 4)
        held = ledger[identity]
        self.assertEqual((held["seen"], held["released"], held["basis"]), provenance)
        self.assertEqual(held["history_version"], trending.releases.HISTORY_VERSION - 1)

    def test_reused_or_deferred_history_does_not_record_an_attempt(self):
        for method, budget in ((trending.releases.HISTORY_VERSION, 40), (trending.releases.HISTORY_VERSION - 1, 0)):
            with self.subTest(method=method, budget=budget):
                row = dict(repo("owner/CVE-2024-1234", stamp(50)), revision="b" * 40)
                ledger = trending.releases.Ledger()
                trending.releases.record(ledger, "CVE-2024-1234", row["html_url"],
                            {"commit": stamp(20), "commit_verified": True, "history_version": method,
                             "checked": stamp(1), "head": "a" * 40})
                with patch.object(trending.releases, "current_repository_evidence") as inspect, \
                        patch.object(trending, "HISTORY_REMAINING", budget):
                    trending.release_dates([row], "test", {row["full_name"]: ["exploit.py"]}, ledger)
                inspect.assert_not_called()
                held = ledger[trending.releases.key("CVE-2024-1234", row["html_url"])]
                self.assertEqual((held["checked"], held["head"]), (stamp(1), "a" * 40))
                self.assertEqual(held["released"], stamp(20))


class MainTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(trending, "remember_repository_metadata")
        self.remember = patcher.start()
        self.addCleanup(patcher.stop)

    def test_reviewed_payload_link_and_stars_match_in_readme_and_feed(self):
        row = repo(f"example/{CVE}", stamp(0.3), stars=500)
        payload = row["html_url"] + "/blob/" + "a" * 40 + "/poc/exploit.py"
        row.update(_artifact_url=payload, _released=stamp(0.3), _basis="commit")
        with tempfile.TemporaryDirectory() as tmp:
            readme, output = Path(tmp, "README.md"), Path(tmp, "trending.json")
            with patch.multiple(
                trending, README=str(readme), TRENDING=str(output), YEARS=1,
                figures=lambda: {"total_cves": 2, "with_pocs": 2, "kev": 1},
                known_exploited=lambda: set(),
                just_landed=lambda token, ledger: [dict(row)],
                search_year=lambda year, since: (1, [dict(row)]),
                qualifying_repositories=lambda rows, token: (rows, {}),
                published_repositories=lambda rows: rows,
                release_dates=released, code_pushed=shipped,
                ledger_landed=lambda ledger, rows: rows,
            ), patch.multiple(trending.releases, load_ledger=lambda: {}, save_ledger=lambda ledger: None), redirect_stdout(io.StringIO()):
                self.assertEqual(trending.main(), 0)
            text = readme.read_text()
            items = json.loads(output.read_text())
        self.assertEqual(text.count(f"]({payload})"), 2)
        self.assertNotIn(f"]({row['html_url']})", text)
        self.assertIn("500\u2b50", text)
        self.assertIn("| Repo stars |", text)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["url"], payload)
        self.assertEqual(items[0]["stars"], 500)
        self.remember.assert_called_once()
        self.assertTrue(items[0]["artifact"] and items[0]["landed"] and items[0]["trending"])

    def test_ledger_only_rows_carry_cached_zero_and_artifact_stars_into_readme_and_feed(self):
        root = 'https://github.com/owner/new'
        artifact = 'https://github.com/owner/lab/blob/main/poc.py'
        entries = [{'cve': CVE, 'desc': 'Research demonstration', 'poc': [root, artifact]}]
        ledger = {}
        for url in (root, artifact):
            trending.releases.record(ledger, CVE, url, {'commit': stamp(0.1), 'commit_verified': True},
                                     observed_at=stamp(0), import_mode=True)
        with tempfile.TemporaryDirectory() as directory:
            readme, output, cache = [Path(directory, name) for name in ('README.md', 'trending.json', 'repo_meta.json')]
            cache.write_text(json.dumps({'owner/new': [0, '2026-10-21'], 'owner/lab': [145, '2026-10-21']}))
            with patch.multiple(trending, README=str(readme), TRENDING=str(output), YEARS=1,
                                figures=lambda: {'total_cves': 2, 'with_pocs': 1, 'kev': 1},
                                known_exploited=lambda: set(), just_landed=lambda *args: [],
                                search_year=lambda *args: (0, [])), \
                    patch.multiple(build_site, REPO_META=cache, build_cve_list=lambda blocked: (entries, 1)), \
                    patch.multiple(trending.releases, load_ledger=lambda: ledger, save_ledger=lambda ledger: None), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(trending.main(), 0)
            self.assertEqual({row['url']: row['stars'] for row in json.loads(output.read_text())},
                             {root: 0, artifact: 145})
            self.assertIn('| 0\u2b50 |', readme.read_text())
            self.assertIn('| 145\u2b50 |', readme.read_text())

    def test_new_trending_repository_is_in_both_sections_and_written_once(self) -> None:
        both = repo(f"MarcusProgram/{CVE}", stamp(0.3), stars=5)
        older = repo(f"example/CVE-{NOW.year}-1000-poc", stamp(300), stars=40)
        fresh = repo("example/CVE-2019-0708-poc", stamp(1))
        with tempfile.TemporaryDirectory() as tmp:
            readme, output = Path(tmp, "README.md"), Path(tmp, "trending.json")
            with patch.multiple(
                trending,
                README=str(readme),
                TRENDING=str(output),
                figures=lambda: {"total_cves": 3, "with_pocs": 2, "kev": 1},
                known_exploited=lambda: {CVE},
                search_year=lambda year, since: (2, [dict(both), dict(older)]) if year == NOW.year else (0, []),
                search=lambda query, **kwargs: (3, [dict(fresh), dict(both), dict(older)]),
                graphql=gate,
                code_pushed=shipped,
                release_dates=released,
                published_repositories=lambda rows: rows,
                ledger_landed=lambda ledger, rows: rows,
            ), patch.multiple(trending.releases, load_ledger=lambda: {}, save_ledger=lambda ledger: None), redirect_stdout(io.StringIO()) as log:
                self.assertEqual(trending.main(), 0)
            text = readme.read_text(encoding="utf-8")
            items = json.loads(output.read_text(encoding="utf-8"))

        landed, trend = text.split("## Just landed", 1)[1].split(f"## Trending in {NOW.year}", 1)
        self.assertIn(f"]({both['html_url']})", landed)
        self.assertIn(f"]({both['html_url']})", trend)
        self.assertNotIn(older["html_url"], landed)
        self.assertCountEqual(
            [(item["url"], item.get("landed", False), item["kev"]) for item in items],
            [
                (both["html_url"], True, True),
                (older["html_url"], False, False),
                (fresh["html_url"], True, False),
            ],
        )
        self.assertIn("(3 repositories, 1 known-exploited)", log.getvalue())

    def previous_row(self, year: int, name: str, **changes) -> dict:
        cve = f"CVE-{year}-4242"
        return {"year": year, "stars": 70, "name": name, "url": f"https://github.com/example/{name}",
                "artifact": False, "shared_repository": False, "source": "github.com", "desc": "Exploit",
                "pushed": stamp(2), "released": stamp(30), "basis": "commit", "score": 1.0, "trending": True,
                "created": stamp(30), "cve": cve, "kev": False, **changes}

    def test_year_github_cannot_answer_keeps_last_runs_rows_and_is_reported(self) -> None:
        fresh = repo(f"example/{CVE}", stamp(0.3), stars=50)
        kept = self.previous_row(NOW.year - 1, "kept-poc", landed=True)
        replaced = self.previous_row(NOW.year, "replaced-poc")

        def search_year(year: int, since: str) -> tuple[int, list[dict]]:
            if year == NOW.year:
                return 1, [dict(fresh)]
            raise RuntimeError("GitHub returned incomplete results")

        with tempfile.TemporaryDirectory() as tmp:
            readme, output, summary = Path(tmp, "README.md"), Path(tmp, "trending.json"), Path(tmp, "summary.md")
            output.write_text(json.dumps([kept, replaced]))
            with patch.multiple(
                trending, README=str(readme), TRENDING=str(output), YEARS=2,
                figures=lambda: {"total_cves": 2, "with_pocs": 2, "kev": 1},
                known_exploited=lambda: {kept["cve"]},
                just_landed=lambda token, ledger: [],
                search_year=search_year,
                qualifying_repositories=lambda rows, token: (rows, {}),
                published_repositories=lambda rows: rows,
                release_dates=released, code_pushed=shipped,
                ledger_landed=lambda ledger, rows: rows,
            ), patch.multiple(trending.releases, load_ledger=lambda: {}, save_ledger=lambda ledger: None), \
                    patch.dict(trending.os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), \
                    redirect_stdout(io.StringIO()) as log, redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(trending.main(), trending.PARTIAL_EXIT)
            text = readme.read_text(encoding="utf-8")
            items = {item["url"]: item for item in json.loads(output.read_text(encoding="utf-8"))}
            report = summary.read_text(encoding="utf-8")
        self.assertIn(f"## Trending in {NOW.year - 1}", text)
        self.assertIn(f"]({kept['url']})", text)
        self.assertIn(f"]({fresh['html_url']})", text)
        self.assertNotIn(replaced["url"], text)
        self.assertEqual(set(items), {kept["url"], fresh["html_url"]})
        self.assertNotIn("landed", items[kept["url"]])
        self.assertTrue(items[kept["url"]]["kev"])
        self.assertIn("RuntimeError: GitHub returned incomplete results", errors.getvalue())
        self.assertIn(f"CVE-{NOW.year - 1} incomplete: RuntimeError", log.getvalue())
        self.assertIn("### Trending refresh incomplete", report)
        self.assertIn(f"- CVE-{NOW.year}: 1 pushed since", report)
        self.assertIn(f"- CVE-{NOW.year - 1} incomplete", report)

    def test_spent_budget_publishes_last_runs_rows_without_calling_github(self) -> None:
        kept = self.previous_row(NOW.year, "kept-poc")
        with tempfile.TemporaryDirectory() as tmp:
            readme, output = Path(tmp, "README.md"), Path(tmp, "trending.json")
            output.write_text(json.dumps([kept]))
            with patch.multiple(
                trending, README=str(readme), TRENDING=str(output), YEARS=1, FINISH_SECONDS=60, DEADLINE=None,
                figures=lambda: {"total_cves": 2, "with_pocs": 1, "kev": 1},
                known_exploited=lambda: set(), load_reviews=lambda: [],
                ledger_landed=lambda ledger, rows: rows,
            ), patch.multiple(trending.releases, load_ledger=lambda: {}, save_ledger=lambda ledger: None), \
                    patch.object(trending.request, "urlopen") as fetch, redirect_stdout(io.StringIO()) as log:
                self.assertEqual(trending.main(budget=60), trending.PARTIAL_EXIT)
            text = readme.read_text(encoding="utf-8")
            items = json.loads(output.read_text(encoding="utf-8"))
        fetch.assert_not_called()
        self.assertIn(f"]({kept['url']})", text)
        self.assertEqual([item["url"] for item in items], [kept["url"]])
        self.assertIn("just landed incomplete: OutOfTime", log.getvalue())
        self.assertIn(f"CVE-{NOW.year} incomplete: OutOfTime", log.getvalue())
        self.assertIn("incomplete: just landed, CVE-", log.getvalue())

    def test_every_ingested_collection_is_credited(self) -> None:
        for source in (*sync_collections.SOURCES, *sync_collections.TREE_SOURCES):
            self.assertIn(f"](https://github.com/{source[1]})", trending.FOOTER)

    def test_cve_summary_is_cleaned_like_repository_text(self) -> None:
        with patch.object(trending, "nvd_description", return_value="Path traversal \N{EM DASH} remote | unauthenticated"):
            self.assertEqual(
                trending.repository_summary({"description": CVE}, CVE),
                "Path traversal - remote / unauthenticated",
            )


class ArtifactDateTests(unittest.TestCase):
    def test_publisher_dates_do_not_claim_hour_precision_or_crash(self):
        self.assertEqual(trending.time_ago(stamp(3)[:10]), "3d ago")
        self.assertEqual(trending.time_ago(NOW.date().isoformat()), "0d ago")

    def test_commit_clock_cannot_postdate_the_repository_push(self) -> None:
        pushed = stamp(0.2)
        payload = {"r0": {
            "pushedAt": pushed,
            "defaultBranchRef": {"target": {
                "p0": {"nodes": [{"committedDate": stamp(-1)}]},
                "p1": {"nodes": [{"committedDate": stamp(1)}]},
            }},
        }}
        with patch.object(trending, "graphql", return_value=payload) as query:
            result = trending.code_pushed(["owner/repo"], "test", {"owner/repo": ["exploit.py", "poc.c"]})
        self.assertEqual(result, {"owner/repo": stamp(1)})
        self.assertIn("pushedAt", query.call_args.args[0])

    def test_future_timestamp_does_not_wrap_into_yesterdays_age(self) -> None:
        self.assertEqual(trending.time_ago(stamp(-0.1)), "just now")


class GraphQLTests(unittest.TestCase):
    def answer(self, payload: dict):
        return lambda req, timeout: io.BytesIO(json.dumps(payload).encode())

    def query(self) -> str:
        return "query { " + " ".join(
            trending.repository_alias(index, name, "name")
            for index, name in enumerate(["owner/missing", "owner/healthy"])
        ) + " }"

    def test_partial_operational_failures_retry_then_abort(self) -> None:
        for error in (
            {"type": "INTERNAL", "path": ["r0"]},
            {"type": "RATE_LIMITED", "path": ["r0"]},
            {"type": "NOT_FOUND", "path": ["r0", "root"]},
        ):
            payload = {"data": {"r0": None, "r1": {"name": "healthy"}}, "errors": [error]}
            with self.subTest(error=error), patch.object(trending.time, "sleep"), patch.object(
                trending.request, "urlopen", side_effect=self.answer(payload)
            ) as fetch:
                with self.assertRaises(RuntimeError):
                    trending.graphql(self.query(), "test")
                self.assertEqual(fetch.call_count, 3)

    def test_missing_alias_is_not_a_deleted_repository(self) -> None:
        with patch.object(trending.time, "sleep"), patch.object(
            trending.request, "urlopen", side_effect=self.answer({"data": {"r1": {"name": "healthy"}}})
        ) as fetch:
            with self.assertRaises(RuntimeError):
                trending.graphql(self.query(), "test")
            self.assertEqual(fetch.call_count, 3)

    def test_failed_query_is_not_read_as_repositories_without_code(self) -> None:
        limited = {"errors": [{"type": "RATE_LIMITED", "message": "API rate limit exceeded"}]}
        with patch.object(trending.time, "sleep"), patch.object(trending.request, "urlopen", self.answer(limited)):
            with self.assertRaisesRegex(RuntimeError, "rate limit"):
                trending.code_pushed(["owner/repo"], "test", {"owner/repo": ["exploit.py"]})

    def test_spent_budget_starts_no_query(self) -> None:
        with patch.object(trending, "DEADLINE", trending.time.monotonic() - 1), \
                patch.object(trending.request, "urlopen") as fetch:
            with self.assertRaises(trending.OutOfTime):
                trending.graphql(self.query(), "test")
        fetch.assert_not_called()

    def test_deleted_repository_leaves_only_that_one_out(self) -> None:
        kept = {"pushedAt": stamp(1), "defaultBranchRef": {"target": {"p0": {"nodes": []}}}}
        payload = {
            "data": {"r0": None, "r1": kept},
            "errors": [
                {"type": "NOT_FOUND", "path": ["r0"], "message": "Could not resolve to a Repository"},
            ],
        }
        with patch.object(trending.request, "urlopen", self.answer(payload)):
            self.assertEqual(trending.graphql(self.query(), "test"), {"r0": None, "r1": kept})


class SearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sleep = self.enterContext(patch.object(trending.time, "sleep"))
        self.enterContext(patch.object(trending, "SEARCH_NOT_BEFORE", 0.0))

    def replies(self, *payloads: dict) -> tuple[list[str], object]:
        urls: list[str] = []
        queue = iter(payloads)

        def urlopen(req, timeout):
            urls.append(req.full_url)
            return io.BytesIO(json.dumps(next(queue)).encode())

        return urls, urlopen

    def test_reads_every_page_in_rest_sort_order(self) -> None:
        urls, urlopen = self.replies(
            {"total_count": 101, "incomplete_results": False,
             "items": [{"full_name": f"a/{n}"} for n in range(100)]},
            {"total_count": 101, "incomplete_results": False, "items": [{"full_name": "a/100"}]},
        )
        with patch.object(trending.request, "urlopen", urlopen):
            total, found = trending.search("CVE in:name")
        self.assertEqual((total, len(found)), (101, 101))
        params = [parse_qs(urlparse(url).query) for url in urls]
        self.assertEqual(
            [(p["sort"], p["order"], p["page"]) for p in params],
            [(["updated"], ["desc"], ["1"]), (["updated"], ["desc"], ["2"])],
        )

    def test_incomplete_results_are_retried_and_never_returned(self) -> None:
        partial = {"total_count": 9, "incomplete_results": True, "items": [{"full_name": "a/b"}]}
        complete = {"total_count": 1, "incomplete_results": False, "items": [{"full_name": "a/b"}]}
        with patch.object(trending.time, "sleep"):
            _, urlopen = self.replies(partial, complete)
            with patch.object(trending.request, "urlopen", urlopen):
                self.assertEqual(trending.search("CVE in:name"), (1, [{"full_name": "a/b"}]))
            _, urlopen = self.replies(partial, partial, partial)
            with patch.object(trending.request, "urlopen", urlopen), self.assertRaises(RuntimeError):
                trending.search("CVE in:name")

    def test_rate_limit_headers_control_retry_delay(self) -> None:
        for headers, expected in [({"Retry-After": "42"}, 42),
                                  ({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1040"}, 41),
                                  ({"X-RateLimit-Remaining": "99", "X-RateLimit-Reset": "2000"}, 60)]:
            response = io.BytesIO(b'{"total_count":0,"items":[]}')
            with self.subTest(headers=headers), patch.object(trending.time, "time", return_value=1000), \
                    patch.object(trending.request, "urlopen", side_effect=[HTTPError("url", 403, "limited", headers, None), response]):
                self.sleep.reset_mock()
                self.assertEqual(trending.search("CVE in:name"), (0, []))
                self.sleep.assert_any_call(expected)

    def test_rate_limit_wait_past_the_budget_stops_instead_of_sleeping(self) -> None:
        limited = HTTPError("url", 403, "limited", {"Retry-After": "42"}, None)
        with patch.object(trending, "DEADLINE", trending.time.monotonic() + 10), \
                patch.object(trending.request, "urlopen", side_effect=[limited]) as fetch:
            with self.assertRaisesRegex(trending.OutOfTime, "42s wait"):
                trending.search("CVE in:name")
        self.assertEqual(fetch.call_count, 1)
        self.assertNotIn(42, [call.args[0] for call in self.sleep.call_args_list])

    def test_search_calls_are_paced_and_bounded(self) -> None:
        urls, urlopen = self.replies(*[
            {"total_count": 5000, "items": [{"full_name": f"a/{i + page * 100}"} for i in range(100)]}
            for page in range(3)])
        with patch.object(trending.request, "urlopen", urlopen), \
                patch.object(trending.time, "monotonic", return_value=100), \
                patch.object(trending, "github_token", return_value="token"):
            total, found = trending.search("CVE poc in:readme", limit=200)
        self.assertEqual((total, len(found), len(urls)), (5000, 200, 2))
        self.assertTrue(any(call.args[0] >= 2 for call in self.sleep.call_args_list))

    def test_year_search_keeps_its_filters_and_lists_each_repository_once(self) -> None:
        urls, urlopen = self.replies(
            {"total_count": 101, "incomplete_results": False,
             "items": [{"full_name": f"a/{n}"} for n in range(100)]},
            # An update during the read shifts the pages; the boundary row comes back.
            {"total_count": 101, "incomplete_results": False,
             "items": [{"full_name": "A/99"}, {"full_name": "a/100"}]},
            *[{"total_count": 1, "incomplete_results": False,
               "items": [{"full_name": "A/100"}]} for _ in range(4)],
        )
        with patch.object(trending.request, "urlopen", urlopen), patch.object(trending, "load_reviews", return_value=[]):
            total, found = trending.search_year(2026, "2026-07-08")
        self.assertEqual((total, len(found), found[-1]["full_name"]), (101, 101, "a/100"))
        params = parse_qs(urlparse(urls[0]).query)
        self.assertEqual((params["sort"], params["order"]), (["updated"], ["desc"]))
        self.assertNotIn("s", params)
        self.assertEqual(
            params["q"][0].split()[:4],
            ['"CVE-2026"', "in:name,description,topics", "stars:>2", "pushed:>2026-07-08"],
        )
        self.assertTrue(all(row["_year"] == 2026 for row in found))


if __name__ == "__main__":
    unittest.main()
