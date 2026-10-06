from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("getTrending", str(ROOT / ".github" / "getTrending.py"))
trending = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trending)
sys.path.insert(0, str(ROOT / "scripts"))

import sync_collections

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

    with patch.multiple(trending, search=lambda query: (len(rows), rows), graphql=graphql, release_dates=released_dates,
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

        def search(query: str) -> tuple[int, list[dict]]:
            queries.append(query)
            return len(rows), rows

        with patch.multiple(trending, search=search, graphql=gate, release_dates=released, published_repositories=lambda rows: rows), \
                redirect_stdout(io.StringIO()):
            landed = trending.just_landed("", {})

        self.assertCountEqual(
            [found["full_name"] for found in landed],
            ["example/CVE-2019-0708-poc", "example/CVE-2021-44228-rce", f"Example/{CVE}"],
        )
        self.assertEqual(len(queries), 1)
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

    def test_qualified_readd_clears_tombstone_without_resetting_release(self):
        row = dict(repo("owner/CVE-2024-1234", stamp(50)), revision="a" * 40)
        ledger = trending.releases.Ledger()
        original = trending.releases.record(ledger, "CVE-2024-1234", row["html_url"],
                                           {"commit": stamp(1), "commit_verified": True,
                                            "history_version": trending.releases.HISTORY_VERSION})
        original["gone"] = stamp(0.5)
        seen = original["seen"]
        with patch.object(trending.releases, "current_repository_evidence") as inspect:
            trending.release_dates([row], "test", {row["full_name"]: ["exploit.py"]}, ledger)
        inspect.assert_not_called()
        restored = ledger[trending.releases.key("CVE-2024-1234", row["html_url"])]
        self.assertNotIn("gone", restored)
        self.assertEqual((restored["seen"], restored["released"]), (seen, stamp(1)))

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
        self.assertNotIn("500\u2b50", text)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["url"], payload)
        self.assertIsNone(items[0]["stars"])
        self.assertTrue(items[0]["artifact"] and items[0]["landed"] and items[0]["trending"])

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
                search=lambda query: (3, [dict(fresh), dict(both), dict(older)]),
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

    def test_year_search_keeps_its_filters_and_lists_each_repository_once(self) -> None:
        urls, urlopen = self.replies(
            {"total_count": 101, "incomplete_results": False,
             "items": [{"full_name": f"a/{n}"} for n in range(100)]},
            # An update during the read shifts the pages; the boundary row comes back.
            {"total_count": 101, "incomplete_results": False,
             "items": [{"full_name": "A/99"}, {"full_name": "a/100"}]},
        )
        with patch.object(trending.request, "urlopen", urlopen):
            total, found = trending.search_year(2026, "2026-07-08")
        self.assertEqual((total, len(found), found[-1]["full_name"]), (101, 101, "a/100"))
        params = parse_qs(urlparse(urls[0]).query)
        self.assertEqual((params["sort"], params["order"]), (["updated"], ["desc"]))
        self.assertNotIn("s", params)
        self.assertEqual(
            params["q"][0].split()[:4],
            ['"CVE-2026"', "in:name", "stars:>2", "pushed:>2026-07-08"],
        )


if __name__ == "__main__":
    unittest.main()
