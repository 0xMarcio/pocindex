from __future__ import annotations

import importlib.util
import io
import json
import re
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

NOW = datetime.now(timezone.utc)
CVE = f"CVE-{NOW.year}-21589"


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
        for alias, name in re.findall(r'(r\d+): repository\(owner: "[^"]*", name: "([^"]*)"\)', query)
    }


def shipped(names: list[str], token: str, paths: dict | None = None) -> dict[str, str]:
    return {name: stamp(0.2) for name in names}


class JustLandedTests(unittest.TestCase):
    def test_lists_new_repositories_for_any_cve_year_once(self) -> None:
        rows = [
            repo("example/CVE-2019-0708-poc", stamp(1)),
            repo("example/CVE-2021-44228-rce", stamp(400)),
            repo("example/cve-exploits", stamp(1), description="Exploit for CVE-2021-44228"),
            repo("example/CVE-2024-1111", None),
            repo("example/CVE-2024-2222", "last week"),
            repo(f"Example/{CVE}", stamp(1), stars=5),
            repo(f"example/{CVE.lower()}", stamp(1)),
        ]
        queries: list[str] = []

        def search(query: str) -> list[dict]:
            queries.append(query)
            return rows

        with patch.multiple(trending, search=search, graphql=gate, code_pushed=shipped), \
                redirect_stdout(io.StringIO()):
            landed = trending.just_landed("")

        self.assertCountEqual(
            [found["full_name"] for found in landed],
            ["example/CVE-2019-0708-poc", f"Example/{CVE}"],
        )
        self.assertEqual(len(queries), 1)
        self.assertIn("created:>=", queries[0])
        self.assertNotRegex(queries[0], r"pushed:|CVE-\d{4}")


class MainTests(unittest.TestCase):
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
                search=lambda query: [dict(fresh), dict(both), dict(older)],
                graphql=gate,
                code_pushed=shipped,
            ), redirect_stdout(io.StringIO()) as log:
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


class ArtifactDateTests(unittest.TestCase):
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
        self.assertEqual(result, {"owner/repo": pushed})
        self.assertIn("pushedAt", query.call_args.args[0])

    def test_future_timestamp_does_not_wrap_into_yesterdays_age(self) -> None:
        self.assertEqual(trending.time_ago(stamp(-0.1)), "just now")


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
            self.assertEqual(len(trending.search("CVE in:name")), 101)
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
                self.assertEqual(trending.search("CVE in:name"), [{"full_name": "a/b"}])
            _, urlopen = self.replies(partial, partial, partial)
            with patch.object(trending.request, "urlopen", urlopen), self.assertRaises(RuntimeError):
                trending.search("CVE in:name")


if __name__ == "__main__":
    unittest.main()
