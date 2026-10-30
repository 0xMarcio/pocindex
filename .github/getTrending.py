#!/usr/bin/env python3
"""Rebuild README.md with the most recently updated CVE proof-of-concept repositories."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import traceback
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib import error, parse, request

SEARCH_URL = "https://api.github.com/search/repositories"
GRAPHQL_URL = "https://api.github.com/graphql"
PAPERWORK = re.compile(
    r"^(?:readme|licen[cs]e|copying|notice|authors|contributing|code_of_conduct"
    r"|security|changelog|history|\.git|\.editorconfig|\.pre-commit)",
    re.IGNORECASE,
)
PATHS_PER_REPO = 12
YEARS = 5
PER_YEAR = 20
SEARCH_PAGE = 100
SEARCH_LIMIT = 1000
WINDOW_DAYS = 90
MIN_STARS = 2
LANDED_DAYS = 10
LANDED_ROWS = 10
LANDED_BATCH = 20
LANDED_LIMIT = 200
HISTORY_LIMIT = 40
HISTORY_REMAINING = HISTORY_LIMIT
HISTORY_RETRY_HOURS = 4
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_LOOKUPS = 4
# Reserve time for in-flight requests and atomic writes.
FINISH_SECONDS = 90
HISTORY_SECONDS = 45
# EX_TEMPFAIL: partial results were published.
PARTIAL_EXIT = 75
DEADLINE: float | None = None
INCOMPLETE: list[str] = []
SUMMARY: list[str] = []
USER_AGENT = "0xMarcio-cve-trending"
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import BRAND, DESCRIPTION, SEARCH_GUIDE, SITE, SLUG
from update_cves import (load_blacklist, qualifying_repo_cves, attach_source_artifacts, ensure_cve_entries,
                         repository_is_nonpublic, discovery_search_terms, extract_cves, readme_text,
                         root_has_cve_artifact, is_valid_cve, topic_names, README_FIELDS, README_PATHS)
import releases
from source_artifacts import reviewed_artifacts, reviewed_cves, load_reviews, identity_cves
from sync_repo_metadata import remember as remember_repository_metadata

README = os.path.join(ROOT, "README.md")
TRENDING = os.path.join(ROOT, "index", "trending.json")
KEV = os.path.join(ROOT, "index", "kev.json")
STATS = os.path.join(ROOT, "docs", "stats.json")
DESC_LIMIT = 110
FOLDED_AFTER = 2   # years past the newest two are collapsed behind a summary
CVE_ID = re.compile(r"(?<![A-Z0-9])CVE[-_](\d{4})[-_](\d{4,})(?![A-Z0-9])", re.IGNORECASE)
SEARCH_NOT_BEFORE = 0.0
RAW = f"https://raw.githubusercontent.com/{SLUG}/main/docs"
HERO_URL = f"{RAW}/hero.svg"
SEARCH_CTA_REV = "8dec6181e823d641132e0ee8a52a1612c2b5dd37"
SEARCH_CTA_URL = f"https://raw.githubusercontent.com/{SLUG}/{SEARCH_CTA_REV}/docs/search.svg"
KEV_MARK = f'<img src="{RAW}/kev.svg" alt="KEV" title="CISA known exploited" height="14"> '


class OutOfTime(RuntimeError):
    pass


def time_left() -> float:
    return float("inf") if DEADLINE is None else DEADLINE - time.monotonic()


def pause(seconds: float, what: str) -> None:
    seconds, left = max(0.0, seconds), time_left()
    if left <= seconds:
        raise OutOfTime(f"time budget spent before {what}" if left <= 0 else
                        f"{what} needs a {seconds:.0f}s wait with {left:.0f}s of the budget left")
    time.sleep(seconds)


def note(line: str) -> None:
    print(line)
    SUMMARY.append(line)


def incomplete(lane: str, problem: BaseException | str, kept: str) -> None:
    if isinstance(problem, BaseException):
        if not isinstance(problem, OutOfTime):
            traceback.print_exception(problem)
        problem = f"{type(problem).__name__}: {problem}"
    INCOMPLETE.append(lane)
    note(f"{lane} incomplete: {problem}; {kept}")


def search(query: str, *, limit: int = SEARCH_LIMIT) -> tuple[int, list[dict]]:
    """How many repositories a search matches, and every one it exposes, most
    recently updated first."""
    if "is:public" not in query.split():
        query += " is:public"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    # The token authenticates the API only; it is never placed in the URL,
    # written to disk, or printed, so it cannot leak through logs or the commit.
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    found: list[dict] = []
    seen: set[str] = set()
    total = 0
    global SEARCH_NOT_BEFORE
    limit = min(limit, SEARCH_LIMIT)
    for page in range(1, (limit + SEARCH_PAGE - 1) // SEARCH_PAGE + 1):
        # The REST API reads sort and order. The website's s and o are ignored
        # and leave the results in best-match order.
        url = SEARCH_URL + "?" + parse.urlencode({
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": SEARCH_PAGE,
            "page": page,
        })
        for attempt in range(3):
            delay = 5 * (attempt + 1)
            pause(SEARCH_NOT_BEFORE - time.monotonic(), "a GitHub search")
            SEARCH_NOT_BEFORE = time.monotonic() + (2.1 if token else 6.1)
            try:
                with request.urlopen(request.Request(url, headers=headers), timeout=30) as response:
                    payload = json.load(response)
            except error.HTTPError as problem:
                if problem.code not in {403, 429, 500, 502, 503, 504} or attempt == 2:
                    raise
                if problem.code in {403, 429}:
                    limits = problem.headers or {}
                    try:
                        if limits.get("Retry-After"):
                            delay = max(delay, float(limits["Retry-After"]))
                        elif str(limits.get("X-RateLimit-Remaining")) == "0" and limits.get("X-RateLimit-Reset"):
                            delay = max(delay, float(limits["X-RateLimit-Reset"]) - time.time() + 1)
                        else:
                            delay = max(delay, 60 * 2 ** attempt)
                    except (TypeError, ValueError):
                        delay = max(delay, 60)
            except (error.URLError, TimeoutError, json.JSONDecodeError):
                if attempt == 2:
                    raise
            else:
                # A search that runs out of time still answers, with whatever
                # it had found so far.
                if not payload.get("incomplete_results"):
                    break
                if attempt == 2:
                    raise RuntimeError(f"GitHub returned incomplete results for {query}")
            pause(delay, "a GitHub search retry")
        total = int(payload.get("total_count") or 0)
        items = payload.get("items") or []
        for repo in items:
            # Results shift between pages while they are read, so a repository
            # can come back twice; GitHub names are case-insensitive.
            name = str(repo.get("full_name") or "").lower()
            if name and name not in seen and not repository_is_nonpublic(repo):
                seen.add(name)
                found.append(repo)
        if not items or len(found) >= min(total, limit):
            break
    return total, found[:limit]


def nvd_description(cve: str) -> str:
    """The CVE's own summary, for a repository that shipped without one.

    A row reading only "CVE-2026-40179" tells nobody what landed. The index
    already holds the NVD text for that id, so it stands in.
    """
    if not cve:
        return ""
    path = os.path.join(ROOT, "cves", cve.split("-")[1], f"{cve}.md")
    try:
        with open(path, encoding="utf-8") as handle:
            body = handle.read()
    except OSError:
        return ""
    start = body.find("### Description")
    if start < 0:
        return ""
    block = body[start + len("### Description"):]
    end = block.find("\n###")
    text = block[:end if end > 0 else len(block)]
    return " ".join(text.split())


def nvd_lookup(cve: str) -> str:
    """Ask NVD directly for a CVE the index has not caught up with yet.

    The newest exploits are for the newest CVEs, which is exactly when the
    daily sync has not run and the local summary does not exist.
    """
    url = NVD_API + parse.quote(cve)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        with request.urlopen(request.Request(url, headers=headers), timeout=20) as response:
            payload = json.load(response)
        for item in payload.get("vulnerabilities") or []:
            for entry in item.get("cve", {}).get("descriptions") or []:
                if entry.get("lang") == "en" and entry.get("value"):
                    return " ".join(str(entry["value"]).split())
    except Exception as problem:
        print(f"NVD lookup for {cve} failed: {problem}")
    return ""


def published_repositories(repositories: list[dict]) -> list[dict]:
    from build_site import load_metadata
    metadata = load_metadata()
    repositories = [repo for repo in repositories if not (metadata.get(cve_of(repo)) or {}).get("rejected")]
    _, unavailable = ensure_cve_entries({cve_of(repo) for repo in repositories if cve_of(repo)}, dry_run=False)
    return [repo for repo in repositories if cve_of(repo) not in unavailable]


def release_dates(repositories: list[dict], token: str, paths: dict[str, list[str]],
                  ledger: dict) -> None:
    """Resolve first qualifying content once, retaining the evidence across runs."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    global HISTORY_REMAINING
    now = releases.utcnow()
    queued, reused = [], []
    for repo in repositories:
        cve = cve_of(repo)
        url = repo.get("_artifact_url") or repo["html_url"]
        old = ledger.get(releases.key(cve, url), {})
        checked = releases.timestamp(old.get("checked"))
        dated = (old.get("commit_verified") and old.get("released")
                 and (old.get("history_version") or 0) >= releases.HISTORY_VERSION)
        cooling = (not dated and HISTORY_RETRY_HOURS > 0 and old.get("head") == repo.get("revision")
                   and checked and datetime.now(timezone.utc) - checked < timedelta(hours=HISTORY_RETRY_HOURS))
        if dated or cooling:
            reused.append((repo, url, None))
        elif HISTORY_REMAINING <= 0:
            reused.append((repo, url, {"error": "History inspection deferred", "deferred": True}))
        else:
            HISTORY_REMAINING -= 1
            queued.append((repo, url))

    def inspect(candidate):
        repo, url = candidate
        if time_left() < HISTORY_SECONDS:
            return repo, url, {"error": "History inspection deferred", "deferred": True}
        evidence = releases.current_repository_evidence(
            repo, paths.get(repo["full_name"], []), headers, cve=cve_of(repo),
        )
        return repo, url, evidence

    with ThreadPoolExecutor(max_workers=4) as pool:
        inspected = list(pool.map(inspect, queued)) + reused
    for repo, url, evidence in inspected:
        identity = releases.key(cve_of(repo), url)
        row = releases.record(ledger, cve_of(repo), url, evidence)
        if evidence is not None and not evidence.get("deferred"):
            row.update(checked=now, head=repo.get("revision"))
    releases.resolve_copies(ledger)
    releases.mark_bulk(ledger)
    for repo, url, _ in inspected:
        row = ledger[releases.key(cve_of(repo), url)]
        repo.update(_released=row.get("released"), _basis=row.get("basis"),
                    _copy=bool(row.get("copy")), _bulk=bool(row.get("bulk")))


def search_candidates(identifier: str, filters: str, *,
                      failures: list[str] | None = None) -> tuple[int, list[dict]]:
    """Collect candidates; optionally retain successful queries after a failure."""
    found = {}
    queries = discovery_search_terms(identifier)
    aliases = {row["repository"] for row in load_reviews()
               if row["cve"].startswith(identifier + "-") and not identity_cves(row["repository"])}
    for name in sorted(aliases):
        owner, repository = name.split("/", 1)
        queries.append(f'"{repository}" in:name user:{owner}')
    for terms in queries:
        query = f"{terms} {filters} fork:false"
        # The landed README lane can judge at most this many recent rows.
        # Keep the full search window for per-year trending candidates.
        try:
            _, rows = search(query, limit=LANDED_LIMIT) if identifier == "CVE" and "in:readme" in terms else search(query)
        except OutOfTime:
            raise
        except Exception as problem:
            if failures is None:
                raise
            traceback.print_exception(problem)
            failures.append(f"{terms}: {type(problem).__name__}: {problem}")
            continue
        print(f"Discovery {terms}: {len(rows)} candidates")
        for repo in rows:
            name = str(repo.get("full_name") or "").lower()
            if name:
                found.setdefault(name, repo)
    return len(found), list(found.values())


def just_landed(token: str, ledger: dict | None = None) -> list[dict]:
    """First qualifying artifact releases, independently of stars or Trending."""
    ledger = releases.load_ledger() if ledger is None else ledger
    started = time.monotonic()
    cutoff = datetime.now(timezone.utc) - timedelta(days=LANDED_DAYS)
    since = cutoff.date().isoformat()
    failures: list[str] = []
    try:
        _, rows = search_candidates("CVE", f"pushed:>={since}", failures=failures)
    except OutOfTime as problem:
        incomplete("just landed", problem, "listed from the release ledger alone")
        return []
    if failures:
        incomplete("just landed", "; ".join(failures), "judged the other searches' candidates")
    candidates, seen = [], set()
    for repo in rows:
        name = str(repo.get("full_name") or "")
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        candidates.append(repo)
    candidates.sort(key=lambda repo: str(repo.get("pushed_at") or ""), reverse=True)
    # README matches include many general repositories. Give that lane its
    # own budget so it cannot displace the name/description candidates.
    pool = [repo for repo in candidates if cve_of(repo)][:LANDED_LIMIT]
    pool += [repo for repo in candidates if not cve_of(repo)][:LANDED_LIMIT]
    pool.sort(key=lambda repo: str(repo.get("pushed_at") or ""), reverse=True)
    fresh: list[dict] = []
    judged = rejected = undated = 0
    for start in range(0, len(pool), LANDED_BATCH):
        if len(fresh) >= LANDED_ROWS and (
            str(pool[start].get("pushed_at") or "") <= fresh[LANDED_ROWS - 1]["_released"]
        ):
            break
        batch = pool[start:start + LANDED_BATCH]
        try:
            accepted, paths = qualifying_repositories(batch, token)
            accepted = published_repositories(accepted)
            release_dates(accepted, token, paths, ledger)
        except Exception as problem:
            incomplete("just landed", problem, f"kept {len(fresh)} rows from {judged} judged candidates")
            break
        judged += len(batch)
        rejected += len(batch) - len(accepted)
        for repo in accepted:
            released = releases.timestamp(repo.get("_released"))
            if released is None:
                undated += 1
            elif cutoff <= released <= datetime.now(timezone.utc) and not repo.get("_copy") and not repo.get("_bulk"):
                fresh.append(repo)
        fresh.sort(key=lambda repo: repo["_released"], reverse=True)
    note(f"just landed: {judged} of {len(candidates)} candidates judged, "
         f"{len(fresh)} qualified, {rejected} rejected, {undated} awaiting release evidence "
         f"in {time.monotonic() - started:.0f}s")
    return fresh[:LANDED_ROWS]


def ledger_landed(ledger: dict, candidates: list[dict]) -> list[dict]:
    import link_health
    from build_site import build_cve_list, build_landed, dedupe_source_links, source_key, CURATED, REPO_META
    entries, _ = build_cve_list(load_blacklist())
    published = {entry["cve"]: entry for entry in entries}
    metadata = json.loads(REPO_META.read_text(encoding="utf-8"))
    rows = {}
    for item in build_landed(entries, metadata, known_exploited(), ledger):
        rows[releases.key(item["cve"], item["url"])] = {
            "cve": item["cve"], "name": item["name"], "html_url": item["url"],
            "description": item["desc"], "stargazers_count": item["stars"],
            "_released": item["released"], "_basis": item["basis"],
        }
    for repo in candidates:
        cve = cve_of(repo)
        url = repo.get("_artifact_url") or repo["html_url"]
        if link_health.unavailable(url):
            continue
        entry = published.get(cve, {})
        curated = [link for _, field in CURATED for link in entry.get(field, [])
                   if source_key(link) == source_key(url)]
        if curated and releases.key(cve, url) not in {releases.key(cve, link) for link in curated}:
            continue
        siblings = [link for link in entry.get("poc", []) if source_key(link) == source_key(url)]
        identity = releases.key(cve, url)
        if identity not in {releases.key(cve, link) for link in dedupe_source_links([*siblings, url], cve)}:
            continue
        current = ledger.get(identity, {})
        if any(current.get(flag) for flag in ("copy", "gone", "bulk")):
            continue
        if not curated:
            rows = {other: item for other, item in rows.items()
                    if other == identity or cve_of(item) != cve
                    or source_key(item.get("_artifact_url") or item["html_url"]) != source_key(url)}
        rows[identity] = repo
    return sorted(rows.values(), key=lambda repo: repo["_released"], reverse=True)[:LANDED_ROWS]


def star_cell(value: int | None) -> str:
    return f"{value}\u2b50" if value is not None else "N/A"


def artifact_link(repo: dict) -> tuple[str, bool]:
    url = repo.get("_artifact_url") or repo.get("html_url") or ""
    parsed = parse.urlsplit(url)
    artifact = parsed.hostname != "github.com" or len(parsed.path.strip("/").split("/")) != 2
    return url, artifact


def search_year(year: int, since: str) -> tuple[int, list[dict]]:
    """Return how many PoC repositories for one CVE year were pushed since a
    date, and every result GitHub exposes for the final artifact-date sort.
    """
    total, rows = search_candidates(f"CVE-{year}", f"stars:>{MIN_STARS} pushed:>{since}")
    for row in rows:
        row["_year"] = year
    return total, rows


def github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def graphql(query: str, token: str) -> dict:
    body = json.dumps({"query": query}).encode("utf-8")
    aliases = set(re.findall(r"\b(r\d+)\s*:\s*repository\s*\(", query))
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(3):
        pause(0, "a GitHub GraphQL query")
        try:
            with request.urlopen(
                request.Request(GRAPHQL_URL, data=body, headers=headers, method="POST"),
                timeout=45,
            ) as response:
                payload = json.load(response)
        except error.HTTPError as exc:
            if exc.code not in {403, 429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == 2:
                raise
        else:
            data = payload.get("data") or {}
            errors = payload.get("errors") or []
            # Only a confirmed missing repository is safe to skip. Nested
            # lookup failures and partial responses must not remove good rows.
            failed = []
            for item in errors:
                path = item.get("path") or []
                if not (
                    item.get("type") == "NOT_FOUND" and len(path) == 1
                    and path[0] in aliases and path[0] in data and data[path[0]] is None
                ):
                    failed.append(item)
            if not failed and aliases.issubset(data):
                return data
            if attempt == 2:
                reason = (failed[0].get("message") or failed[0]) if failed else "missing repository data"
                raise RuntimeError(f"GitHub GraphQL failed: {reason}")
        pause(4 * (attempt + 1), "a GitHub GraphQL retry")
    return {}


def repository_alias(index: int, full_name: str, body: str) -> str:
    owner, name = full_name.split("/", 1)
    return (
        f"r{index}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
        f"{{ {body} }}"
    )


def code_paths(full_names: list[str], token: str) -> dict[str, list[str]]:
    """Root entries of each repository that are not paperwork."""
    paths: dict[str, list[str]] = {}
    for start in range(0, len(full_names), 20):
        batch = full_names[start : start + 20]
        query = "query { " + " ".join(
            repository_alias(i, n, 'object(expression: "HEAD:") { ... on Tree { entries { name } } }')
            for i, n in enumerate(batch)
        ) + " }"
        data = graphql(query, token)
        for index, full_name in enumerate(batch):
            tree = ((data.get(f"r{index}") or {}).get("object") or {}).get("entries") or []
            names = [str(e.get("name") or "") for e in tree]
            paths[full_name] = [n for n in names if n and not PAPERWORK.match(n)][:PATHS_PER_REPO]
    return paths


def qualifying_repositories(
    repositories: list[dict], token: str
) -> tuple[list[dict], dict[str, list[str]]]:
    """Apply the index's PoC classifier before publishing a trending row."""
    accepted: list[dict] = []
    code: dict[str, list[str]] = {}
    blacklist = load_blacklist()
    fields = """
      databaseId createdAt pushedAt isPrivate visibility defaultBranchRef { target { oid } }
    """ + README_FIELDS + """
      root: object(expression: \"HEAD:\") {
        ... on Tree { entries { name type oid } }
      }
    """
    batches = [repositories[start:start + 20] for start in range(0, len(repositories), 20)]

    def describe(batch: list[dict]) -> dict:
        query = "query { " + " ".join(
            repository_alias(i, str(repo.get("full_name") or ""), fields)
            for i, repo in enumerate(batch)
        ) + " }"
        data = graphql(query, token)
        if not data:
            raise RuntimeError("GitHub returned no repository content for the PoC gate")
        return data

    with ThreadPoolExecutor(max_workers=4) as pool:
        contents = list(pool.map(describe, batches))
    for batch, data in zip(batches, contents):
        for index, repo in enumerate(batch):
            content = data.get(f"r{index}")
            if content is None:
                continue
            full_name = str(repo.get("full_name") or "")
            topics = [
                {"topic": {"name": str(topic)}}
                for topic in repo.get("topics") or []
                if topic
            ]
            candidate = {
                **content,
                "nameWithOwner": full_name,
                "description": repo.get("description") or "",
                "isFork": bool(repo.get("fork")),
                "private": repo.get("private"),
                "visibility": content.get("visibility") or repo.get("visibility"),
                "repositoryTopics": {"nodes": topics},
            }
            wanted = (extract_cves(f"{full_name.replace('_', ' ')} {candidate['description']} "
                                  f"{' '.join(topic_names(candidate))} {readme_text(candidate)}")
                      | reviewed_cves(full_name))
            years = {int(cve.split("-")[1]) for cve in wanted}
            if repo.get("_year"):
                years &= {repo["_year"]}
            attach_source_artifacts(candidate, {"Authorization": f"Bearer {token}"}, blacklist, cves=wanted)
            qualified = {cve for year in years for cve in qualifying_repo_cves(candidate, year, blacklist)}
            if len(wanted) > 5:
                # A collection's stars and latest commit describe the whole
                # repository. Only a dedicated CVE name or a reviewed artifact
                # can supply a single-CVE homepage row; retain its index links.
                qualified &= identity_cves(full_name) | {item.cve for item in reviewed_artifacts(candidate)}
            if not qualified:
                continue
            specific = {cve for cve in qualified if root_has_cve_artifact(candidate, cve)}
            specific.update(item.cve for item in reviewed_artifacts(candidate) if item.cve in qualified)
            choices = specific or qualified
            preferred = cve_of(repo)
            mentions = [f"CVE-{year}-{number}" for year, number in CVE_ID.findall(readme_text(candidate))]
            cve = preferred if preferred in choices else next(
                (mention for mention in mentions if mention in choices),
                max(choices, key=lambda value: tuple(map(int, value.split("-")[1:]))),
            )
            repo["cve"] = cve
            repo["_shared_repository"] = len(wanted) > 5 and cve not in identity_cves(full_name)
            entries = ((content.get("root") or {}).get("entries") or [])
            readme_path = next((path for field, path in README_PATHS.items()
                                if (content.get(field) or {}).get("text")), None)
            code[full_name] = releases.artifact_paths(
                entries, cve, readme_path=readme_path, readme_qualified=True, limit=PATHS_PER_REPO,
            )
            if artifacts := reviewed_artifacts(candidate):
                matching = [item for item in artifacts if item.cve == cve]
                code[full_name] = sorted({item.path for item in matching})[:PATHS_PER_REPO]
                if matching:
                    from build_site import dedupe_source_links
                    repo["_artifact_url"] = dedupe_source_links([item.url for item in matching], cve)[0]
            repo["revision"] = ((content.get("defaultBranchRef") or {}).get("target") or {}).get("oid")
            repo["id"] = content.get("databaseId") or repo.get("id")
            accepted.append(repo)
    return accepted, code


def code_pushed(
    full_names: list[str], token: str, paths: dict[str, list[str]] | None = None
) -> dict[str, str]:
    """When each repository last committed something that is not paperwork.

    A repository whose only recent commit edits the README has not shipped a
    new proof of concept, and saying it was updated an hour ago is a lie the
    whole front page is built on.
    """
    paths = paths if paths is not None else code_paths(full_names, token)
    latest: dict[str, str] = {}
    def fetch_dates(names: list[str]) -> dict[str, str]:
        found = {}
        parts = []
        for index, full_name in enumerate(names):
            history = " ".join(
                f'p{j}: history(first: 1, path: {json.dumps(path)}) {{ nodes {{ committedDate }} }}'
                for j, path in enumerate(paths[full_name])
            )
            parts.append(repository_alias(
                index, full_name,
                f"pushedAt defaultBranchRef {{ target {{ ... on Commit {{ {history} }} }} }}",
            ))
        data = graphql("query { " + " ".join(parts) + " }", token)
        for index, full_name in enumerate(names):
            repository = data.get(f"r{index}") or {}
            target = (repository.get("defaultBranchRef") or {}).get("target") or {}
            dates = [
                (target.get(f"p{j}") or {}).get("nodes", [{}])[0].get("committedDate")
                for j in range(len(paths[full_name]))
                if (target.get(f"p{j}") or {}).get("nodes")
            ]
            dates = [d for d in dates if d]
            if dates:
                # Commit clocks are user supplied; they cannot postdate the push.
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                ceiling = min(repository.get("pushedAt") or now, now)
                valid = [value for value in dates if value <= ceiling]
                if valid:
                    found[full_name] = max(valid)
        return found

    names = [name for name in full_names if paths.get(name)]
    batches = [names[start:start + 6] for start in range(0, len(names), 6)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for found in pool.map(fetch_dates, batches):
            latest.update(found)
    return latest


def popularity(repo: dict) -> float:
    from build_site import trending_score
    return trending_score({"stars": repo.get("stargazers_count"), "released": repo.get("_released"),
                           "pushed": repo.get("_shipped"), "shared_repository": repo.get("_shared_repository")})


def time_ago(timestamp: str) -> str:
    moment = releases.timestamp(timestamp)
    if moment is None:
        return ""
    delta = datetime.now(timezone.utc) - moment
    if len(timestamp) == 10:
        return f"{max(0, delta.days)}d ago"
    if delta.total_seconds() < 0:
        return "just now"
    for amount, unit in ((delta.days, "d"), (delta.seconds // 3600, "h"), (delta.seconds // 60, "m")):
        if amount > 0:
            return f"{amount}{unit} ago"
    return "just now"


def cell(value: str) -> str:
    """Keep repository text on a single markdown table cell."""
    text = " ".join(str(value or "").split()).replace("|", "/")
    return text.replace("\u2014", "-").replace("\u2013", "-")



def known_exploited() -> set[str]:
    """CVE ids CISA lists as exploited in the wild."""
    try:
        with open(KEV, encoding="utf-8") as handle:
            return {str(key).upper() for key in json.load(handle)}
    except (OSError, ValueError):
        return set()


def cve_of(repo: dict) -> str:
    text = f"{repo.get('cve') or ''} {repo.get('name') or ''} {repo.get('description') or ''}"
    return next((cve for year, number in CVE_ID.findall(text)
                 if is_valid_cve(cve := f"CVE-{year}-{number}")), "")


def repository_summary(repo: dict, cve: str) -> str:
    """Prefer the CVE summary when a repository only has placeholder copy."""
    summary = cell(repo.get("description"))
    remainder = CVE_ID.sub("", summary).strip(" -:|")
    placeholder = re.fullmatch(
        r"(?i)(?:draft|todo|tbd|placeholder)(?:\s+or\s+(?:draft|todo|tbd|placeholder))*",
        remainder,
    )
    if not remainder or placeholder:
        return cell(nvd_description(cve)) or summary
    return summary


def shorten(text: str) -> str:
    text = cell(text)
    if len(text) <= DESC_LIMIT:
        return text
    return text[:DESC_LIMIT].rsplit(" ", 1)[0] + "\u2026"


def table_row(item: dict, when: str) -> str:
    """One README row, drawn from the same item the feed publishes."""
    return (f"| {star_cell(item.get('stars'))} | {time_ago(when)} "
            f"| {KEV_MARK if item.get('kev') else ''}[{item.get('name')}]({item.get('url')}) "
            f"| {shorten(item.get('desc'))} |")


def figures() -> dict:
    """Index totals, written by hero.py from the same count the banner shows."""
    try:
        with open(STATS, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def shields(text: str) -> str:
    """Escape one field of a shields badge path.

    The path is split on single hyphens, so a hyphen inside the text has to be
    doubled before it is percent-encoded or the badge loses everything after it.
    """
    return parse.quote(text.replace("-", "--").replace("_", "__"), safe="")


def pill(label: str, value: str, colour: str, link: str) -> str:
    """A shields badge whose text is baked in at build time.

    Anything describing the index is fixed here rather than resolved when the
    page is viewed: the figure is then exactly the one the banner was drawn
    from, and it cannot degrade to "resource not found" when a lookup fails.
    """
    return (f"[![{label}](https://img.shields.io/badge/"
            f"{shields(label)}-{shields(value)}-{colour}"
            f"?style=flat-square&labelColor=161b22)]({link})")


def live_pill(path: str, label: str, colour: str, link: str, stamp: str) -> str:
    """A shields badge that has to be resolved at view time.

    The stamp is ignored by shields but changes the URL every rebuild, so
    GitHub's image proxy fetches a fresh badge instead of replaying a cached one.
    """
    return (f"[![{label}](https://img.shields.io/github/{path}"
            f"?style=flat-square&label={parse.quote(label)}&color={colour}"
            f"&labelColor=161b22&_={stamp})]({link})")


def count_stamp(counts: dict) -> str:
    keys = ("total_cves", "with_pocs", "kev")
    if any(not counts.get(key) for key in keys):
        raise RuntimeError("docs/stats.json does not contain usable corpus counts")
    return "-".join(str(int(counts[key])) for key in keys)


def refresh_count_header() -> int:
    """Update only the README figures after a corpus-changing sync."""
    counts = figures()
    stamp = count_stamp(counts)
    with open(README, encoding="utf-8") as handle:
        content = handle.read()

    content, hero_replacements = re.subn(
        rf"({re.escape(HERO_URL)}\?v=)[^\"]+",
        rf"\g<1>{stamp}",
        content,
        count=1,
    )
    badges = {
        "CVEs with PoCs": pill(
            "CVEs with PoCs", f"{counts['with_pocs']:,}", "2f81f7",
            f"{SITE}/",
        ),
        "known exploited": pill(
            "known exploited", f"{counts['kev']:,}", "f85149",
            f"{SITE}/",
        ),
    }
    badge_replacements = 0
    for label, badge in badges.items():
        content, replaced = re.subn(
            rf"\[!\[{re.escape(label)}\]\([^)]+\)\]\([^)]+\)",
            lambda _: badge,
            content,
            count=1,
        )
        badge_replacements += replaced
    if hero_replacements != 1 or badge_replacements != len(badges):
        raise RuntimeError("README count header is missing an expected field")

    with open(README, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"Updated README counts to {stamp}")
    return 0


def header(stamp: str, synced: str) -> list[str]:
    """Everything above the tables. The banner carries a cache-busting stamp
    because GitHub proxies README images and would otherwise serve a stale copy
    of a file that is redrawn whenever the index moves."""
    counts = figures()
    home = f"{SITE}/"
    badges = [
        pill("last sync", synced, "2f81f7", f"https://github.com/{SLUG}/commits/main"),
        live_pill("actions/workflow/status/" + SLUG + "/hot_cves.yml", "CI", "2f81f7",
                  f"https://github.com/{SLUG}/actions/workflows/hot_cves.yml", stamp),
    ]
    if counts.get("with_pocs"):
        badges.append(pill("CVEs with PoCs", f"{counts['with_pocs']:,}", "2f81f7", home))
    if counts.get("kev"):
        badges.append(pill("known exploited", f"{counts['kev']:,}", "f85149", home))
    badges.append(live_pill("stars/" + SLUG, "stars", "e3b341",
                            f"https://github.com/{SLUG}/stargazers", stamp))
    return [
        '<div align="center">',
        "",
        f'<a href="{home}"><img src="{HERO_URL}?v={count_stamp(counts)}" alt="{BRAND}" width="100%"></a>',
        "",
        "&nbsp;".join(badges),
        "",
        f'<a href="{home}"><img src="{SEARCH_CTA_URL}" alt="Search {BRAND}" width="100%"></a>',
        "",
        "</div>",
        "",
        f"**[{BRAND}]({home})**: {DESCRIPTION} {SEARCH_GUIDE}",
        "",
    ]


FOOTER = """

## Data

Every file is plain JSON on the CDN. No key, no rate limit.

```bash
# everything the index knows about one CVE
curl -s @SITE@/CVE_list.json \\
  | jq '.[] | select(.cve == "CVE-2021-44228") | {cve, poc: (.poc | length), nuclei, msf, edb, vulhub, collections}'

# every published CVSS assessment plus vetted advisory links
curl -s @SITE@/cve_metadata.json | jq '."CVE-2021-44228"'

# likelihood of exploitation in the next 30 days
curl -s @SITE@/epss.json | jq '."CVE-2021-44228"'

# stars and last push for one PoC repository; repository keys are lowercased
curl -s @SITE@/repo_meta.json | jq '."sfewer-r7/cve-2026-55040"'
```

What CISA says is being exploited, that also has a PoC here, ranked by how
likely each is to be used next:

```bash
curl -s @SITE@/kev.json  -o kev.json
curl -s @SITE@/epss.json -o epss.json
jq -n --slurpfile kev kev.json --slurpfile epss epss.json \\
  '[$kev[0] | keys[] | select($epss[0][.]) | {cve: ., epss: $epss[0][.][0]}]
   | sort_by(-.epss) | .[:10]'
```

| Endpoint | Holds |
| --- | --- |
| [`CVE_list.json`](@SITE@/CVE_list.json) | Every CVE with a linked PoC, its description and its `poc`, `nuclei`, `msf`, `edb`, `vulhub` and `collections` links |
| [`cve_metadata.json`](@SITE@/cve_metadata.json) | CVSS v2.0, v3.0, v3.1 and v4.0 assessments from NVD and the CVE Program, with vectors and vetted advisory links |
| [`epss.json`](@SITE@/epss.json) | Exploitation probability and percentile, for nearly every CVE indexed |
| [`nuclei.json`](@SITE@/nuclei.json) | Template metadata for the CVEs covered by a runnable Nuclei check |
| [`kev.json`](@SITE@/kev.json) | CISA known exploited, keyed by CVE id |
| [`repo_meta.json`](@SITE@/repo_meta.json) | Stars and last push date per PoC repository, keys lowercased |
| [`trending_poc.json`](@SITE@/trending_poc.json) | Two independent lists in display order, `landed` by first release and `items` for Trending, plus index totals |
| [`cves/2026/CVE-2026-68138.md`](cves/2026/CVE-2026-68138.md) | Markdown copy of one CVE, one directory per year |

CVSS rows are `[version, score, severity, vector, source, assessment type]`.
Advisory rows are `[URL, NVD reference tags]`.
Repository metadata rows are `[stars, last_push_UTC_date]`. Repo stars describe
the hosting GitHub repository, including links to individual files. `N/A`
means that no public repository reading is available; a measured zero is `0`.
`published` is the CVE record publication date. When it is unavailable,
`poc_observed` records the earliest retained observation of a listed PoC.
Newest uses that fallback and labels it separately as “PoC observed”.

## Sources

Public PoCs are indexed as soon as they pass source checks. CVE and NVD metadata
enrich the listing when available; pending CVE records do not hide PoC links.

| Source | What it contributes |
| --- | --- |
| GitHub | Repositories naming a CVE, checked for code before they are linked |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Historical repository candidates, passed through the same code and intent checks |
| [Nuclei](https://github.com/projectdiscovery/nuclei-templates) | Runnable templates that exercise the vulnerability |
| [ExploitDB](https://gitlab.com/exploit-database/exploitdb) | Archived exploits, mapped by their own CVE column |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Modules, best ranked first |
| [Vulhub](https://github.com/vulhub/vulhub) | Runnable vulnerable environments and reproduction steps |
| [afrog](https://github.com/zan8in/afrog), [Vulnerability](https://github.com/tzwlhack/Vulnerability), [0day](https://github.com/helloexp/0day), [xray](https://github.com/chaitin/xray), [Google Security Research](https://github.com/google/security-research), [GitHub Security Lab](https://github.com/github/securitylab), [Rhino Security Labs](https://github.com/RhinoSecurityLabs/CVEs), [Tenable](https://github.com/tenable/poc), [pedrib](https://github.com/pedrib/PoC) | CVE-specific templates, code and reproduction guides inside multi-CVE repositories |
| [Openwall](https://www.openwall.com/lists/), [SecLists](https://seclists.org/) and [Gist](https://gist.github.com/) | Reproducers from disclosure posts and Gists that NVD references, linked only after review |
| [EPSS](https://www.first.org/epss/) | Daily exploitation probability from FIRST |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | What is being exploited in the wild |
| [NVD](https://nvd.nist.gov/) | CVSS assessments and tagged vendor, third-party, patch and mitigation references |
| [CVE Program](https://www.cve.org/) | The CVE record, publication state and CNA references |

## Build

| Job | Cadence | Picks up |
| --- | --- | --- |
| [Trending sweep](.github/workflows/hot_cves.yml) | hourly | Front-page repositories, new repository metadata, a rotating refresh of older repositories and CVE Program scores received during discovery |
| [CVE sync](.github/workflows/sync_cve_pocs.yml) | daily | New CVEs, CNA references and recently pushed GitHub repositories for every CVE year |
| [Metadata sync](.github/workflows/sync_metadata.yml) | daily plus weekly full pass | CVSS, advisories, rejected records, current CISA KEV status and reviewed Gist and mailing list reproducers |
| [Nuclei sync](.github/workflows/sync_nuclei.yml) | daily | New templates and rating changes |
| [Exploit archives](.github/workflows/sync_exploits.yml) | daily | ExploitDB, Metasploit and Vulhub mappings |
| [Historical GitHub sync](.github/workflows/sync_pocingithub.yml) | daily | Older PoC repositories missed by the recent-push window |
| [Path collection sync](.github/workflows/sync_collections.yml) | every 6 hours | CVE-specific artifacts inside curated multi-CVE repositories |
| [Link audit](.github/workflows/audit_poc_links.yml) | daily | Repositories that went dead, dropped from the index |

## Contributing

Missing PoC, wrong link, dead repository: open an issue with the CVE id and the
repository URL.
""".replace("@SITE@", SITE)


def previous_items() -> list[dict]:
    try:
        with open(TRENDING, encoding="utf-8") as handle:
            rows = json.load(handle)
    except (OSError, ValueError):
        return []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def carried_rows(previous: list[dict], year: int, kev: set[str]) -> list[dict]:
    import link_health
    from build_site import trending_score
    rows = []
    for item in previous:
        url = str(item.get("url") or "")
        if item.get("trending") and item.get("year") == year and url and not link_health.unavailable(url):
            row = {key: value for key, value in item.items() if key != "landed"}
            row.update(kev=row.get("cve") in kev, score=trending_score(row))
            rows.append(row)
    return sorted(rows, key=lambda row: row["score"], reverse=True)[:PER_YEAR]


def replace_file(path: str, text: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=os.path.dirname(path),
                                     delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def finish(seconds: float, budget: float | None) -> int:
    status = "incomplete" if INCOMPLETE else "complete"
    title = f"Trending refresh {status} in {seconds:.0f}s"
    if budget is not None:
        title += f" of a {budget:.0f}s budget"
    print(title + (f"; incomplete: {', '.join(dict.fromkeys(INCOMPLETE))}" if INCOMPLETE else ""))
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"### {title}\n\n" + "".join(f"- {line}\n" for line in SUMMARY) + "\n")
    return PARTIAL_EXIT if INCOMPLETE else 0


def main(*, history_limit: int = HISTORY_LIMIT, retry_history: bool = False,
         budget: float | None = None) -> int:
    import link_health
    global HISTORY_REMAINING, HISTORY_RETRY_HOURS, DEADLINE
    began = time.monotonic()
    DEADLINE = None if budget is None else began + budget - FINISH_SECONDS
    INCOMPLETE.clear()
    SUMMARY.clear()
    HISTORY_REMAINING = history_limit
    HISTORY_RETRY_HOURS = 0 if retry_history else 4
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=WINDOW_DAYS)).date().isoformat()
    current_year = now.year
    kev = known_exploited()
    previous = previous_items()
    items: list[dict] = []
    sections: list[list[str]] = []

    token = github_token()
    ledger = releases.load_ledger()
    fresh = just_landed(token, ledger)
    observations = list(fresh)
    for year in range(current_year, current_year - YEARS, -1):
        started = time.monotonic()
        try:
            total, repositories = search_year(year, since)
            searched = len(repositories)
            repositories, paths = qualifying_repositories(repositories, token)
            repositories = published_repositories(repositories)
            repositories = [repo for repo in repositories if not link_health.unavailable(artifact_link(repo)[0])]
            observations.extend(repositories)
            release_dates(repositories, token, paths, ledger)
            shipped = code_pushed(
                [str(r.get("full_name") or "") for r in repositories], token, paths
            )
        except Exception as problem:
            rows = carried_rows(previous, year, kev)
            incomplete(f"CVE-{year}", problem, f"kept {len(rows)} rows from the previous run")
        else:
            for repo in repositories:
                repo["_shipped"] = shipped.get(str(repo.get("full_name") or ""), "")
            qualified = len(repositories)
            repositories = [r for r in repositories if r["_shipped"][:10] >= since]
            repositories.sort(key=popularity, reverse=True)
            recent = len(repositories)
            repositories = repositories[:PER_YEAR]
            note(f"CVE-{year}: {total} pushed since {since}, "
                 f"{searched - qualified} rejected by artifact gate, "
                 f"{qualified - recent} without a recent artifact commit, "
                 f"{len(repositories)} published in {time.monotonic() - started:.0f}s")
            rows = []
            for repo in repositories:
                pushed = repo["_shipped"]
                cve = cve_of(repo)
                url, artifact = artifact_link(repo)
                summary = repository_summary(repo, cve)
                rows.append({
                    "year": year,
                    "stars": repo.get("stargazers_count"),
                    "name": cell(repo.get("name")),
                    "url": url,
                    "artifact": artifact,
                    "shared_repository": bool(repo.get("_shared_repository")),
                    "source": parse.urlsplit(url).hostname,
                    "desc": summary,
                    "pushed": pushed,
                    "released": repo.get("_released"),
                    "basis": repo.get("_basis"),
                    "score": popularity(repo),
                    "trending": True,
                    "created": str(repo.get("created_at") or ""),
                    "cve": cve,
                    "kev": cve in kev,
                })
        if not rows:
            continue
        items.extend(rows)
        sections.append([
            f"## Trending in {year}",
            "",
            "| Repo stars | Updated | Repository | Description |",
            "| --- | --- | --- | --- |",
            *(table_row(row, row["pushed"]) for row in rows),
        ])

    remember_repository_metadata(observations)
    landed = ledger_landed(ledger, fresh)

    stamp = now.strftime("%Y%m%d%H%M")
    # No hyphens: they are the field separator in a shields badge path.
    synced = now.strftime("%d %b %Y %H:%M UTC")
    lines = header(stamp, synced)
    if landed:
        lines.append("## Just landed")
        lines.append("")
        lines.append("| Repo stars | Released | PoC | Description |")
        lines.append("| --- | --- | --- | --- |")
        lookups = 0
        for repo in landed:
            cve = cve_of(repo)
            url, artifact = artifact_link(repo)
            stars = repo.get("stargazers_count")
            exploited = cve in kev
            # A day-old repository often ships without a description; the CVE's
            # own summary says more than an empty cell.
            summary = repository_summary(repo, cve)
            if not summary and cve and lookups < NVD_LOOKUPS and time_left() > 0:
                lookups += 1
                summary = cell(nvd_lookup(cve))
                time.sleep(6)
            items.append({
                "year": int(cve.split("-")[1]) if cve else current_year,
                "stars": stars,
                "name": cell(repo.get("name")),
                "url": url,
                "artifact": artifact,
                "shared_repository": bool(repo.get("_shared_repository")),
                "source": parse.urlsplit(url).hostname,
                "desc": summary,
                "pushed": repo.get("_shipped"),
                "released": repo["_released"],
                "basis": repo.get("_basis"),
                "score": popularity(repo),
                "trending": False,
                "created": str(repo.get("created_at") or ""),
                "cve": cve,
                "kev": exploited,
                "landed": True,
            })
            lines.append(table_row(items[-1], repo["_released"]))
        lines.append("")
    for index, block in enumerate(sections):
        if index == FOLDED_AFTER and len(sections) > FOLDED_AFTER:
            years = ", ".join(
                section[0].rsplit(" ", 1)[-1] for section in sections[FOLDED_AFTER:]
            )
            lines.append(f"<details>\n<summary>{years}</summary>\n")
        lines.extend(block)
        lines.append("")
    if len(sections) > FOLDED_AFTER:
        lines.append("</details>")

    # The site merges both lanes into one list, so a repository in both is
    # written once and keeps its landed flag.
    unique: dict[str, dict] = {}
    for item in items:
        kept = unique.setdefault(releases.key(item["cve"], item["url"]), item)
        if item.get("landed"):
            kept["landed"] = True
    items = sorted(unique.values(), key=lambda item: item["score"], reverse=True)
    releases.resolve_copies(ledger)
    releases.save_ledger(ledger)
    flagged = sum(1 for item in items if item["kev"])

    replace_file(README, "\n".join(lines).rstrip() + FOOTER)
    replace_file(TRENDING, json.dumps(items, ensure_ascii=False, indent=1) + "\n")
    print(f"Wrote {README} and {TRENDING} ({len(items)} repositories, {flagged} known-exploited)")
    return finish(time.monotonic() - began, budget)


if __name__ == "__main__":
    if sys.argv[1:] == ["--counts-only"]:
        raise SystemExit(refresh_count_header())
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-limit", type=int, default=HISTORY_LIMIT)
    parser.add_argument("--retry-history", action="store_true")
    parser.add_argument("--budget-seconds", type=float,
                        help="Write the tables within this many seconds, keeping last run's rows "
                             "for any year there was no time to refresh")
    args = parser.parse_args()
    if args.history_limit < 0:
        parser.error("--history-limit must not be negative")
    if args.budget_seconds is not None and args.budget_seconds <= FINISH_SECONDS:
        parser.error(f"--budget-seconds must leave more than the {FINISH_SECONDS}s needed to write")
    raise SystemExit(main(history_limit=args.history_limit, retry_history=args.retry_history,
                          budget=args.budget_seconds))
