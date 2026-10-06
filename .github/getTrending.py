#!/usr/bin/env python3
"""Rebuild README.md with the most recently updated CVE proof-of-concept repositories."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib import error, parse, request

SEARCH_URL = "https://api.github.com/search/repositories"
GRAPHQL_URL = "https://api.github.com/graphql"
# Editing a README is not updating a proof of concept. Everything a repository
# carries as paperwork is ignored when working out when its PoC last changed.
PAPERWORK = re.compile(
    r"^(?:readme|licen[cs]e|copying|notice|authors|contributing|code_of_conduct"
    r"|security|changelog|history|\.git|\.editorconfig|\.pre-commit)",
    re.IGNORECASE,
)
PATHS_PER_REPO = 12
LANGUAGES = (
    "Shell", "Go", "ASP", "WebAssembly", "R", "Lua", "Python", "C++", "C",
    "JavaScript", "Perl", "PowerShell", "Ruby", "Rust", "Java", "PHP",
)
YEARS = 5
PER_YEAR = 20
SEARCH_PAGE = 100
SEARCH_LIMIT = 1000
WINDOW_DAYS = 90   # a PoC nobody has touched this quarter is not "recent"
MIN_STARS = 2
# A PoC published today has no stars yet, so the star floor hid exactly the
# rows worth seeing first. This lane drops the floor and pays for it with a
# short window and a hard cap.
LANDED_DAYS = 10
LANDED_ROWS = 10
LANDED_POOL = 50
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# NVD allows five requests per thirty seconds unauthenticated, and only a
# couple of rows per run ever need one.
NVD_LOOKUPS = 4
USER_AGENT = "0xMarcio-cve-trending"
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import BRAND, DESCRIPTION, SEARCH_GUIDE, SITE, SLUG
from update_cves import load_blacklist, qualifying_repo_cves

README = os.path.join(ROOT, "README.md")
TRENDING = os.path.join(ROOT, "index", "trending.json")
KEV = os.path.join(ROOT, "index", "kev.json")
STATS = os.path.join(ROOT, "docs", "stats.json")
DESC_LIMIT = 110   # a table cell, not a paragraph
FOLDED_AFTER = 2   # years past the newest two are collapsed behind a summary
CVE_ID = re.compile(r"CVE[-_](\d{4})[-_](\d{4,7})", re.IGNORECASE)
RAW = f"https://raw.githubusercontent.com/{SLUG}/main/docs"
HERO_URL = f"{RAW}/hero.svg"
SEARCH_CTA_REV = "8dec6181e823d641132e0ee8a52a1612c2b5dd37"
SEARCH_CTA_URL = f"https://raw.githubusercontent.com/{SLUG}/{SEARCH_CTA_REV}/docs/search.svg"
KEV_MARK = f'<img src="{RAW}/kev.svg" alt="KEV" title="CISA known exploited" height="14"> '


def search(query: str, pool: int) -> tuple[int, list[dict]]:
    """One repository search, most recently updated first."""
    url = SEARCH_URL + "?" + parse.urlencode(
        {"q": query, "s": "updated", "o": "desc", "per_page": pool}
    )
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(3):
        try:
            with request.urlopen(request.Request(url, headers=headers), timeout=30) as response:
                payload = json.load(response)
            return int(payload.get("total_count") or 0), payload.get("items") or []
        except error.HTTPError as problem:
            if problem.code not in (403, 422, 503) or attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))
    return 0, []


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


def just_landed(token: str, seen: set[str]) -> list[dict]:
    """Fresh PoCs with no star floor and no language filter.

    A repository published this morning usually has neither: GitHub has not
    classified its language yet and nobody has starred it. Filtering on either
    is what kept day-one exploits off the page. What replaces them is a check
    that the repository actually carries code, since dropping the filters also
    lets through the write-ups and empty placeholders that share the naming.
    """
    since = (datetime.now(timezone.utc) - timedelta(days=LANDED_DAYS)).date().isoformat()
    year = datetime.now(timezone.utc).year
    rows: list[dict] = []
    for target in (year, year - 1):
        _, found = search(f'"CVE-{target}" in:name pushed:>{since}', LANDED_POOL)
        rows.extend(found)

    candidates = []
    for repo in rows:
        name = str(repo.get("full_name") or "")
        if not name or name in seen or not cve_of(repo):
            continue
        seen.add(name)
        candidates.append(repo)
    candidates.sort(key=lambda repo: str(repo.get("pushed_at") or ""), reverse=True)
    # Only the freshest are worth two API round trips each.
    candidates = candidates[:LANDED_ROWS * 4]

    searched = len(candidates)
    candidates, paths = qualifying_repositories(candidates, token)
    names = [str(repo["full_name"]) for repo in candidates]
    shipped = code_pushed(names, token, paths)

    fresh, hollow = [], 0
    for repo in candidates:
        name = str(repo["full_name"])
        pushed = shipped.get(name)
        if not pushed:
            hollow += 1
            continue
        if pushed[:10] < since:
            continue
        repo["_shipped"] = pushed
        fresh.append(repo)
    fresh.sort(key=lambda repo: repo["_shipped"], reverse=True)
    print(
        f"just landed: {len(fresh)} qualified, "
        f"{searched - len(candidates)} rejected by artifact gate, "
        f"{hollow} without an artifact commit"
    )
    return fresh[:LANDED_ROWS]


def search_year(year: int, since: str) -> tuple[int, list[dict]]:
    """Return how many PoC repositories for one CVE year were pushed since a
    date, and every result GitHub exposes for the final artifact-date sort.
    """
    query = " ".join(
        [f'"CVE-{year}" in:name', f"stars:>{MIN_STARS}", f"pushed:>{since}"]
        + [f"language:{language}" for language in LANGUAGES]
    )
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    # The token authenticates the API only; it is never placed in the URL,
    # written to disk, or printed, so it cannot leak through logs or the commit.
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    repositories: list[dict] = []
    seen: set[str] = set()
    total = 0
    for page in range(1, SEARCH_LIMIT // SEARCH_PAGE + 1):
        url = SEARCH_URL + "?" + parse.urlencode({
            "q": query,
            "s": "updated",
            "o": "desc",
            "per_page": SEARCH_PAGE,
            "page": page,
        })
        for attempt in range(3):
            try:
                with request.urlopen(
                    request.Request(url, headers=headers), timeout=30
                ) as response:
                    payload = json.load(response)
                break
            except error.HTTPError as exc:
                if exc.code not in {403, 429, 500, 502, 503, 504} or attempt == 2:
                    raise
            except (error.URLError, TimeoutError, json.JSONDecodeError):
                if attempt == 2:
                    raise
            time.sleep(5 * (attempt + 1))

        total = int(payload.get("total_count") or 0)
        found = payload.get("items") or []
        for repo in found:
            name = str(repo.get("full_name") or "")
            if name and name not in seen:
                seen.add(name)
                repositories.append(repo)
        if not found or len(repositories) >= min(total, SEARCH_LIMIT):
            break
    return total, repositories


def github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def graphql(query: str, token: str) -> dict:
    body = json.dumps({"query": query}).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(3):
        try:
            with request.urlopen(
                request.Request(GRAPHQL_URL, data=body, headers=headers, method="POST"),
                timeout=45,
            ) as response:
                return json.load(response).get("data") or {}
        except error.HTTPError as exc:
            if exc.code not in {403, 429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == 2:
                raise
        time.sleep(4 * (attempt + 1))
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
      readmeMd: object(expression: \"HEAD:README.md\") { ... on Blob { text } }
      readmeUpper: object(expression: \"HEAD:README.MD\") { ... on Blob { text } }
      readmeRst: object(expression: \"HEAD:README.rst\") { ... on Blob { text } }
      readmeBare: object(expression: \"HEAD:README\") { ... on Blob { text } }
      root: object(expression: \"HEAD:\") {
        ... on Tree { entries { name type } }
      }
    """
    for start in range(0, len(repositories), 20):
        batch = repositories[start : start + 20]
        query = "query { " + " ".join(
            repository_alias(i, str(repo.get("full_name") or ""), fields)
            for i, repo in enumerate(batch)
        ) + " }"
        data = graphql(query, token)
        if not data:
            raise RuntimeError("GitHub returned no repository content for the PoC gate")
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
                "repositoryTopics": {"nodes": topics},
            }
            cve = cve_of(repo)
            if not cve or cve not in qualifying_repo_cves(
                candidate, int(cve.split("-")[1]), blacklist
            ):
                continue
            entries = ((content.get("root") or {}).get("entries") or [])
            code[full_name] = [
                str(entry.get("name") or "")
                for entry in entries
                if entry.get("name") and not PAPERWORK.match(str(entry["name"]))
            ][:PATHS_PER_REPO]
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
    batch: list[str] = []

    def flush(names: list[str]) -> None:
        if not names:
            return
        parts = []
        for index, full_name in enumerate(names):
            history = " ".join(
                f'p{j}: history(first: 1, path: {json.dumps(path)}) {{ nodes {{ committedDate }} }}'
                for j, path in enumerate(paths[full_name])
            )
            parts.append(repository_alias(
                index, full_name,
                f"defaultBranchRef {{ target {{ ... on Commit {{ {history} }} }} }}",
            ))
        data = graphql("query { " + " ".join(parts) + " }", token)
        for index, full_name in enumerate(names):
            target = ((data.get(f"r{index}") or {}).get("defaultBranchRef") or {}).get("target") or {}
            dates = [
                (target.get(f"p{j}") or {}).get("nodes", [{}])[0].get("committedDate")
                for j in range(len(paths[full_name]))
                if (target.get(f"p{j}") or {}).get("nodes")
            ]
            dates = [d for d in dates if d]
            if dates:
                latest[full_name] = max(dates)

    for full_name in full_names:
        if not paths.get(full_name):
            continue
        batch.append(full_name)
        if len(batch) == 6:
            flush(batch)
            batch = []
    flush(batch)
    return latest


def time_ago(timestamp: str) -> str:
    moment = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - moment
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
    match = CVE_ID.search(f"{repo.get('name') or ''} {repo.get('description') or ''}")
    return f"CVE-{match.group(1)}-{match.group(2)}" if match else ""


def repository_summary(repo: dict, cve: str) -> str:
    """Prefer the CVE summary when a repository only has placeholder copy."""
    summary = cell(repo.get("description"))
    remainder = CVE_ID.sub("", summary).strip(" -:|")
    placeholder = re.fullmatch(
        r"(?i)(?:draft|todo|tbd|placeholder)(?:\s+or\s+(?:draft|todo|tbd|placeholder))*",
        remainder,
    )
    if not remainder or placeholder:
        return nvd_description(cve) or summary
    return summary


def shorten(text: str) -> str:
    text = cell(text)
    if len(text) <= DESC_LIMIT:
        return text
    return text[:DESC_LIMIT].rsplit(" ", 1)[0] + "\u2026"


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
| [`cve_metadata.json`](@SITE@/cve_metadata.json) | NVD CVSS v2.0, v3.0, v3.1 and v4.0 assessments with vectors and vetted advisory links |
| [`epss.json`](@SITE@/epss.json) | Exploitation probability and percentile, for nearly every CVE indexed |
| [`nuclei.json`](@SITE@/nuclei.json) | Template metadata for the CVEs covered by a runnable Nuclei check |
| [`kev.json`](@SITE@/kev.json) | CISA known exploited, keyed by CVE id |
| [`repo_meta.json`](@SITE@/repo_meta.json) | Stars and last push date per PoC repository, keys lowercased |
| [`trending_poc.json`](@SITE@/trending_poc.json) | Trending repositories plus index totals |
| [`cves/2026/CVE-2026-68138.md`](cves/2026/CVE-2026-68138.md) | Markdown copy of one CVE, one directory per year |

CVSS rows are `[version, score, severity, vector, source, assessment type]`.
Advisory rows are `[URL, NVD reference tags]`.

## Sources

| Source | What it contributes |
| --- | --- |
| GitHub | Repositories naming a CVE, checked for code before they are linked |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Historical repository candidates, passed through the same code and intent checks |
| [Nuclei](https://github.com/projectdiscovery/nuclei-templates) | Runnable templates that exercise the vulnerability |
| [ExploitDB](https://gitlab.com/exploit-database/exploitdb) | Archived exploits, mapped by their own CVE column |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Modules, best ranked first |
| [Vulhub](https://github.com/vulhub/vulhub) | Runnable vulnerable environments and reproduction steps |
| [afrog](https://github.com/zan8in/afrog), [Vulnerability](https://github.com/tzwlhack/Vulnerability), [0day](https://github.com/helloexp/0day), [xray](https://github.com/chaitin/xray) | CVE-specific templates, code and reproduction guides inside multi-CVE repositories |
| [EPSS](https://www.first.org/epss/) | Daily exploitation probability from FIRST |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | What is being exploited in the wild |
| [NVD](https://nvd.nist.gov/) | CVSS assessments and tagged vendor, third-party, patch and mitigation references |
| [CVE Program](https://www.cve.org/) | The CVE record, publication state and CNA references |

## Build

| Job | Cadence | Picks up |
| --- | --- | --- |
| [Trending sweep](.github/workflows/hot_cves.yml) | hourly | Front-page repositories and prior-hour candidates added to the searchable index |
| [CVE sync](.github/workflows/sync_cve_pocs.yml) | daily | New CVEs, CNA references and recently pushed GitHub repositories for every CVE year |
| [Metadata sync](.github/workflows/sync_metadata.yml) | daily plus weekly full pass | CVSS, advisories, rejected records and current CISA KEV status |
| [Nuclei sync](.github/workflows/sync_nuclei.yml) | daily | New templates and rating changes |
| [Exploit archives](.github/workflows/sync_exploits.yml) | daily | ExploitDB, Metasploit and Vulhub mappings |
| [Historical GitHub sync](.github/workflows/sync_pocingithub.yml) | weekly | Older PoC repositories missed by the recent-push window |
| [Path collection sync](.github/workflows/sync_collections.yml) | weekly | CVE-specific artifacts inside curated multi-CVE repositories |
| [Link audit](.github/workflows/audit_poc_links.yml) | weekly | Repositories that went dead, dropped from the index |

## Contributing

Missing PoC, wrong link, dead repository: open an issue with the CVE id and the
repository URL.
""".replace("@SITE@", SITE)


def main() -> int:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=WINDOW_DAYS)).date().isoformat()
    current_year = now.year
    kev = known_exploited()
    items: list[dict] = []
    sections: list[list[str]] = []
    flagged = 0

    token = github_token()
    for year in range(current_year, current_year - YEARS, -1):
        total, repositories = search_year(year, since)
        searched = len(repositories)
        repositories, paths = qualifying_repositories(repositories, token)
        shipped = code_pushed(
            [str(r.get("full_name") or "") for r in repositories], token, paths
        )
        for repo in repositories:
            repo["_shipped"] = shipped.get(str(repo.get("full_name") or ""), "")
        qualified = len(repositories)
        repositories = [r for r in repositories if r["_shipped"][:10] >= since]
        repositories.sort(key=lambda repo: repo["_shipped"], reverse=True)
        repositories = repositories[:PER_YEAR]
        print(f"CVE-{year}: {total} pushed since {since}, "
              f"{searched - qualified} rejected by artifact gate, "
              f"{qualified - len(repositories)} without a recent artifact commit")
        if not repositories:
            continue
        block = [
            f"## Trending in {year}",
            "",
            "| Stars | Updated | Repository | Description |",
            "| --- | --- | --- | --- |",
        ]
        for repo in repositories:
            # The last commit that touched anything but paperwork. pushed_at counts
            # a README tweak, which had the table claiming a year-old exploit was
            # updated twenty-one hours ago.
            pushed = repo["_shipped"]
            cve = cve_of(repo)
            exploited = cve in kev
            flagged += exploited
            # Same fallback the landed lane uses. These CVEs are old enough to
            # be in the index already, so it costs nothing to ask.
            summary = repository_summary(repo, cve)
            items.append({
                "year": year,
                "stars": int(repo.get("stargazers_count") or 0),
                "name": cell(repo.get("name")),
                "url": repo.get("html_url") or "",
                "desc": summary,
                "pushed": pushed,
                "created": str(repo.get("created_at") or ""),
                "cve": cve,
                "kev": exploited,
            })
            block.append(
                f"| {repo.get('stargazers_count', 0)}\u2b50 | {time_ago(pushed)} "
                f"| {KEV_MARK if exploited else ''}[{cell(repo.get('name'))}]({repo.get('html_url')}) "
                f"| {shorten(summary)} |"
            )
        sections.append(block)

    landed = just_landed(token, {item["url"].split("github.com/")[-1] for item in items})

    stamp = now.strftime("%Y%m%d%H%M")
    # No hyphens: they are the field separator in a shields badge path.
    synced = now.strftime("%d %b %Y %H:%M UTC")
    lines = header(stamp, synced)
    if landed:
        lines.append("## Just landed")
        lines.append("")
        lines.append("| Stars | Updated | Repository | Description |")
        lines.append("| --- | --- | --- | --- |")
        lookups = 0
        for repo in landed:
            cve = cve_of(repo)
            exploited = cve in kev
            # A day-old repository often ships without a description; the CVE's
            # own summary says more than an empty cell.
            summary = repository_summary(repo, cve)
            if not summary and cve and lookups < NVD_LOOKUPS:
                lookups += 1
                summary = cell(nvd_lookup(cve))
                time.sleep(6)
            items.append({
                "year": int(cve.split("-")[1]) if cve else current_year,
                "stars": int(repo.get("stargazers_count") or 0),
                "name": cell(repo.get("name")),
                "url": repo.get("html_url") or "",
                "desc": summary,
                "pushed": repo["_shipped"],
                "created": str(repo.get("created_at") or ""),
                "cve": cve,
                "kev": exploited,
                "landed": True,
            })
            lines.append(
                f"| {repo.get('stargazers_count', 0)}\u2b50 | {time_ago(repo['_shipped'])} "
                f"| {KEV_MARK if exploited else ''}[{cell(repo.get('name'))}]({repo.get('html_url')}) "
                f"| {shorten(summary)} |"
            )
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

    with open(README, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip() + FOOTER)
    with open(TRENDING, "w", encoding="utf-8") as handle:
        json.dump(items, handle, ensure_ascii=False, indent=1)
        handle.write("\n")
    print(f"Wrote {README} and {TRENDING} ({len(items)} repositories, {flagged} known-exploited)")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--counts-only"]:
        raise SystemExit(refresh_count_header())
    if sys.argv[1:]:
        print("usage: getTrending.py [--counts-only]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
