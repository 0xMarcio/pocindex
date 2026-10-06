#!/usr/bin/env python3
"""Discover CVE proof-of-concept links and update the repository."""

from __future__ import annotations

import argparse
import http.client
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Collection, Iterable, Iterator
from urllib import error, request
from urllib.parse import quote, urlparse

import source_artifacts

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cves"
INDEX = ROOT / "index"
GITHUB_LIST = INDEX / "github.txt"
REFERENCE_LIST = INDEX / "references.txt"
VERIFIED_REFERENCE_LIST = INDEX / "reference_pocs.txt"
BLACKLIST_FILE = INDEX / "blacklist.txt"
ADVISORY_FILE = INDEX / "advisory_hosts.txt"
STATE_FILE = ROOT / ".github" / "cve_sync_state.json"
KEV_FILE = INDEX / "kev.json"
DATES_FILE = INDEX / "cve_dates.json"
RECORD_STATE_FILE = INDEX / "cve_record_state.json"
DISCOVERY_STATE_FILE = INDEX / "github_discovery_state.json"
RECORD_RETRY_DAYS = 1

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVELIST_DELTA_LOG_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
)

CVE_RE = re.compile(r"\bCVE[-_ ](?P<year>\d{4})[-_ ](?P<number>\d{4,})\b", re.IGNORECASE)
# A repository that calls itself an exploit in Chinese is still an exploit;
# an English-only vocabulary quietly reads every one of them as "not a PoC".
# CJK terms sit outside the \b group because CJK has no word boundaries.
POC_RE = re.compile(
    r"\b(?:poc|exploit(?:ation)?|proof[ _-]*of[ _-]*concept|"
    r"repro(?:ducer|duction|duce)?|payload|"
    r"prueba[ _-]*de[ _-]*concepto|explotaci(?:on|ón)|"
    r"explora(?:cao|ção)|preuve[ _-]*de[ _-]*concept)\b"
    r"|漏洞利用|漏洞复现|复现|利用代码|利用脚本|攻击脚本|驗證程式|検証コード"
    r"|эксплойт|익스플로잇",
    re.IGNORECASE,
)
CODE_FILE_RE = re.compile(
    r"\.(?:c|cc|cpp|cs|go|java|js|mjs|nse|php|pl|ps1|py|rb|rs|sh|ts)$",
    re.IGNORECASE,
)
NON_POC_RE = re.compile(
    r"(?:\b(?:advisory|aggregat(?:ion|or)|analysis|ansible|audits?|block(?:er|ing)?|blog|"
    r"bookmark|challenge|cheat[ _-]*sheets?|check(?:s|er|ing)?|collection|corpus|course|ctf|"
    r"dataset|defen(?:ce|se|sive)|detect(?:ion|or)?|dfir|epss|exam(?:en)?|feed|finder|framework|"
    r"github[ _-]*stars|hardening|hub|investigation|"
    r"honeypot|intelligence|ioc|lab|list|lookup|mitigat(?:e|ing|ion|or)|model(?:er|ing)|"
    r"monitor(?:ing)?|notes?|oscp|papers?|patch(?:es|ed|ing)?|pentest|portfolio|prediction|"
    r"pre[ _-]*checks?|prevent(?:ion|ive)?|profile|protect(?:ion|ive)|"
    r"remediat(?:e|ion)|reports?|"
    r"resources?|rules?|scan(?:s|ner|ning)?|shield|signature|suggester|templates?|toolkit|"
    r"training|tutorial|validat(?:e|ion|or)|verif(?:y|ier|ication)|walkthrough|wazuh|"
    r"workarounds?|fix(?:es|ed|ing)?|"
    r"write[ _-]*ups?)\b|searchpoc|watchdog)",
    re.IGNORECASE,
)
SECTION_RE_TEMPLATE = r"({header}\s*\n)(.*?)(?=\n#### |\n### |\Z)"
USER_AGENT = "0xMarcio-cve-poc-sync"

GITHUB_SEARCH_QUERY = """
query($query: String!, $cursor: String) {
  search(type: REPOSITORY, query: $query, first: 100, after: $cursor) {
    repositoryCount
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on Repository {
        nameWithOwner
        url
        description
        isArchived
        isFork
        pushedAt
        defaultBranchRef { target { oid } }
        repositoryTopics(first: 20) { nodes { topic { name } } }
      }
    }
  }
  rateLimit { cost remaining resetAt }
}
"""


@dataclass
class CVEDetails:
    description: str
    products: list[str]
    versions: list[str]
    vulnerabilities: list[str]
    title: str = ""
    vendors: list[str] = field(default_factory=list)


@dataclass
class SyncStats:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def poc_link_key(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return url.rstrip("/")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return url
    repo = f"{parts[0]}/{parts[1]}".lower()
    suffix = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
    return f"github:{repo}{suffix}?{parsed.query}#{parsed.fragment}"


def stable_unique_poc_links(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = poc_link_key(value)
        if value and key not in seen:
            seen.add(key)
            result.append(value)
    return result


def is_valid_cve(cve_id: str) -> bool:
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id, re.IGNORECASE)
    if not match:
        return False
    return 1999 <= int(match.group(1)) <= 2100


def extract_cves(text: str | None, year: int | None = None) -> set[str]:
    result: set[str] = set()
    for match in CVE_RE.finditer(text or ""):
        match_year = int(match.group("year"))
        if year is not None and match_year != year:
            continue
        cve_id = f"CVE-{match_year}-{match.group('number')}"
        if is_valid_cve(cve_id):
            result.add(cve_id)
    return result


def load_blacklist(path: Path = BLACKLIST_FILE) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def load_advisory_hosts(path: Path = ADVISORY_FILE) -> tuple[str, ...]:
    """Destinations that only publish patch notices, never exploit code."""
    if not path.exists():
        return ()
    return tuple(
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def is_advisory(url: str, rules: Collection[str]) -> bool:
    trimmed = re.sub(r"^https?://(?:www\.)?", "", url.strip().lower())
    return any(trimmed.startswith(rule) for rule in rules)


ADVISORY_HOSTS = load_advisory_hosts()


def is_blacklisted_repo(full_name: str, blacklist: Collection[str]) -> bool:
    return full_name.lower() in blacklist


def normalise_identity(text: str) -> str:
    return re.sub(r"[_-]+", " ", text)


def github_repo_from_url(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != "github.com":
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def github_url_is_profile_root(url: str) -> bool:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != "github.com":
        return False
    parts = [part for part in parsed.path.split("/") if part]
    return len(parts) == 2 and parts[0].lower() == parts[1].lower()


def github_url_is_ambiguous_root(url: str, cve_id: str) -> bool:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != "github.com":
        return False
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        return False
    identity = normalise_identity(f"{parts[0]} {parts[1]}")
    if not NON_POC_RE.search(identity):
        return False
    return not (
        cve_id in extract_cves(identity)
        and POC_RE.search(identity)
    )


def readme_text(repo: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("readmeMd", "readmeUpper", "readmeRst", "readmeBare"):
        value = repo.get(key)
        if isinstance(value, dict) and isinstance(value.get("text"), str):
            parts.append(value["text"])
    return "\n".join(stable_unique(parts))


def topic_names(repo: dict[str, Any]) -> list[str]:
    topics = repo.get("repositoryTopics") or {}
    names: list[str] = []
    for node in topics.get("nodes") or []:
        name = ((node or {}).get("topic") or {}).get("name")
        if name:
            names.append(str(name))
    return names


def root_entry_names(repo: dict[str, Any]) -> list[str]:
    root = repo.get("root") or {}
    return [
        str(entry.get("name") or "")
        for entry in root.get("entries") or []
        if entry.get("name")
    ]


def root_has_poc_artifact(repo: dict[str, Any], cve_id: str) -> bool:
    if root_has_cve_artifact(repo, cve_id):
        return True
    for name in root_entry_names(repo):
        if name.lower().startswith(("readme", "license", "security")):
            continue
        if POC_RE.search(normalise_identity(name)):
            return True
    return False


def root_has_cve_artifact(repo: dict[str, Any], cve_id: str) -> bool:
    year, number = cve_id.split("-")[1:]
    cve_pattern = re.compile(
        rf"\bCVE[-_ ]{re.escape(year)}[-_ ]{re.escape(number)}\b",
        re.IGNORECASE,
    )
    for name in root_entry_names(repo):
        if name.lower().startswith(("readme", "license", "security")):
            continue
        if cve_pattern.search(name):
            return True
    return False


def root_has_code(repo: dict[str, Any]) -> bool:
    return any(CODE_FILE_RE.search(name) for name in root_entry_names(repo))


TEXT_ONLY_RE = re.compile(
    r"^(?:readme|license|licence|security|contributing|changelog|code_of_conduct|"
    r"\.gitignore|\.gitattributes|funding\.yml)(?:\.|$)|\.(?:md|txt|rst)$",
    re.IGNORECASE,
)
PAYLOAD_RE = re.compile(r"```|~~~|^ {4}\S", re.MULTILINE)
COMMAND_RE = re.compile(
    r"\b(?:curl|wget|python3?|php|perl|ruby|nc|ncat|bash|msfconsole|nuclei|sqlmap|"
    r"GET /|POST /|PUT /)\b|https?://[^\s)]*\?"
)


def repo_is_bare(repo: dict[str, Any], readme: str) -> bool:
    """Nothing runnable, and nothing that says how.

    A sample of two hundred indexed repositories held fourteen with a bare
    README or none at all: empty shells, placeholders, a link to a paywall.
    Anything with a directory, a file that is not documentation, a file named
    for the CVE or as a PoC, or a README that carries a code block, a command,
    a request or a real write-up is not bare. Where the root is unknown the
    question is not asked.
    """
    root = repo.get("root")
    if not isinstance(root, dict):
        return False
    for entry in root.get("entries") or []:
        name = str(entry.get("name") or "")
        if str(entry.get("type") or "") == "tree" or not TEXT_ONLY_RE.search(name):
            return False
        if POC_RE.search(normalise_identity(name)) or CODE_FILE_RE.search(name):
            return False
    text = readme or ""
    return not (len(text) >= 1000 or PAYLOAD_RE.search(text) or COMMAND_RE.search(text))


def truncated_ids(cve_ids: Collection[str]) -> set[str]:
    """Identifiers that a longer identifier from the same year extends."""
    numbers: dict[str, set[str]] = defaultdict(set)
    for cve_id in cve_ids:
        _, year, number = cve_id.split("-")
        numbers[year].add(number)
    return {
        f"CVE-{year}-{number}"
        for year, values in numbers.items()
        for number in values
        if any(other.startswith(number) for other in values - {number})
    }


def readme_has_poc_context(readme: str, cve_id: str, full_name: str = "") -> bool:
    year, number = cve_id.split("-")[1:]
    pattern = re.compile(rf"\bCVE[-_ ]{re.escape(year)}[-_ ]{re.escape(number)}\b", re.IGNORECASE)
    for match in pattern.finditer(readme):
        line_start = readme.rfind("\n", 0, match.start()) + 1
        line_end = readme.find("\n", match.end())
        line = readme[line_start : line_end if line_end >= 0 else len(readme)]
        linked_repos = {
            github_repo_from_url(url).lower()
            for url in re.findall(r"https://github\.com/[^\s)>]+", line, re.IGNORECASE)
        }
        linked_repos.discard("")
        if linked_repos and full_name.lower() not in linked_repos:
            continue
        start = max(0, match.start() - 350)
        end = min(len(readme), match.end() + 350)
        if POC_RE.search(readme[start:end]):
            return True
    return False


def qualifying_repo_cves(
    repo: dict[str, Any],
    year: int,
    blacklist: Collection[str],
) -> set[str]:
    full_name = str(repo.get("nameWithOwner") or "")
    if not full_name or repo.get("isFork"):
        return set()
    owner, repo_name = full_name.lower().split("/", 1)
    if owner == repo_name or repo_name.endswith(".github.io"):
        return set()
    if is_blacklisted_repo(full_name, blacklist):
        return set()

    description = str(repo.get("description") or "")
    topics = " ".join(topic_names(repo))
    readme = readme_text(repo)
    reviewed = {item.cve for item in source_artifacts.reviewed_artifacts(repo)
                if int(item.cve.split("-")[1]) == year}
    if repo_is_bare(repo, readme):
        return reviewed
    all_name_cves = extract_cves(full_name) | extract_cves(normalise_identity(full_name))
    all_identity_cves = (
        all_name_cves
        | extract_cves(description)
        | extract_cves(topics)
    )
    # Underscores are word characters, so a raw name like CVE-A_CVE-B matches
    # neither identifier; read the separator-normalised form as well.
    name_cves = extract_cves(full_name, year) | extract_cves(normalise_identity(full_name), year)
    description_cves = extract_cves(description, year)
    topic_cves = extract_cves(topics, year)
    readme_cves = extract_cves(readme, year)
    # A caption or description that drops a digit, "CVE-2023-3883" written for
    # CVE-2023-38831, still parses as a valid identifier and would otherwise
    # enrol the repository against whatever unrelated advisory owns it. Trust
    # the repository name, which may deliberately carry both identifiers.
    truncated = truncated_ids(name_cves | description_cves | topic_cves | readme_cves) - name_cves
    description_cves -= truncated
    topic_cves -= truncated
    readme_cves -= truncated
    identity_cves = name_cves | description_cves | topic_cves
    identity_text = normalise_identity(f"{full_name} {description}")
    identity_has_poc = bool(POC_RE.search(identity_text))
    metadata_has_poc = identity_has_poc or bool(POC_RE.search(topics))
    identity_is_non_poc = bool(NON_POC_RE.search(identity_text))
    has_code = root_has_code(repo)
    if identity_is_non_poc and not (name_cves and identity_has_poc and has_code):
        return reviewed
    if len(readme_cves) > 5 and not identity_cves:
        readme_cves = set()
    accepted: set[str] = set(reviewed)
    for cve_id in name_cves:
        has_context = readme_has_poc_context(readme, cve_id, full_name)
        has_artifact = root_has_poc_artifact(repo, cve_id)
        has_content = bool(readme.strip()) or has_artifact or has_code
        if (
            (not identity_is_non_poc or has_artifact or has_code)
            and (metadata_has_poc or has_context or has_artifact)
            and has_content
        ):
            accepted.add(cve_id)
    for cve_id in description_cves | topic_cves:
        has_context = readme_has_poc_context(readme, cve_id, full_name)
        has_cve_artifact = root_has_cve_artifact(repo, cve_id)
        if all_name_cves and cve_id not in all_name_cves and not has_cve_artifact:
            continue
        if (
            (not identity_is_non_poc or cve_id in name_cves)
            and (metadata_has_poc or has_context)
            and (has_context or has_cve_artifact or has_code)
        ):
            accepted.add(cve_id)
    for cve_id in readme_cves:
        has_artifact = root_has_poc_artifact(repo, cve_id)
        has_cve_artifact = root_has_cve_artifact(repo, cve_id)
        if all_name_cves and cve_id not in all_name_cves and not has_cve_artifact:
            continue
        if all_identity_cves and cve_id not in all_identity_cves and not has_cve_artifact:
            continue
        if identity_cves and cve_id not in identity_cves and not has_artifact:
            continue
        if (
            readme_has_poc_context(readme, cve_id, full_name)
            and (has_artifact or identity_has_poc)
        ):
            accepted.add(cve_id)
    return accepted - source_artifacts.excluded_cves(full_name)


def http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = 45,
    allow_not_found: bool = False,
) -> Any:
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    body = None
    method = "GET"
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
        method = "POST"

    for attempt in range(3):
        req = request.Request(url, data=body, headers=request_headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as response:
                return json.load(response)
        except error.HTTPError as exc:
            if allow_not_found and exc.code == 404:
                return None
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (
            error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            http.client.HTTPException,
        ):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)
    raise RuntimeError(f"Unable to fetch {url}")


def github_repository_data(payload: dict[str, Any], aliases: Collection[str]) -> dict[str, Any]:
    data = payload.get("data") or {}
    for error in payload.get("errors") or []:
        path = error.get("path") or []
        if (
            error.get("type") == "NOT_FOUND"
            and len(path) == 1
            and path[0] in aliases
            and path[0] in data
            and data[path[0]] is None
        ):
            continue
        raise RuntimeError(f"GitHub repository lookup failed: {error.get('message') or error}")
    if any(alias not in data for alias in aliases):
        raise RuntimeError("GitHub repository lookup returned incomplete response data")
    rate = data.get("rateLimit") or {}
    if int(rate.get("remaining") or 0) < 5:
        raise RuntimeError(f"GitHub GraphQL quota is nearly exhausted; resets at {rate.get('resetAt')}")
    return data


class GitHubClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("GITHUB_TOKEN is required for GitHub PoC discovery")
        self.headers = {"Authorization": f"Bearer {token}"}

    def search_page(self, query_text: str, cursor: str | None = None) -> dict[str, Any]:
        payload = http_json(
            GITHUB_GRAPHQL_URL,
            headers=self.headers,
            data={"query": GITHUB_SEARCH_QUERY, "variables": {"query": query_text, "cursor": cursor}},
        )
        data = payload.get("data") or {}
        search = data.get("search")
        if payload.get("errors") or not search:
            messages = "; ".join(str(item.get("message")) for item in payload.get("errors") or [])
            raise RuntimeError(f"GitHub search failed: {messages or 'missing response data'}")
        page = search.get("pageInfo") or {}
        if (
            not isinstance(search.get("repositoryCount"), int)
            or not isinstance(search.get("nodes"), list)
            or not isinstance(page.get("hasNextPage"), bool)
            or (page["hasNextPage"] and not page.get("endCursor"))
            or any(not isinstance(node, dict) for node in search["nodes"])
        ):
            raise RuntimeError("GitHub search returned incomplete response data")
        rate = data.get("rateLimit") or {}
        if int(rate.get("remaining") or 0) < 5:
            raise RuntimeError(f"GitHub GraphQL quota is nearly exhausted; resets at {rate.get('resetAt')}")
        return search

    def fetch_readmes(
        self,
        full_names: list[str],
    ) -> tuple[set[str], dict[str, str], dict[str, list[dict[str, str]]]]:
        fields = """
          readmeMd: object(expression: \"HEAD:README.md\") { ... on Blob { text } }
          readmeUpper: object(expression: \"HEAD:README.MD\") { ... on Blob { text } }
          readmeRst: object(expression: \"HEAD:README.rst\") { ... on Blob { text } }
          readmeBare: object(expression: \"HEAD:README\") { ... on Blob { text } }
          root: object(expression: \"HEAD:\") {
            ... on Tree { entries { name type } }
          }
        """
        aliases: list[str] = []
        names: list[str] = []
        for full_name in full_names:
            if "/" not in full_name:
                continue
            owner, name = full_name.split("/", 1)
            index = len(names)
            aliases.append(
                f"repo{index}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
                f"{{ {fields} }}"
            )
            names.append(full_name)
        if not aliases:
            return set(), {}, {}
        query_text = "query { " + " ".join(aliases) + " rateLimit { remaining resetAt } }"
        payload = http_json(
            GITHUB_GRAPHQL_URL,
            headers=self.headers,
            data={"query": query_text},
        )
        data = github_repository_data(payload, {f"repo{index}" for index in range(len(names))})
        result: dict[str, str] = {}
        roots: dict[str, list[dict[str, str]]] = {}
        existing: set[str] = set()
        for index, full_name in enumerate(names):
            repo = data.get(f"repo{index}")
            if repo is None:
                continue
            existing.add(full_name)
            text = readme_text(repo)
            if text:
                result[full_name] = text
            entries = ((repo.get("root") or {}).get("entries") or [])
            roots[full_name] = [
                {"name": str(entry.get("name") or ""), "type": str(entry.get("type") or "")}
                for entry in entries
                if entry.get("name")
            ]
        return existing, result, roots


def split_date_range(start: date, end: date) -> tuple[tuple[date, date], tuple[date, date]]:
    midpoint = start + timedelta(days=(end - start).days // 2)
    return (start, midpoint), (midpoint + timedelta(days=1), end)


def build_search_query(search_terms: str, qualifier: str, start: date, end: date) -> str:
    return (
        f"{search_terms} fork:false archived:false "
        f"{qualifier}:{start.isoformat()}..{end.isoformat()}"
    )


def search_range(
    client: GitHubClient,
    search_terms: str,
    qualifier: str,
    start: date,
    end: date,
) -> Iterator[dict[str, Any]]:
    query_text = build_search_query(search_terms, qualifier, start, end)
    first_page = client.search_page(query_text)
    count = int(first_page.get("repositoryCount") or 0)

    if count > 1000:
        if start == end:
            raise RuntimeError(f"GitHub search returned more than 1000 repositories for {query_text}")
        left, right = split_date_range(start, end)
        yield from search_range(client, search_terms, qualifier, *left)
        yield from search_range(client, search_terms, qualifier, *right)
        return

    print(f"GitHub {qualifier} {start}..{end}: {count} repositories")
    page = first_page
    received = 0
    cursors: set[str] = set()
    while True:
        for repo in page.get("nodes") or []:
            if repo:
                received += 1
                yield repo
        page_info = page.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = str(page_info.get("endCursor") or "")
        if not cursor or cursor in cursors:
            raise RuntimeError("GitHub search returned an invalid pagination cursor")
        cursors.add(cursor)
        page = client.search_page(query_text, cursor)
    if received < count:
        raise RuntimeError(f"GitHub search returned only {received} of {count} repositories")


def search_without_range(client: GitHubClient, search_terms: str) -> Iterator[dict[str, Any]]:
    query_text = f"{search_terms} fork:false archived:false"
    cursor: str | None = None
    while True:
        page = client.search_page(query_text, cursor)
        if int(page.get("repositoryCount") or 0) > 1000:
            raise RuntimeError(f"GitHub search returned more than 1000 repositories for {query_text}")
        for repo in page.get("nodes") or []:
            if repo:
                yield repo
        page_info = page.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = str(page_info.get("endCursor"))


def discover_github_pocs(
    token: str,
    *,
    years: Iterable[int],
    lookback_days: int,
    backfill: bool,
    cve_filter: set[str],
    window_end: date | None = None,
    checkpoints: dict[str, str] | None = None,
    artifact_cache_write: bool = True,
) -> dict[str, list[str]]:
    client = GitHubClient(token)
    blacklist = load_blacklist()
    discovered: dict[str, list[str]] = defaultdict(list)
    repositories: dict[str, dict[str, Any]] = {}
    target_years = list(years)
    if cve_filter:
        target_years = sorted({int(cve_id.split("-")[1]) for cve_id in cve_filter})

    def remember(repo: dict[str, Any]) -> None:
        full_name = str(repo.get("nameWithOwner") or "")
        if full_name and not is_blacklisted_repo(full_name, blacklist):
            repositories[full_name] = repo

    def collect(repo: dict[str, Any], year: int) -> None:
        url = str(repo.get("url") or "").rstrip("/")
        if not url.startswith("https://github.com/"):
            return
        for cve_id in qualifying_repo_cves(repo, year, blacklist):
            if cve_filter and cve_id not in cve_filter:
                continue
            links = source_artifacts.approved_artifact_links(repo, cve_id) or [url]
            for link in links:
                if link not in discovered[cve_id]:
                    discovered[cve_id].append(link)

    def search_terms(identifier: str) -> list[str]:
        return [
            f'"{identifier}" in:name,description',
            f'"{identifier}" poc in:readme',
            f'"{identifier}" exploit in:readme',
            f'"{identifier}" "proof of concept" in:readme',
            f'"{identifier}" reproducer in:readme',
        ]

    if cve_filter:
        for cve_id in sorted(cve_filter):
            for terms in search_terms(cve_id):
                for repo in search_without_range(client, terms):
                    remember(repo)
    else:
        end = window_end or datetime.now(timezone.utc).date()
        for year in target_years:
            if backfill:
                qualifier = "created"
                start = date(2008, 1, 1)
            else:
                qualifier = "pushed"
                previous = (checkpoints or {}).get(str(year))
                anchor = min(end, date.fromisoformat(previous)) if previous else end
                start = anchor - timedelta(days=max(1, lookback_days))
            for terms in search_terms(f"CVE-{year}"):
                for repo in search_range(client, terms, qualifier, start, end):
                    remember(repo)

    # Deferred reviewed work survives the moving search window. Refresh its HEAD
    # before resuming so a stale candidate cache cannot approve changed bytes.
    pending_cves = {row["cve"] for row in source_artifacts.load_reviews()
                    if int(row["cve"].split("-")[1]) in target_years
                    and (not cve_filter or row["cve"] in cve_filter)}
    pending_names = source_artifacts.pending_reviewed_names(cves=pending_cves)
    missing = [name for name in pending_names if name.lower() not in {n.lower() for n in repositories}
               and any(int(c.split("-")[1]) in target_years and (not cve_filter or c in cve_filter)
                       for c in source_artifacts.reviewed_cves(name))
               and not is_blacklisted_repo(name, blacklist)]
    if missing:
        aliases = []
        for index, full_name in enumerate(missing):
            owner, name = full_name.split("/", 1)
            aliases.append(f"repo{index}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
                           "{ nameWithOwner url description isFork defaultBranchRef { target { oid } } }")
        payload = http_json(GITHUB_GRAPHQL_URL, headers=client.headers,
                            data={"query": "query { " + " ".join(aliases) + " rateLimit { remaining resetAt } }"})
        replay = github_repository_data(payload, {f"repo{index}" for index in range(len(missing))})
        for index in range(len(missing)):
            if replay.get(f"repo{index}") is not None:
                remember(replay[f"repo{index}"])
        if artifact_cache_write:
            source_artifacts.mark_pending_checked(missing)

    names = sorted(repositories)
    batches = [names[offset : offset + 10] for offset in range(0, len(names), 10)]
    completed = 0
    existing_names: set[str] = set()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(client.fetch_readmes, batch): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            try:
                existing, readmes, roots = future.result()
            except Exception as exc:
                for pending in futures:
                    pending.cancel()
                raise RuntimeError(f"README batch starting with {batch[0]} failed: {exc}") from exc
            existing_names.update(existing)
            for full_name, text in readmes.items():
                repositories[full_name]["readmeMd"] = {"text": text}
            for full_name, entries in roots.items():
                repositories[full_name]["root"] = {"entries": entries}
            completed += len(batch)
            if completed % 500 < len(batch):
                print(f"Fetched README data for {completed} of {len(names)} repositories")

    removed = set(repositories) - existing_names
    for full_name in removed:
        del repositories[full_name]
    if removed:
        print(f"Discarded {len(removed)} repositories removed during discovery")

    pending_order = {name: index for index, name in enumerate(pending_names)}
    for repo in sorted(repositories.values(), key=lambda r: pending_order.get(str(r.get("nameWithOwner", "")).lower(), len(pending_order))):
        wanted = {c for c in (source_artifacts.identity_cves(str(repo.get("nameWithOwner") or ""))
                            | source_artifacts.reviewed_cves(str(repo.get("nameWithOwner") or "")))
                  if int(c.split("-")[1]) in target_years and (not cve_filter or c in cve_filter)}
        attach_source_artifacts(repo, client.headers, blacklist, cves=wanted, persist=artifact_cache_write)
        for year in target_years:
            collect(repo, year)
    return discovered



def attach_source_artifacts(
    repo: dict[str, Any], headers: dict[str, str], blacklist: Collection[str],
    *, cves: set[str] | None = None, persist: bool = True,
) -> None:
    """Add locally verified nested evidence without weakening the ordinary gate."""
    name = str(repo.get("nameWithOwner") or "")
    if not name or repo.get("isFork") or is_blacklisted_repo(name, blacklist):
        return
    if "defaultBranchRef" in repo and repo["defaultBranchRef"] is None:
        return
    known = source_artifacts.reviewed_cves(name)
    # Unreviewed bytes cannot pass the same-repository approval registry.
    # Do not spend the Actions REST quota harvesting candidates here.
    wanted = known if cves is None else known & cves
    if not wanted:
        return
    repo["_source_artifacts"] = source_artifacts.inspect_repository(
        # A caller selecting one CVE (such as Trending) must not overwrite
        # unfinished inspection of the other reviewed CVEs in this repository.
        repo, known, readme_text(repo), http_json, headers, persist=persist,
        budget=source_artifacts.automatic_budget(),
    )


def cna_container(record: dict[str, Any]) -> dict[str, Any]:
    return (record.get("containers") or {}).get("cna") or {}


def record_is_published(record: dict[str, Any]) -> bool:
    return str((record.get("cveMetadata") or {}).get("state") or "").upper() == "PUBLISHED"


def record_cve_id(record: dict[str, Any]) -> str:
    return str((record.get("cveMetadata") or {}).get("cveId") or "").upper()


def english_description(container: dict[str, Any]) -> str:
    descriptions = container.get("descriptions") or []
    for item in descriptions:
        if str(item.get("lang") or "").lower().startswith("en") and item.get("value"):
            return str(item["value"]).strip()
    for item in descriptions:
        if item.get("value"):
            return str(item["value"]).strip()
    return ""


def details_from_record(record: dict[str, Any]) -> CVEDetails | None:
    if not record_is_published(record):
        return None
    cna = cna_container(record)
    description = english_description(cna)
    if not description:
        return None

    products: list[str] = []
    versions: list[str] = []
    vendors: list[str] = []
    for affected in cna.get("affected") or []:
        # CNA product entries also describe unaffected products. Exclude one
        # only when the default and every version/change explicitly agree;
        # missing or unknown statuses are not evidence that it is unaffected.
        version_rows = affected.get("versions") or []
        statuses = [str(affected.get("defaultStatus") or "").strip().lower()]
        for version in version_rows:
            statuses.append(str(version.get("status") or "").strip().lower())
            statuses.extend(
                str(change.get("status") or "").strip().lower()
                for change in version.get("changes") or []
            )
        if all(status == "unaffected" for status in statuses):
            continue
        vendor = str(affected.get("vendor") or "").strip()
        if vendor and vendor.lower() not in ("n/a", "unknown"):
            vendors.append(vendor)
        for field in ("product", "packageName"):
            product = str(affected.get(field) or "").strip()
            if product and product.lower() not in {"n/a", "unknown"}:
                products.append(product)
                break
        for version in version_rows:
            status = str(version.get("status") or "affected").lower()
            value = str(version.get("version") or "").strip()
            if status == "affected" and value:
                versions.append(value)

    vulnerabilities: list[str] = []
    for problem in cna.get("problemTypes") or []:
        for item in problem.get("descriptions") or []:
            value = item.get("description") or item.get("cweId")
            if value:
                vulnerabilities.append(str(value).strip())

    return CVEDetails(
        description=description,
        products=stable_unique(products),
        versions=stable_unique(versions),
        vulnerabilities=stable_unique(vulnerabilities),
        title=" ".join(str(cna.get("title") or "").split()),
        vendors=stable_unique(vendors),
    )


def reference_is_poc(
    reference: dict[str, Any],
    blacklist: Collection[str],
    cve_id: str = "",
    advisories: Collection[str] | None = None,
    trust_exploit_tag: bool = True,
) -> bool:
    url = str(reference.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return False
    if is_advisory(url, ADVISORY_HOSTS if advisories is None else advisories):
        return False
    repo = github_repo_from_url(url)
    if repo and (
        is_blacklisted_repo(repo, blacklist)
        or github_url_is_profile_root(url)
        or (cve_id and github_url_is_ambiguous_root(url, cve_id))
    ):
        return False
    tags = [str(tag).lower() for tag in reference.get("tags") or []]
    evidence = " ".join(
        [url, str(reference.get("name") or ""), *(tags if trust_exploit_tag else [])]
    )
    if trust_exploit_tag and any("exploit" in tag for tag in tags):
        return True
    return bool(POC_RE.search(evidence))


def poc_references(
    record: dict[str, Any],
    blacklist: Collection[str] | None = None,
) -> list[str]:
    cve_id = record_cve_id(record)
    if not cve_id or not record_is_published(record):
        return []
    blacklist = load_blacklist() if blacklist is None else blacklist
    containers = record.get("containers") or {}
    candidates = [(cna_container(record), True)] + [
        (container, False)
        for container in containers.get("adp") or []
        if isinstance(container, dict)
    ]
    references: list[str] = []
    for container, trust_exploit_tag in candidates:
        for item in container.get("references") or []:
            url = str(item.get("url") or "").strip()
            if reference_is_poc(
                item,
                blacklist,
                cve_id,
                trust_exploit_tag=trust_exploit_tag,
            ):
                references.append(url)
    return stable_unique_poc_links(references)


def reference_url_is_live(url: str, timeout: int = 15) -> bool:
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "User-Agent": USER_AGENT,
    }
    for method in ("HEAD", "GET"):
        request_headers = dict(headers)
        if method == "GET":
            request_headers["Range"] = "bytes=0-0"
        req = request.Request(url, headers=request_headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as response:
                if method == "GET":
                    response.read(1)
                if int(response.status) < 400:
                    return True
        except error.HTTPError as exc:
            code = exc.code
            exc.close()
            if method == "GET" and code in {404, 410}:
                return False
        except (error.URLError, TimeoutError, OSError):
            pass
    return True


def filter_live_references(
    references: dict[str, list[str]],
    checker: Callable[[str], bool] | None = None,
) -> dict[str, list[str]]:
    checker = reference_url_is_live if checker is None else checker
    urls = stable_unique(url for values in references.values() for url in values)
    if not urls:
        return references
    dead: set[str] = set()
    with ThreadPoolExecutor(max_workers=min(8, len(urls))) as executor:
        futures = {executor.submit(checker, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                if not future.result():
                    dead.add(url)
            except Exception:
                continue
    if dead:
        print(f"Discarded {len(dead)} references returning 404 or 410")
    return {
        cve_id: [url for url in urls_for_cve if url not in dead]
        for cve_id, urls_for_cve in references.items()
        if any(url not in dead for url in urls_for_cve)
    }


def read_record(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def load_backfill_records(
    cve_dir: Path,
    year: int,
    cve_filter: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], dict[str, Path]]:
    records: dict[str, dict[str, Any]] = {}
    references: dict[str, list[str]] = {}
    paths: dict[str, Path] = {}
    blacklist = load_blacklist()

    for path in sorted(cve_dir.rglob("CVE-*.json")):
        cve_id = path.stem.upper()
        if not is_valid_cve(cve_id) or int(cve_id.split("-")[1]) != year:
            continue
        if cve_filter and cve_id not in cve_filter:
            continue
        paths[cve_id] = path
        record = read_record(path)
        if not record or not record_is_published(record):
            continue
        selected = poc_references(record, blacklist)
        if selected:
            records[cve_id] = record
            references[cve_id] = selected
    return records, references, paths


def load_state(path: Path | None = None, *, allow_missing: bool = False) -> str | None:
    path = path or STATE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        if allow_missing:
            return None
        raise RuntimeError("Missing CVE delta checkpoint; use --bootstrap-delta explicitly to start from retained history") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unreadable or corrupt CVE delta checkpoint: {path}") from exc
    value = data.get("cvelist_fetch_time") if isinstance(data, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Invalid CVE delta checkpoint: {path}")
    parse_delta_time(value)
    return value


def parse_delta_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"Invalid CVE delta timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def delta_changes(last_fetch_time: str | None, *, bootstrap: bool = False) -> tuple[dict[str, str], str]:
    if not last_fetch_time and not bootstrap:
        raise RuntimeError("CVE delta discovery requires a checkpoint or explicit bootstrap")
    log = http_json(CVELIST_DELTA_LOG_URL)
    if not isinstance(log, list) or not log:
        raise RuntimeError("CVE List V5 delta log is empty")
    times = [parse_delta_time(str(batch.get("fetchTime") or "")) for batch in log]
    if times != sorted(times, reverse=True):
        raise RuntimeError("CVE List V5 delta log is not ordered newest first")
    if last_fetch_time and parse_delta_time(last_fetch_time) < times[-1]:
        raise RuntimeError(
            f"CVE List V5 delta retention gap: checkpoint {last_fetch_time} precedes "
            f"oldest retained batch {log[-1]['fetchTime']}. "
            "Recover with --catch-up-dir pointing to a complete pinned CVE List V5 snapshot."
        )
    newest = str(log[0].get("fetchTime") or "")
    selected: list[dict[str, Any]] = []
    for batch in log:
        fetch_time = str(batch.get("fetchTime") or "")
        if last_fetch_time and parse_delta_time(fetch_time) <= parse_delta_time(last_fetch_time):
            break
        selected.append(batch)

    changes: dict[str, str] = {}
    for batch in reversed(selected):
        for group in ("new", "updated"):
            for item in batch.get(group) or []:
                cve_id = str(item.get("cveId") or "").upper()
                url = str(item.get("githubLink") or "")
                if is_valid_cve(cve_id) and url:
                    changes[cve_id] = url
    print(f"CVE List V5: {len(selected)} delta batches, {len(changes)} changed CVEs")
    return changes, newest


def catch_up_snapshot_files(snapshot: Path) -> tuple[str, dict[str, str], str]:
    """Use the committed tree as the completeness manifest, never a file count."""
    def git(*arguments: str) -> bytes:
        try:
            return subprocess.run(["git", "-C", str(snapshot), *arguments], check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("Catch-up requires a pinned CVE List V5 Git checkout; extracted directories lack a trusted completeness manifest") from exc

    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != snapshot.resolve():
        raise RuntimeError("--catch-up-dir must point to the CVE List V5 Git checkout root")
    revision = git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    algorithm = git("rev-parse", "--show-object-format").decode().strip()
    if algorithm not in {"sha1", "sha256"}:
        raise RuntimeError("Unsupported CVE snapshot object format")
    files = {}
    for entry in git("ls-tree", "-rz", "--full-tree", revision, "--", "cves").split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if path != "cves/deltaLog.json" and not re.fullmatch(r"cves/[12][0-9]{3}/[^/]+/CVE-[0-9]{4}-[0-9]{4,}\.json", path):
            continue
        mode, kind, oid = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise RuntimeError(f"Invalid catch-up snapshot entry: {path}")
        files[path] = oid
    if "cves/deltaLog.json" not in files or len(files) < 2:
        raise RuntimeError("CVE List V5 HEAD must track deltaLog.json and CVE records")
    return revision, files, algorithm


def read_snapshot_json(path: Path, oid: str, algorithm: str) -> dict | list:
    try:
        if path.is_symlink():
            raise ValueError("symlink")
        raw = path.read_bytes()
        digest = hashlib.new(algorithm, f"blob {len(raw)}\0".encode() + raw).hexdigest()
        if digest != oid:
            raise ValueError("blob differs from pinned HEAD")
        return json.loads(raw)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Invalid catch-up snapshot file (missing, dirty or sparse): {path}") from exc


def load_catch_up_records(snapshot: Path) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], str]:
    """Recover a retention gap from verified files in a pinned CVE List checkout."""
    revision, files, algorithm = catch_up_snapshot_files(snapshot)
    log = read_snapshot_json(snapshot / "cves/deltaLog.json", files["cves/deltaLog.json"], algorithm)
    if not isinstance(log, list) or not log:
        raise RuntimeError("Snapshot CVE delta log is empty")
    checkpoint = str(log[0].get("fetchTime") or "")
    snapshot_time = parse_delta_time(checkpoint)
    previous = load_state()
    if not previous:
        raise RuntimeError("Catch-up requires an existing CVE delta checkpoint")
    previous_time = parse_delta_time(previous)
    if snapshot_time <= previous_time:
        raise RuntimeError("Catch-up snapshot does not advance the existing CVE delta checkpoint")
    records: dict[str, dict[str, Any]] = {}
    references: dict[str, list[str]] = {}
    blacklist = load_blacklist()
    scanned = 0
    for relative, oid in files.items():
        if relative == "cves/deltaLog.json":
            continue
        path = snapshot / relative
        record = read_snapshot_json(path, oid, algorithm)
        if not isinstance(record, dict) or record_cve_id(record) != path.stem:
            raise RuntimeError(f"Invalid catch-up CVE record: {path}")
        scanned += 1
        meta = record.get("cveMetadata") or {}
        modified = str(meta.get("dateUpdated") or meta.get("datePublished") or "")
        if modified and parse_delta_time(modified) <= previous_time:
            continue
        state = str(meta.get("state") or "").upper()
        if state not in {"PUBLISHED", "REJECTED", "RESERVED"} or (state == "PUBLISHED" and details_from_record(record) is None):
            raise RuntimeError(f"Incomplete catch-up CVE record: {path}")
        cve_id = record_cve_id(record)
        records[cve_id] = record
        if selected := poc_references(record, blacklist):
            references[cve_id] = selected
    if not scanned:
        raise RuntimeError("Catch-up snapshot contains no CVE records")
    print(f"CVE List V5 catch-up ({revision[:12]}): {scanned} records scanned, {len(records)} changed since {previous}")
    return records, references, checkpoint


def fetch_records(urls: dict[str, str], *, allow_not_found: bool) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    failures: list[str] = []

    def fetch(cve_id: str, url: str) -> tuple[str, dict[str, Any] | None]:
        result = http_json(url, allow_not_found=allow_not_found)
        if result is None and allow_not_found:
            return cve_id, None
        if (
            not isinstance(result, dict)
            or record_cve_id(result) != cve_id
            or str((result.get("cveMetadata") or {}).get("state") or "").upper()
            not in {"PUBLISHED", "RESERVED", "REJECTED"}
            or (record_is_published(result) and details_from_record(result) is None)
        ):
            raise RuntimeError("Incomplete or mismatched CVE record")
        return cve_id, result

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(fetch, cve_id, url): cve_id for cve_id, url in urls.items()}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                fetched_cve, record = future.result()
            except Exception as exc:
                failures.append(f"{cve_id}: {exc}")
                continue
            if record:
                records[fetched_cve] = record

    if failures:
        raise RuntimeError("Failed to fetch CVE records: " + "; ".join(failures[:10]))
    return records


def load_incremental_records(
    cve_filter: set[str],
    *, bootstrap: bool = False,
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], str]:
    checkpoint = load_state(allow_missing=bootstrap)
    if bootstrap and checkpoint:
        raise RuntimeError("--bootstrap-delta requires a missing checkpoint; existing state cannot be reset")
    changes, newest = delta_changes(checkpoint, bootstrap=bootstrap)
    if cve_filter:
        changes = {cve_id: url for cve_id, url in changes.items() if cve_id in cve_filter}
    records = fetch_records(changes, allow_not_found=False) if changes else {}
    blacklist = load_blacklist()
    references = {
        cve_id: selected
        for cve_id, record in records.items()
        if (selected := poc_references(record, blacklist))
    }
    return records, references, newest


def fetch_missing_records(
    cve_ids: Iterable[str],
    records: dict[str, dict[str, Any]],
) -> None:
    urls = {
        cve_id: CVE_API_URL.format(cve_id=cve_id)
        for cve_id in cve_ids
        if cve_id not in records
    }
    if urls:
        records.update(fetch_records(urls, allow_not_found=True))


def record_dates(records: dict[str, dict[str, Any]], *, dry_run: bool) -> int:
    """Keep cve_dates.json current from the records this run already fetched.

    The file was seeded from the CVE Program's daily 590 MB release; every
    record the delta log hands us afterwards carries its own dates, so the
    archive never has to be downloaded again.
    """
    try:
        stored = json.loads(DATES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        stored = {}
    changed = 0
    for cve_id, record in records.items():
        meta = record.get("cveMetadata") or {}
        published = str(meta.get("datePublished") or "")[:10]
        modified = str(meta.get("dateUpdated") or meta.get("dateReserved") or "")[:10]
        if not published and not modified:
            continue
        value = [published, modified]
        if stored.get(cve_id) != value:
            stored[cve_id] = value
            changed += 1
    if changed and not dry_run:
        DATES_FILE.write_text(
            json.dumps(stored, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return changed


def cvelist_record_path(cvelist_dir: Path, cve_id: str) -> Path:
    """Resolve one CVE List V5 record without scanning the full corpus."""
    base = cvelist_dir / "cves" if (cvelist_dir / "cves").is_dir() else cvelist_dir
    _, year, number = cve_id.split("-", 2)
    bucket = f"{int(number) // 1000}xxx"
    return base / year / bucket / f"{cve_id}.json"


def load_record_state(path: Path = RECORD_STATE_FILE) -> dict[str, dict[str, str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def retry_record(entry: dict[str, str], today: date) -> bool:
    if str(entry.get("status") or "").upper() == "REJECTED":
        return False
    try:
        checked = date.fromisoformat(str(entry.get("checked") or ""))
    except ValueError:
        return True
    return (today - checked).days >= RECORD_RETRY_DAYS


def ensure_cve_entries(
    cve_ids: Iterable[str],
    *,
    dry_run: bool,
    cvelist_dir: Path | None = None,
) -> tuple[set[str], set[str]]:
    """Create base markdown for published source CVEs missing from the index.

    A local CVE List checkout is the efficient path for a large backfill. The
    normal scheduled jobs ask the CVE Services API only for new gaps.
    """
    wanted = {
        cve_id.upper()
        for cve_id in cve_ids
        if is_valid_cve(cve_id.upper())
        and not (CVES / cve_id.split("-")[1] / f"{cve_id.upper()}.md").exists()
    }
    state = load_record_state()
    state = {
        cve_id: value
        for cve_id, value in state.items()
        if not (CVES / cve_id.split("-")[1] / f"{cve_id}.md").exists()
    }
    if not wanted:
        if not dry_run and RECORD_STATE_FILE.exists():
            RECORD_STATE_FILE.write_text(
                json.dumps(state, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return set(), set()
    if cvelist_dir is not None and not cvelist_dir.is_dir():
        raise ValueError(f"CVE List directory does not exist: {cvelist_dir}")

    today = datetime.now(timezone.utc).date()
    due = wanted if cvelist_dir is not None else {
        cve_id for cve_id in wanted if retry_record(state.get(cve_id, {}), today)
    }
    records: dict[str, dict[str, Any]] = {}
    if cvelist_dir is not None:
        for cve_id in sorted(due):
            path = cvelist_record_path(cvelist_dir, cve_id)
            if record := read_record(path):
                records[cve_id] = record

    fetch_missing_records(due, records)
    created: set[str] = set()
    unavailable: set[str] = wanted - due
    kev = load_kev()
    for cve_id in sorted(due):
        record = records.get(cve_id) or {}
        details = details_from_record(record)
        if details is None:
            unavailable.add(cve_id)
            status = str((record.get("cveMetadata") or {}).get("state") or "UNAVAILABLE").upper()
            state[cve_id] = {"status": status, "checked": today.isoformat()}
            continue
        path = CVES / cve_id.split("-")[1] / f"{cve_id}.md"
        if not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(build_markdown(cve_id, details, [], [], kev), encoding="utf-8")
        created.add(cve_id)
        state.pop(cve_id, None)

    record_dates(records, dry_run=dry_run)
    if not dry_run:
        RECORD_STATE_FILE.write_text(
            json.dumps(state, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return created, unavailable


def load_kev(path: Path = KEV_FILE) -> dict[str, list]:
    """CISA's known-exploited catalogue, as refreshed by the weekly audit."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def kev_badge(cve_id: str, kev: dict[str, list]) -> str:
    """The one badge that says an attacker is using this today."""
    entry = kev.get(cve_id.upper())
    if not entry:
        return ""
    ransomware = len(entry) > 1 and entry[1]
    return badge("CISA KEV", "Known Exploited · Ransomware" if ransomware else "Known Exploited", "red")


def badge(label: str, message: str, color: str) -> str:
    return (
        "![](https://img.shields.io/static/v1?"
        f"label={quote(label, safe='')}&message={quote(message, safe='')}&color={color})"
    )


def record_preamble(cve_id: str, details: CVEDetails, kev: dict[str, list] | None = None) -> list[str]:
    """Everything above the description: the heading, the record's own title
    in bold, and one badge per vendor, product, version and weakness.

    The title and the vendor are what people search for and what the
    description often never names: "PAN-OS: OS Command Injection in
    GlobalProtect" says more than a paragraph that opens with "A command
    injection as a result of arbitrary file creation".
    """
    lines = [f"### [{cve_id}](https://www.cve.org/CVERecord?id={cve_id})"]
    if details.title:
        lines.append(f"**{details.title}**")
    products = details.products or ["n/a"]
    versions = details.versions or ["n/a"]
    vulnerabilities = details.vulnerabilities or ["n/a"]
    version_color = "brightgreen" if details.versions else "blue"
    vuln_color = "brightgreen" if details.vulnerabilities else "blue"
    lines.extend(badge("Vendor", value, "blue") for value in details.vendors)
    lines.extend(badge("Product", value, "blue") for value in products)
    lines.extend(badge("Version", value, version_color) for value in versions)
    lines.extend(badge("Vulnerability", value, vuln_color) for value in vulnerabilities)
    known_exploited = kev_badge(cve_id, kev or {})
    if known_exploited:
        lines.append(known_exploited)
    return lines


def refresh_record_header(path: Path, details: CVEDetails, kev: dict[str, list], *, dry_run: bool) -> bool:
    """Rewrite one existing record's preamble from its current CVE record.

    Only the lines above "### Description" move; the description and every
    PoC section stay byte for byte, so a record whose title, vendor or
    products did not change is not touched at all.
    """
    with path.open("r", encoding="utf-8", newline="") as handle:
        text = handle.read()
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(newline)
    anchor = next((i for i, line in enumerate(lines) if line.strip() == "### Description"), None)
    if anchor is None:
        return False
    updated = newline.join([*record_preamble(path.stem.upper(), details, kev), "", *lines[anchor:]])
    if updated == text:
        return False
    if not dry_run:
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(updated)
    return True


def refresh_record_headers(records: dict[str, dict[str, Any]], *, dry_run: bool) -> int:
    """Refresh the preamble of every existing record among those given."""
    kev = load_kev()
    refreshed = 0
    for cve_id, record in records.items():
        path = CVES / cve_id.split("-")[1] / f"{cve_id}.md"
        if not path.exists():
            continue
        details = details_from_record(record or {})
        if details is None:
            continue
        if refresh_record_header(path, details, kev, dry_run=dry_run):
            refreshed += 1
    return refreshed


def refresh_all_record_headers(cvelist_dir: Path, *, dry_run: bool) -> tuple[int, int]:
    """The one-off pass over every record, from a local CVE List checkout.

    Reads the records one at a time: the whole list is 330,000 JSON files and
    holding them all would need most of a gigabyte for nothing.
    """
    kev = load_kev()
    seen = refreshed = 0
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        cve_id = path.stem.upper()
        record = read_record(cvelist_record_path(cvelist_dir, cve_id))
        if not record:
            continue
        details = details_from_record(record)
        if details is None:
            continue
        seen += 1
        if refresh_record_header(path, details, kev, dry_run=dry_run):
            refreshed += 1
        if seen % 20000 == 0:
            print(f"{seen:,} records read, {refreshed:,} refreshed", flush=True)
    return seen, refreshed


def build_markdown(
    cve_id: str,
    details: CVEDetails,
    github_links: list[str],
    references: list[str],
    kev: dict[str, list] | None = None,
) -> str:
    description = "\n".join(
        line.expandtabs(4).rstrip() for line in details.description.strip().splitlines()
    )
    lines = record_preamble(cve_id, details, kev)
    lines.extend(["", "### Description", "", description, "", "### POC", "", "#### Reference"])
    lines.extend((f"- {url}" for url in references) if references else ["No PoCs from references."])
    lines.extend(["", "#### Github"])
    lines.extend((f"- {url}" for url in github_links) if github_links else ["No PoCs found on GitHub currently."])
    lines.append("")
    return "\n".join(lines)


def parse_section_links(block: str) -> list[str]:
    links: list[str] = []
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("No PoCs"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith(("http://", "https://")):
            links.append(line)
    return stable_unique(links)


def section_links(text: str, header: str) -> list[str]:
    pattern = re.compile(SECTION_RE_TEMPLATE.format(header=re.escape(header)), re.DOTALL)
    match = pattern.search(text)
    return parse_section_links(match.group(2)) if match else []


def merge_section(text: str, header: str, links: Iterable[str], empty_text: str) -> tuple[str, bool]:
    incoming = stable_unique_poc_links(links)
    if not incoming:
        return text, False
    pattern = re.compile(SECTION_RE_TEMPLATE.format(header=re.escape(header)), re.DOTALL)
    match = pattern.search(text)
    if not match:
        return text, False
    existing = parse_section_links(match.group(2))
    combined = stable_unique_poc_links([*existing, *incoming])
    if combined == existing:
        return text, False
    return replace_section(text, header, combined, empty_text)


def replace_section(
    text: str,
    header: str,
    links: Iterable[str],
    empty_text: str,
) -> tuple[str, bool]:
    values = stable_unique_poc_links(links)
    pattern = re.compile(SECTION_RE_TEMPLATE.format(header=re.escape(header)), re.DOTALL)
    match = pattern.search(text)
    if not match:
        return text, False
    newline = "\r\n" if "\r\n" in match.group(1) else "\n"
    replacement = newline.join(f"- {url}" for url in values) if values else empty_text
    body = match.group(2)
    trailing = body[len(body.rstrip()) :] or newline
    updated = text[: match.start(2)] + replacement + trailing + text[match.end(2) :]
    return updated, updated != text


def update_existing_markdown(
    path: Path,
    github_links: list[str],
    references: list[str],
    *,
    dry_run: bool,
) -> bool:
    with path.open("r", encoding="utf-8", newline="") as handle:
        original = handle.read()
    updated, reference_changed = merge_section(
        original,
        "#### Reference",
        references,
        "No PoCs from references.",
    )
    existing_github = section_links(updated, "#### Github")
    # Qualification is evidence the reference section alone may not carry.
    github_values = stable_unique_poc_links([*existing_github, *github_links])
    updated, github_changed = replace_section(
        updated,
        "#### Github",
        github_values,
        "No PoCs found on GitHub currently.",
    )
    if not (reference_changed or github_changed):
        return False
    if not updated.endswith(("\n", "\r")):
        updated += "\r\n" if "\r\n" in original else "\n"
    if not dry_run:
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(updated)
    return True


def sync_markdown(
    records: dict[str, dict[str, Any]],
    github: dict[str, list[str]],
    references: dict[str, list[str]],
    *,
    dry_run: bool,
) -> tuple[SyncStats, dict[str, list[str]], dict[str, list[str]]]:
    stats = SyncStats()
    kev = load_kev()
    accepted_github: dict[str, list[str]] = {}
    accepted_references: dict[str, list[str]] = {}
    cve_ids = sorted(set(github) | set(references))

    for cve_id in cve_ids:
        year = cve_id.split("-")[1]
        path = CVES / year / f"{cve_id}.md"
        github_links = [url for url in stable_unique(github.get(cve_id, []))
                        if cve_id not in source_artifacts.excluded_cves(github_repo_from_url(url))]
        reference_links = [url for url in stable_unique(references.get(cve_id, []))
                           if cve_id not in source_artifacts.excluded_cves(github_repo_from_url(url))]
        record = records.get(cve_id)

        if record and not record_is_published(record):
            stats.skipped.append(f"{cve_id}: CVE is not published")
            continue

        if path.exists():
            if update_existing_markdown(
                path,
                github_links,
                reference_links,
                dry_run=dry_run,
            ):
                stats.updated.append(cve_id)
        else:
            details = details_from_record(record or {})
            if not details:
                stats.skipped.append(f"{cve_id}: published CVE metadata is unavailable")
                continue
            if not dry_run:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    build_markdown(cve_id, details, github_links, reference_links, kev),
                    encoding="utf-8",
                )
            stats.created.append(cve_id)

        accepted_github[cve_id] = github_links
        accepted_references[cve_id] = reference_links

    return stats, accepted_github, accepted_references


def append_inventory(path: Path, mappings: dict[str, list[str]], *, dry_run: bool) -> int:
    existing = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    additions = sorted(
        f"{cve_id} - {url}"
        for cve_id, urls in mappings.items()
        for url in urls
        if url and f"{cve_id} - {url}" not in existing
    )
    if not additions or dry_run:
        return len(additions)
    prefix = ""
    if path.exists() and path.stat().st_size and not path.read_bytes().endswith(b"\n"):
        prefix = "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(prefix + "\n".join(additions) + "\n")
    return len(additions)


def reconcile_inventory(
    path: Path,
    section: str,
    mappings: dict[str, list[str]],
    *,
    dry_run: bool,
) -> tuple[int, int]:
    """Make an inventory an exact view of its markdown section."""
    expected = {
        f"{md_path.stem} - {url}"
        for md_path in CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")
        for url in section_links(md_path.read_text(encoding="utf-8", errors="replace"), section)
    }
    expected.update(
        f"{cve_id} - {url}"
        for cve_id, urls in mappings.items()
        for url in urls
        if url
    )
    current_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    current = set(current_lines)
    additions = len(expected - current)
    removals = len(current - expected) + len(current_lines) - len(current)
    if not dry_run and (additions or removals):
        seen: set[str] = set()
        kept: list[str] = []
        for line in current_lines:
            if line in expected and line not in seen:
                kept.append(line)
                seen.add(line)
        path.write_text(
            "\n".join([*kept, *sorted(expected - seen)]) + "\n",
            encoding="utf-8",
        )
    return additions, removals


def write_state(fetch_time: str, *, dry_run: bool) -> None:
    if not fetch_time or dry_run:
        return
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps({"cvelist_fetch_time": fetch_time}, indent=2) + "\n",
        encoding="utf-8",
    )


def load_discovery_state() -> dict[str, Any]:
    if not DISCOVERY_STATE_FILE.exists():
        return {"years": {}, "pending": {}}
    state = json.loads(DISCOVERY_STATE_FILE.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or not all(isinstance(state.get(key), dict) for key in ("years", "pending")):
        raise ValueError("Invalid GitHub discovery state")
    for year, endpoint in state["years"].items():
        if not re.fullmatch(r"\d{4}", year):
            raise ValueError("Invalid GitHub discovery year")
        date.fromisoformat(endpoint)
    for cve_id, entry in state["pending"].items():
        if not is_valid_cve(cve_id) or not isinstance(entry, dict) or any(
            not isinstance(entry.get(key), list) or any(not isinstance(url, str) for url in entry[key])
            for key in ("github", "references")
        ):
            raise ValueError("Invalid pending GitHub discovery")
    return state


def write_discovery_state(state: dict[str, Any]) -> None:
    DISCOVERY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = DISCOVERY_STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(DISCOVERY_STATE_FILE)


def newest_delta_time() -> str:
    log = http_json(CVELIST_DELTA_LOG_URL)
    if not isinstance(log, list) or not log:
        raise RuntimeError("CVE List V5 delta log is empty")
    return str(log[0].get("fetchTime") or "")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover and ingest CVE PoC links")
    parser.add_argument("--bootstrap-delta", action="store_true", help="Explicitly initialize a missing checkpoint from all retained CVE delta batches; earlier history needs a separate backfill")
    parser.add_argument("--catch-up-dir", type=Path, help="CVE List V5 Git checkout root; verifies every tracked CVE JSON against pinned HEAD before recovery")
    parser.add_argument("--backfill-dir", type=Path, help="Local CVE List V5 year directory")
    parser.add_argument("--year", type=int, help="Year to backfill")
    parser.add_argument("--lookback-days", type=int, default=3, help="GitHub pushed-date overlap")
    parser.add_argument("--years", type=int, default=2, help="Number of recent years to scan")
    parser.add_argument("--all-years", action="store_true", help="Scan every CVE year since 1999")
    parser.add_argument("--cve", action="append", default=[], help="Process one CVE ID")
    parser.add_argument("--skip-github", action="store_true", help="Skip GitHub repository discovery")
    parser.add_argument("--skip-cvelist", action="store_true", help="Skip CVE List V5 references")
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing files")
    parser.add_argument("--cvelist-dir", type=Path, help="Local CVE List V5 checkout")
    parser.add_argument(
        "--refresh-headers",
        action="store_true",
        help="Rewrite the title and badges of every record from --cvelist-dir, and do nothing else",
    )
    args = parser.parse_args()
    if args.bootstrap_delta and (args.catch_up_dir or args.backfill_dir or args.cve or args.skip_cvelist or args.refresh_headers):
        parser.error("--bootstrap-delta cannot be filtered, skipped, or combined with catch-up/backfill/header refresh")
    if bool(args.backfill_dir) != bool(args.year):
        parser.error("--backfill-dir and --year must be used together")
    if args.catch_up_dir and (args.backfill_dir or args.cve or args.skip_cvelist or args.refresh_headers):
        parser.error("--catch-up-dir cannot be filtered, skipped, or combined with backfill/header refresh")
    if args.lookback_days < 1 or args.years < 1:
        parser.error("--lookback-days and --years must be positive")
    return args


def main() -> int:
    args = parse_args()
    cve_filter = {cve.upper() for cve in args.cve if is_valid_cve(cve.upper())}
    if args.cve and len(cve_filter) != len(args.cve):
        raise SystemExit("Every --cve value must be a valid CVE ID")

    if args.refresh_headers:
        if not args.cvelist_dir or not args.cvelist_dir.is_dir():
            raise SystemExit("--refresh-headers needs --cvelist-dir pointing at a CVE List V5 checkout")
        seen, refreshed = refresh_all_record_headers(args.cvelist_dir, dry_run=args.dry_run)
        print(f"Record headers: {seen:,} records read, {refreshed:,} refreshed")
        return 0

    backfill = bool(args.backfill_dir)
    records: dict[str, dict[str, Any]] = {}
    references: dict[str, list[str]] = {}
    record_paths: dict[str, Path] = {}
    checkpoint = ""
    discovery_end = datetime.now(timezone.utc).date()
    discovery_state = load_discovery_state() if not args.skip_github and not cve_filter else None
    years: list[int] = []

    if not args.skip_cvelist:
        if getattr(args, "catch_up_dir", None):
            records, references, checkpoint = load_catch_up_records(args.catch_up_dir)
            references = filter_live_references(references)
        elif backfill:
            records, references, record_paths = load_backfill_records(
                args.backfill_dir,
                args.year,
                cve_filter,
            )
            print(f"CVE List V5 backfill: {len(references)} CVEs with PoC references")
        else:
            records, references, checkpoint = load_incremental_records(cve_filter, bootstrap=getattr(args, "bootstrap_delta", False))
            references = filter_live_references(references)

    github: dict[str, list[str]] = {}
    if not args.skip_github:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        current_year = datetime.now(timezone.utc).year
        if backfill:
            years = [args.year]
        elif args.all_years:
            years = list(range(current_year, 1998, -1))
        else:
            years = list(range(current_year, current_year - args.years, -1))
        github = discover_github_pocs(
            token,
            years=years,
            lookback_days=args.lookback_days,
            backfill=backfill,
            cve_filter=cve_filter,
            window_end=discovery_end,
            checkpoints=discovery_state["years"] if discovery_state else None,
            artifact_cache_write=not args.dry_run,
        )
        print(f"GitHub discovery: {sum(len(urls) for urls in github.values())} links for {len(github)} CVEs")

    if backfill:
        for cve_id in set(github) - set(records):
            path = record_paths.get(cve_id)
            if path and (record := read_record(path)):
                records[cve_id] = record
    deferred: set[str] = set()
    if discovery_state is not None:
        for cve_id, pending in discovery_state["pending"].items():
            if backfill and int(cve_id.split("-")[1]) not in years:
                continue
            for mappings, field in ((github, "github"), (references, "references")):
                if pending[field]:
                    mappings[cve_id] = stable_unique([*mappings.get(cve_id, []), *pending[field]])
            if not retry_record(pending, discovery_end):
                deferred.add(cve_id)
    candidates = set(github) | set(references)
    fetch_missing_records(candidates - deferred, records)

    stats, accepted_github, accepted_references = sync_markdown(
        records,
        github,
        references,
        dry_run=args.dry_run,
    )
    github_additions, github_removals = reconcile_inventory(
        GITHUB_LIST,
        "#### Github",
        accepted_github,
        dry_run=args.dry_run,
    )
    reference_additions, reference_removals = reconcile_inventory(
        REFERENCE_LIST,
        "#### Reference",
        accepted_references,
        dry_run=args.dry_run,
    )
    verified_reference_additions = append_inventory(
        VERIFIED_REFERENCE_LIST,
        accepted_references,
        dry_run=args.dry_run,
    )

    # A record that changed upstream may have a new title, vendor or product
    # list; the ones fetched this run are refreshed in place.
    refreshed = refresh_record_headers(records, dry_run=args.dry_run)
    dated = record_dates(records, dry_run=args.dry_run)
    if not backfill and not cve_filter:
        write_state(checkpoint, dry_run=args.dry_run)
    if discovery_state is not None and not args.dry_run:
        for cve_id in candidates:
            record = records.get(cve_id) or {}
            status = str((record.get("cveMetadata") or {}).get("state") or "UNAVAILABLE").upper()
            if cve_id in accepted_github or cve_id in accepted_references or status == "REJECTED":
                discovery_state["pending"].pop(cve_id, None)
            else:
                previous = discovery_state["pending"].get(cve_id, {})
                discovery_state["pending"][cve_id] = {
                    "github": github.get(cve_id, []),
                    "references": references.get(cve_id, []),
                    "status": previous.get("status", status) if cve_id in deferred else status,
                    "checked": previous["checked"] if cve_id in deferred else discovery_end.isoformat(),
                }
        discovery_state["years"].update({str(year): discovery_end.isoformat() for year in years})
        write_discovery_state(discovery_state)

    print(
        f"Created: {len(stats.created)} | Updated: {len(stats.updated)} | "
        f"Skipped: {len(stats.skipped)}"
    )
    print(
        f"Inventory changes: +{github_additions}/-{github_removals} GitHub | "
        f"+{reference_additions}/-{reference_removals} references | "
        f"{verified_reference_additions} verified references added | "
        f"{dated} publication dates | {refreshed} headers refreshed"
    )
    if stats.skipped:
        for entry in stats.skipped[:20]:
            print(f"Skipped {entry}")
        if len(stats.skipped) > 20:
            print(f"Skipped {len(stats.skipped) - 20} additional CVEs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
