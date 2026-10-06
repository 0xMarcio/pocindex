#!/usr/bin/env python3
"""Sync published CVSS scores, advisories and advisory-hosted PoCs.

NVD remains the normalized primary feed. CVE List V5, CISA Vulnrichment,
GitHub's reviewed advisory database and a small vendor ledger fill gaps where
NVD has not published a vector. Every source must supply its own vector and
score. This script never calculates or guesses one.
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import update_cves

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cves"
INDEX = ROOT / "index"
OUTPUT = INDEX / "metadata"
ADVISORY_FILE = INDEX / "advisory_hosts.txt"
GITHUB_CACHE = INDEX / "github_advisories.json"
VENDOR_FILE = INDEX / "vendor_cvss.json"
FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/2.0"
GITHUB_API = "https://api.github.com/advisories"
CVELIST_ROOT = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
VULNRICHMENT_ROOT = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
USER_AGENT = "0xMarcio-cve-metadata"
CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
VECTOR_VERSION = re.compile(r"^CVSS:(4\.0|3\.1|3\.0)/")
POC_HEADING = re.compile(
    r"(?im)^\s{0,3}(?:#{1,6}\s+|\*\*)?"
    r"(?:poc|proof[ -]of[ -]concept|reproducer|reproduction(?: steps)?|"
    r"steps to reproduce|exploit(?: code| steps| example)?)"
    r"(?:\*\*)?\s*:?.*$"
)
MARKDOWN_HEADING = re.compile(r"(?m)^\s{0,3}#{1,6}\s+")
CODE_BLOCK = re.compile(r"```[^\n]*\n.{40,}?```", re.DOTALL)
RUN_COMMAND = re.compile(
    r"(?im)^\s*(?:\$\s*)?(?:curl|wget|python\d*|bash|sh|powershell|pwsh|"
    r"node|php|ruby|java|go run)\b|^(?:GET|POST|PUT|PATCH|DELETE)\s+\S+\s+HTTP/"
)

# Positive assessments are canonical when sources disagree. Within that,
# newest CVSS generation comes first; every generation remains in the tooltip.
METRIC_FIELDS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
CVE_METRIC_FIELDS = (
    ("cvssV4_0", "4.0"),
    ("cvssV3_1", "3.1"),
    ("cvssV3_0", "3.0"),
    ("cvssV2_0", "2.0"),
)
VERSION_ORDER = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
ENRICHMENT_ASSESSMENTS = {
    "CVE Program CNA",
    "CVE Program ADP",
    "CISA Vulnrichment",
    "GitHub Reviewed",
}

ADVISORY_TAGS = {
    "vendor advisory",
    "third party advisory",
    "mitigation",
    "patch",
    "release notes",
    "product",
    "issue tracking",
}
PRESERVED_TAGS = ADVISORY_TAGS | {"exploit"}
TAG_ORDER = {
    "Vendor Advisory": 0,
    "Third Party Advisory": 1,
    "GitHub Advisory": 2,
    "Mitigation": 3,
    "Patch": 4,
    "Release Notes": 5,
    "Product": 6,
    "Issue Tracking": 7,
    "Advisory": 8,
    "Exploit": 9,
}
TAG_NAMES = {tag.lower(): tag for tag in TAG_ORDER}
SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def local_cves() -> set[str]:
    return {
        path.stem.upper()
        for path in CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")
        if CVE.fullmatch(path.stem.upper())
    }


def load_advisory_rules() -> tuple[str, ...]:
    try:
        lines = ADVISORY_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    return tuple(
        line.strip().lower()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )


def matches_advisory_rule(url: str, rules: Iterable[str]) -> bool:
    target = re.sub(r"^https?://(?:www\.)?", "", url.strip().lower())
    return any(target.startswith(rule) for rule in rules)


def qualitative_severity(version: str, score: float) -> str:
    if score == 0 and version != "2.0":
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if version == "2.0" or score < 9:
        return "HIGH"
    return "CRITICAL"


def vector_version(vector: str, fallback: str) -> str:
    match = VECTOR_VERSION.match(vector)
    if match:
        return match.group(1)
    return "2.0" if fallback == "2.0" else fallback


def published_metric(
    data: dict[str, Any],
    fallback_version: str,
    source: str,
    assessment: str,
) -> list[Any] | None:
    vector = str(data.get("vectorString") or "").strip()
    try:
        score = round(float(data["baseScore"]), 1)
    except (KeyError, TypeError, ValueError):
        return None
    if not vector or not 0 <= score <= 10:
        return None
    version = vector_version(vector, str(data.get("version") or fallback_version).strip())
    if version not in VERSION_ORDER:
        return None
    severity = str(data.get("baseSeverity") or "").upper()
    if severity not in SEVERITIES:
        severity = qualitative_severity(version, score)
    return [version, score, severity, vector, source, assessment]


def normalize_metric(metric: dict[str, Any], version: str) -> list[Any] | None:
    data = metric.get("cvssData") or {}
    if "baseSeverity" not in data and metric.get("baseSeverity"):
        data = {**data, "baseSeverity": metric["baseSeverity"]}
    source = str(metric.get("source") or "").strip()
    assessment = str(metric.get("type") or "").strip()
    return published_metric(data, version, source, assessment)


def metric_rank(row: list[Any]) -> tuple[int, int, int, int, str, str]:
    source = str(row[4]).lower()
    assessment = str(row[5]).lower()
    assessment_order = {
        "primary": 0,
        "cve program cna": 2,
        "vendor advisory": 3,
        "security vendor": 3,
        "cve program adp": 4,
        "cisa vulnrichment": 4,
        "github reviewed": 5,
    }
    return (
        0 if isinstance(row[1], (int, float)) and row[1] > 0 else 1,
        VERSION_ORDER.get(str(row[0]), 99),
        assessment_order.get(assessment, 1),
        0 if source == "nvd@nist.gov" else 1,
        source,
        str(row[3]),
    )


def merge_metrics(*groups: Iterable[list[Any]]) -> list[list[Any]]:
    selected: dict[tuple[Any, ...], list[Any]] = {}
    for rows in groups:
        for row in rows:
            if not isinstance(row, list) or len(row) < 6:
                continue
            key = tuple(row[:5])
            current = selected.get(key)
            if current is None or metric_rank(row) < metric_rank(current):
                selected[key] = row[:6]
    return sorted(selected.values(), key=metric_rank)


def cvss_metrics(cve: dict[str, Any]) -> list[list[Any]]:
    metrics = cve.get("metrics") or {}
    selected: list[list[Any]] = []
    for field, version in METRIC_FIELDS:
        rows = [
            normalized
            for item in metrics.get(field) or []
            if isinstance(item, dict)
            if (normalized := normalize_metric(item, version)) is not None
        ]
        selected.extend(rows)
    return merge_metrics(selected)


def advisory_links(cve: dict[str, Any], rules: Iterable[str]) -> list[list[Any]]:
    links: dict[str, set[str]] = {}
    for reference in cve.get("references") or []:
        if not isinstance(reference, dict):
            continue
        url = str(reference.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        raw_tags = [str(tag).strip() for tag in reference.get("tags") or []]
        advisory_tags = [TAG_NAMES[tag.lower()] for tag in raw_tags if tag.lower() in ADVISORY_TAGS]
        if not advisory_tags and not matches_advisory_rule(url, rules):
            continue
        tags = {TAG_NAMES[tag.lower()] for tag in raw_tags if tag.lower() in PRESERVED_TAGS}
        if not advisory_tags:
            tags.add("Advisory")
        links.setdefault(url.rstrip("/"), set()).update(tags)
    return [
        [url, sorted(tags, key=lambda tag: (TAG_ORDER.get(tag, 99), tag))]
        for url, tags in sorted(
            links.items(),
            key=lambda item: (
                min(TAG_ORDER.get(tag, 99) for tag in item[1]),
                item[0],
            ),
        )
    ]


def metadata_entry(cve: dict[str, Any], rules: Iterable[str]) -> dict[str, Any] | None:
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return {"rejected": True}
    entry: dict[str, Any] = {}
    scores = cvss_metrics(cve)
    advisories = advisory_links(cve, rules)
    if scores:
        entry["cvss"] = scores
    if advisories:
        entry["advisories"] = advisories
    return entry or None


def merge_advisories(*groups: Iterable[list[Any]]) -> list[list[Any]]:
    links: dict[str, set[str]] = {}
    for rows in groups:
        for row in rows:
            if not isinstance(row, list) or not row:
                continue
            url = str(row[0]).strip().rstrip("/")
            if not url.startswith(("http://", "https://")):
                continue
            tags = row[1] if len(row) > 1 and isinstance(row[1], list) else []
            links.setdefault(url, set()).update(str(tag) for tag in tags if str(tag))
    return [
        [url, sorted(tags or {"Advisory"}, key=lambda tag: (TAG_ORDER.get(tag, 99), tag))]
        for url, tags in sorted(
            links.items(),
            key=lambda item: (
                min((TAG_ORDER.get(tag, 99) for tag in item[1]), default=99),
                item[0],
            ),
        )
    ]


def merge_entry(entry: dict[str, Any] | None, addition: dict[str, Any]) -> dict[str, Any]:
    merged = dict(entry or {})
    if merged.get("rejected"):
        return merged
    scores = merge_metrics(merged.get("cvss", []), addition.get("cvss", []))
    advisories = merge_advisories(merged.get("advisories", []), addition.get("advisories", []))
    if scores:
        merged["cvss"] = scores
    else:
        merged.pop("cvss", None)
    if advisories:
        merged["advisories"] = advisories
    else:
        merged.pop("advisories", None)
    return merged


def without_assessments(entry: dict[str, Any], assessments: set[str]) -> dict[str, Any]:
    cleaned = dict(entry)
    rows = [
        row
        for row in cleaned.get("cvss", [])
        if not isinstance(row, list) or len(row) < 6 or str(row[5]) not in assessments
    ]
    if rows:
        cleaned["cvss"] = rows
    else:
        cleaned.pop("cvss", None)
    return cleaned


def without_github_advisories(entry: dict[str, Any]) -> dict[str, Any]:
    cleaned = without_assessments(entry, {"GitHub Reviewed"})
    owned = {update_cves.poc_link_key(url) for url in cleaned.pop("github_poc_only", [])}
    pending = set(cleaned.get("github_poc_pending", []))
    advisories = []
    for url, tags in cleaned.get("advisories", []):
        tags = set(tags)
        if "GitHub Advisory" in tags:
            # Legacy mixed-source rows have no exact Exploit provenance. Keep
            # those until NVD refreshes them; cache-only rows are unambiguous.
            if update_cves.poc_link_key(url) in owned or tags <= {"GitHub Advisory", "Exploit"}:
                tags.discard("Exploit")
            elif "Exploit" in tags:
                pending.add(url)
            tags.discard("GitHub Advisory")
        if tags:
            advisories.append([url, list(tags)])
    if advisories:
        cleaned["advisories"] = merge_advisories(advisories)
    else:
        cleaned.pop("advisories", None)
    if pending:
        cleaned["github_poc_pending"] = sorted(pending)
    return cleaned


def write_compact_json(path: Path, payload: Any, *, dry_run: bool) -> bool:
    rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    try:
        current = path.read_text(encoding="utf-8")
    except OSError:
        current = ""
    if current == rendered:
        return False
    if dry_run:
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(rendered)
        temporary = Path(handle.name)
    temporary.replace(path)
    return True


def load_json_url(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    allow_not_found: bool = False,
    timeout: int = 90,
) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as problem:
            if allow_not_found and problem.code == 404:
                return None
            if problem.code < 500 or attempt == 2:
                raise
        except (TimeoutError, urllib.error.URLError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)
    raise RuntimeError(f"Failed to load {url}")


def advisory_has_poc(description: str) -> bool:
    for heading in POC_HEADING.finditer(description or ""):
        following = description[heading.end() :]
        end = len(following)
        offset = 0
        fenced = False
        for line in following.splitlines(keepends=True):
            marker = line.lstrip()
            if marker.startswith(("```", "~~~")):
                fenced = not fenced
            elif not fenced and MARKDOWN_HEADING.match(line):
                end = offset
                break
            offset += len(line)
        section = following[:end]
        if len(section.strip()) < 80:
            continue
        if CODE_BLOCK.search(section) or RUN_COMMAND.search(section):
            return True
        steps = re.findall(r"(?m)^\s*(?:\d+[.)]|[-*])\s+\S+", section)
        if len(steps) >= 3 and re.search(r"(?i)https?://|payload|request|response|endpoint", section):
            return True
    return False


def github_metrics(advisory: dict[str, Any]) -> list[list[Any]]:
    metrics: list[list[Any]] = []
    severities = advisory.get("cvss_severities") or {}
    for field, version in (("cvss_v4", "4.0"), ("cvss_v3", "3.1")):
        data = severities.get(field)
        if not isinstance(data, dict):
            continue
        normalized = published_metric(
            {"vectorString": data.get("vector_string"), "baseScore": data.get("score")},
            version,
            "GitHub Advisory Database",
            "GitHub Reviewed",
        )
        if normalized:
            metrics.append(normalized)
    top = advisory.get("cvss") or {}
    normalized = published_metric(
        {"vectorString": top.get("vector_string"), "baseScore": top.get("score")},
        "3.1",
        "GitHub Advisory Database",
        "GitHub Reviewed",
    )
    if normalized:
        metrics.append(normalized)
    return merge_metrics(metrics)


def github_cache_entry(advisory: dict[str, Any]) -> list[Any] | None:
    cve_id = str(advisory.get("cve_id") or "").upper()
    ghsa_id = str(advisory.get("ghsa_id") or "").upper()
    if not CVE.fullmatch(cve_id) or not ghsa_id.startswith("GHSA-") or advisory.get("withdrawn_at"):
        return None
    url = str(advisory.get("html_url") or f"https://github.com/advisories/{ghsa_id}").rstrip("/")
    updated = str(advisory.get("updated_at") or advisory.get("published_at") or "")
    return [
        cve_id,
        url,
        github_metrics(advisory),
        1 if advisory_has_poc(str(advisory.get("description") or "")) else 0,
        updated,
    ]


def load_github_cache() -> tuple[str, dict[str, list[Any]]]:
    try:
        payload = json.loads(GITHUB_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "", {}
    if not isinstance(payload, dict):
        return "", {}
    updated = str(payload.pop("_updated", ""))
    return updated, {
        key: value
        for key, value in payload.items()
        if key.startswith("GHSA-") and isinstance(value, list) and len(value) >= 5
    }


class TransientAPIError(RuntimeError):
    """A response worth retrying: rate limited or a server-side failure."""


def github_advisory_pages(*, since: str | None) -> Iterable[list[dict[str, Any]]]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = {
        "type": "reviewed",
        "sort": "updated",
        "direction": "desc",
        "per_page": "100",
    }
    if since:
        params["updated"] = f">={since}"
    path: str | None = f"/advisories?{urllib.parse.urlencode(params)}"
    pages = 0
    connection = http.client.HTTPSConnection("api.github.com", timeout=90)
    try:
        while path:
            for attempt in range(3):
                try:
                    connection.request("GET", path, headers={"User-Agent": USER_AGENT, **headers})
                    response = connection.getresponse()
                    link = response.getheader("Link") or ""
                    body = response.read()
                    if response.status >= 400:
                        message = f"GitHub advisory API {response.status}: {body.decode('utf-8', 'replace')[:300]}"
                        if response.status in (403, 429) or response.status >= 500:
                            raise TransientAPIError(message)
                        raise RuntimeError(message)
                    payload = json.loads(body)
                    break
                except (OSError, http.client.HTTPException, json.JSONDecodeError, TransientAPIError) as problem:
                    connection.close()
                    if attempt == 2:
                        raise
                    # A rate limit or a server error needs a real pause; a dropped
                    # connection only a moment.
                    time.sleep(30 * (attempt + 1) if isinstance(problem, TransientAPIError) else attempt + 1)
                    connection = http.client.HTTPSConnection("api.github.com", timeout=90)
            if not isinstance(payload, list):
                raise RuntimeError("GitHub advisory API returned a non-list payload")
            yield payload
            pages += 1
            if pages % 50 == 0:
                print(f"GitHub advisories: {pages * 100:,} reviewed records fetched", flush=True)
            match = re.search(r'<(https://api\.github\.com/[^>]+)>;\s*rel="next"', link)
            if not match:
                path = None
                continue
            next_url = urllib.parse.urlsplit(match.group(1))
            path = next_url.path + (f"?{next_url.query}" if next_url.query else "")
    finally:
        connection.close()


def github_since(updated: str) -> str | None:
    if not updated:
        return None
    try:
        value = datetime.fromisoformat(updated.replace("Z", "+00:00")) - timedelta(days=2)
    except ValueError:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sync_github_cache(*, full: bool, dry_run: bool) -> dict[str, list[Any]]:
    previous_updated, existing = load_github_cache()
    full = full or not existing
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if full and not token:
        raise RuntimeError("A GITHUB_TOKEN or GH_TOKEN is required for a full advisory sync")
    cache: dict[str, list[Any]] = {} if full else dict(existing)
    newest = "" if full else previous_updated
    processed = 0
    for page in github_advisory_pages(since=None if full else github_since(previous_updated)):
        processed += len(page)
        for advisory in page:
            ghsa_id = str(advisory.get("ghsa_id") or "").upper()
            if not ghsa_id.startswith("GHSA-"):
                continue
            row = github_cache_entry(advisory)
            if row is None:
                cache.pop(ghsa_id, None)
                continue
            cache[ghsa_id] = row
            newest = max(newest, str(row[4]))
    payload = {"_updated": newest, **dict(sorted(cache.items()))}
    changed = write_compact_json(GITHUB_CACHE, payload, dry_run=dry_run)
    pocs = sum(bool(row[3]) for row in cache.values())
    print(
        f"GitHub advisories: {processed:,} fetched, {len(cache):,} cached, "
        f"{pocs:,} with embedded PoCs{' | cache changed' if changed else ''}"
    )
    return cache


def sync_github_pocs(cache: dict[str, list[Any]], *, dry_run: bool) -> None:
    references: dict[str, list[str]] = {}
    for row in cache.values():
        if len(row) >= 4 and row[3] and CVE.fullmatch(str(row[0])):
            references.setdefault(str(row[0]), []).append(str(row[1]))
    for cve_id in references:
        references[cve_id] = sorted(set(references[cve_id]))

    created, unavailable = update_cves.ensure_cve_entries(references, dry_run=dry_run)
    accepted: dict[str, list[str]] = {}
    updated = 0
    for cve_id, urls in sorted(references.items()):
        path = CVES / cve_id.split("-")[1] / f"{cve_id}.md"
        if not path.exists():
            continue
        if update_cves.update_existing_markdown(path, [], urls, dry_run=dry_run):
            updated += 1
        accepted[cve_id] = urls
    additions = update_cves.append_inventory(
        update_cves.REFERENCE_LIST,
        accepted,
        dry_run=dry_run,
    )
    print(
        f"GitHub advisory PoCs: {len(accepted):,} CVEs, {len(created):,} created, "
        f"{updated:,} updated, {additions:,} references added, {len(unavailable):,} unavailable"
    )


def prune_github_pocs(
    previous: dict[str, dict[str, Any]],
    entries: dict[str, dict[str, Any]],
    *,
    dry_run: bool,
) -> None:
    removed: set[tuple[str, str]] = set()
    for cve_id, entry in previous.items():
        pending = {update_cves.poc_link_key(url) for url in entry.get("github_poc_pending", [])}
        supported = {
            update_cves.poc_link_key(url)
            for url, tags in entries.get(cve_id, {}).get("advisories", [])
            if "Exploit" in tags
        }
        removed.update(
            (cve_id, update_cves.poc_link_key(url))
            for url, tags in entry.get("advisories", [])
            if ("GitHub Advisory" in tags or update_cves.poc_link_key(url) in pending) and "Exploit" in tags
            and update_cves.poc_link_key(url) not in supported
        )
    if not removed:
        return
    if update_cves.VERIFIED_REFERENCE_LIST.exists():
        for line in update_cves.VERIFIED_REFERENCE_LIST.read_text(encoding="utf-8").splitlines():
            cve_id, separator, url = line.partition(" - ")
            if separator:
                removed.discard((cve_id, update_cves.poc_link_key(url)))
    for cve_id in sorted({cve_id for cve_id, _ in removed}):
        path = CVES / cve_id.split("-")[1] / f"{cve_id}.md"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        kept = [
            url for url in update_cves.section_links(text, "#### Reference")
            if (cve_id, update_cves.poc_link_key(url)) not in removed
        ]
        updated, changed = update_cves.replace_section(text, "#### Reference", kept, "No PoCs from references.")
        if changed and not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
    inventory = update_cves.REFERENCE_LIST
    if inventory.exists():
        lines = inventory.read_text(encoding="utf-8").splitlines()
        kept_lines = []
        for line in lines:
            cve_id, separator, url = line.partition(" - ")
            if not separator or (cve_id, update_cves.poc_link_key(url)) not in removed:
                kept_lines.append(line)
        if len(kept_lines) != len(lines) and not dry_run:
            inventory.write_text("\n".join(kept_lines) + ("\n" if kept_lines else ""), encoding="utf-8")


def cve_record_url(root: str, cve_id: str) -> str:
    match = CVE.fullmatch(cve_id)
    if not match:
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    bucket = f"{int(match.group(2)) // 1000}xxx"
    return f"{root}/{match.group(1)}/{bucket}/{cve_id}.json"


def provider_name(container: dict[str, Any], fallback: str) -> str:
    provider = container.get("providerMetadata") or {}
    return str(provider.get("shortName") or provider.get("orgId") or fallback)


def container_metrics(container: dict[str, Any], assessment: str) -> list[list[Any]]:
    source = provider_name(container, assessment)
    rows: list[list[Any]] = []
    for item in container.get("metrics") or []:
        if not isinstance(item, dict):
            continue
        for field, version in CVE_METRIC_FIELDS:
            data = item.get(field)
            if not isinstance(data, dict):
                continue
            normalized = published_metric(data, version, source, assessment)
            if normalized:
                rows.append(normalized)
    return rows


def cve_program_metrics(record: dict[str, Any]) -> list[list[Any]]:
    containers = record.get("containers") or {}
    rows: list[list[Any]] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        rows.extend(container_metrics(cna, "CVE Program CNA"))
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            rows.extend(container_metrics(adp, "CVE Program ADP"))
    return merge_metrics(rows)


def cisa_metrics(record: dict[str, Any]) -> list[list[Any]]:
    containers = record.get("containers") or {}
    rows: list[list[Any]] = []
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            rows.extend(container_metrics(adp, "CISA Vulnrichment"))
    return merge_metrics(rows)


def needs_fallback(entry: dict[str, Any]) -> bool:
    rows = entry.get("cvss") or []
    return not rows or any(
        isinstance(row, list) and len(row) >= 6 and str(row[5]) in ENRICHMENT_ASSESSMENTS - {"GitHub Reviewed"}
        for row in rows
    )


def enrich_fallback_metrics(
    entries: dict[str, dict[str, Any]],
    held: set[str],
    previous: dict[str, dict[str, Any]] | None = None,
) -> None:
    previous = previous or {}
    targets = sorted(cve_id for cve_id in held if needs_fallback(entries.get(cve_id, {})))
    if not targets:
        return

    def fetch(cve_id: str) -> tuple[str, list[list[Any]], bool]:
        rows: list[list[Any]] = []
        complete = True
        for root, parser in ((CVELIST_ROOT, cve_program_metrics), (VULNRICHMENT_ROOT, cisa_metrics)):
            try:
                record = load_json_url(cve_record_url(root, cve_id), allow_not_found=True)
                if record is None:
                    continue
                if (
                    not isinstance(record, dict)
                    or update_cves.record_cve_id(record) != cve_id
                    or (record.get("cveMetadata") or {}).get("state") not in {"PUBLISHED", "REJECTED"}
                    or not isinstance(record.get("containers"), dict)
                ):
                    raise ValueError("Incomplete or mismatched CVE record")
                rows.extend(parser(record))
            except Exception as problem:
                print(f"{cve_id}: {root} unavailable ({problem})")
                complete = False
                continue
        return cve_id, merge_metrics(rows), complete

    enriched = 0
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(fetch, cve_id): cve_id for cve_id in targets}
        for future in as_completed(futures):
            cve_id, rows, complete = future.result()
            if not complete:
                retained = [
                    row for row in previous.get(cve_id, {}).get("cvss", [])
                    if len(row) >= 6 and row[5] in ENRICHMENT_ASSESSMENTS - {"GitHub Reviewed"}
                ]
                if retained:
                    entries[cve_id] = merge_entry(entries.get(cve_id), {"cvss": retained})
                continue
            base = without_assessments(
                entries.get(cve_id, {}),
                ENRICHMENT_ASSESSMENTS - {"GitHub Reviewed"},
            )
            entries[cve_id] = merge_entry(base, {"cvss": rows})
            if rows:
                enriched += 1
    print(f"CVE Program and CISA fallbacks: {len(targets):,} checked, {enriched:,} scored")


def load_vendor_entries() -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(VENDOR_FILE.read_text(encoding="utf-8"))
    except OSError:
        return {}
    except json.JSONDecodeError as problem:
        raise RuntimeError(f"Cannot read {VENDOR_FILE}: {problem}") from problem
    if not isinstance(payload, dict):
        raise RuntimeError(f"{VENDOR_FILE} is not a CVE metadata object")
    return {
        cve_id: entry
        for cve_id, entry in payload.items()
        if CVE.fullmatch(cve_id) and isinstance(entry, dict)
    }


def merge_enrichment(
    entries: dict[str, dict[str, Any]],
    held: set[str],
    cache: dict[str, list[Any]],
    previous: dict[str, dict[str, Any]] | None = None,
) -> None:
    for cve_id in held:
        if cve_id in entries:
            entries[cve_id] = without_github_advisories(entries[cve_id])

    enrich_fallback_metrics(entries, held, previous)

    for cve_id, addition in load_vendor_entries().items():
        if cve_id in held:
            entries[cve_id] = merge_entry(entries.get(cve_id), addition)

    for row in cache.values():
        cve_id, url, scores, poc = row[:4]
        if cve_id not in held:
            continue
        entry = entries.get(cve_id) or {}
        if entry.get("rejected"):
            continue
        tags = ["GitHub Advisory"]
        if poc:
            tags.append("Exploit")
            if not any(
                update_cves.poc_link_key(link) == update_cves.poc_link_key(url) and "Exploit" in labels
                for link, labels in entry.get("advisories", [])
            ):
                entry = {**entry, "github_poc_only": sorted({*entry.get("github_poc_only", []), url})}
        entries[cve_id] = merge_entry(
            entry,
            {"cvss": scores, "advisories": [[url, tags]]},
        )


def feed_url(name: str) -> str:
    return f"{FEED_ROOT}/nvdcve-2.0-{name}.json.gz"


def load_feed(name: str) -> list[dict[str, Any]]:
    request = urllib.request.Request(feed_url(name), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=900) as response:
        with gzip.GzipFile(fileobj=response) as compressed:
            payload = json.load(compressed)
    if payload.get("format") != "NVD_CVE" or payload.get("version") != "2.0":
        raise RuntimeError(f"{name}: unexpected NVD feed format")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise RuntimeError(f"{name}: NVD feed has no vulnerability list")
    return vulnerabilities


def load_shards() -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    if not OUTPUT.exists():
        return entries
    for path in sorted(OUTPUT.glob("[12][0-9][0-9][0-9].json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as problem:
            raise RuntimeError(f"Cannot read {path}: {problem}") from problem
        if not isinstance(payload, dict):
            raise RuntimeError(f"{path} is not a CVE metadata object")
        entries.update(payload)
    return entries


def write_shards(entries: dict[str, dict[str, Any]], *, dry_run: bool) -> tuple[int, int]:
    by_year: dict[str, dict[str, Any]] = {}
    for cve_id, entry in entries.items():
        match = CVE.fullmatch(cve_id)
        if match:
            by_year.setdefault(match.group(1), {})[cve_id] = entry

    changed = 0
    removed = 0
    existing = set(OUTPUT.glob("[12][0-9][0-9][0-9].json")) if OUTPUT.exists() else set()
    for year, payload in sorted(by_year.items()):
        path = OUTPUT / f"{year}.json"
        rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        try:
            current = path.read_text(encoding="utf-8")
        except OSError:
            current = ""
        if current == rendered:
            existing.discard(path)
            continue
        try:
            before = len(json.loads(current)) if current else 0
        except ValueError:
            before = 0
        if len(payload) < before * 0.9:
            # A complete run starts from nothing, so a year whose NVD feed came
            # back short would be published short. Withdrawn records are a
            # handful a day; a tenth of a year is a broken feed.
            raise RuntimeError(
                f"{path.name} would shrink from {before:,} to {len(payload):,} CVEs; "
                "refusing to publish a short NVD feed"
            )
        changed += 1
        existing.discard(path)
        if dry_run:
            continue
        OUTPUT.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=OUTPUT, delete=False) as handle:
            handle.write(rendered)
            temporary = Path(handle.name)
        temporary.replace(path)

    for path in existing:
        if path.stat().st_size > len("{}\n"):
            raise RuntimeError(f"{path.name} would be deleted outright; refusing to publish an empty NVD feed")
        removed += 1
        if not dry_run:
            path.unlink()
    return changed, removed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync CVSS, advisories and advisory-hosted PoCs")
    parser.add_argument("--full", action="store_true", help="rebuild NVD and GitHub advisory data")
    parser.add_argument(
        "--github-full",
        action="store_true",
        help="rebuild the reviewed GitHub advisory cache without a full NVD sync",
    )
    parser.add_argument("--year", action="append", type=int, default=[], help="process one NVD feed year")
    parser.add_argument("--dry-run", action="store_true", help="report without writing files")
    args = parser.parse_args()
    if args.full and args.year:
        parser.error("--full and --year cannot be combined")
    return args


def main() -> int:
    args = parse_args()
    github_cache = sync_github_cache(
        full=args.full or args.github_full,
        dry_run=args.dry_run,
    )
    sync_github_pocs(github_cache, dry_run=args.dry_run)
    held = local_cves()
    rules = load_advisory_rules()
    previous = load_shards()
    entries = {} if args.full else dict(previous)
    if args.year:
        feed_names = sorted({str(max(2002, year)) for year in args.year})
    elif args.full:
        feed_names = [str(year) for year in range(2002, datetime.now(timezone.utc).year + 1)]
    else:
        feed_names = ["modified", "recent"]

    seen: set[str] = set()
    processed = 0
    for name in feed_names:
        vulnerabilities = load_feed(name)
        matched = 0
        for wrapper in vulnerabilities:
            cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
            if not isinstance(cve, dict):
                continue
            cve_id = str(cve.get("id") or "").upper()
            if cve_id not in held:
                continue
            entry = metadata_entry(cve, rules)
            if entry is None:
                entries.pop(cve_id, None)
            else:
                entries[cve_id] = entry
            seen.add(cve_id)
            matched += 1
        processed += len(vulnerabilities)
        print(f"{name}: {len(vulnerabilities):,} NVD records, {matched:,} held CVEs")
        del vulnerabilities

    merge_enrichment(entries, held, github_cache, previous)

    # A targeted year run replaces only CVEs present in those NVD feed years.
    # A complete run starts from an empty map, so withdrawn metadata disappears.
    entries = {cve: value for cve, value in entries.items() if cve in held and value}
    changed, removed = write_shards(entries, dry_run=args.dry_run)
    prune_github_pocs(previous, entries, dry_run=args.dry_run)
    scored = sum(bool(entry.get("cvss")) for entry in entries.values())
    advised = sum(bool(entry.get("advisories")) for entry in entries.values())
    rejected = sum(bool(entry.get("rejected")) for entry in entries.values())
    print(
        f"metadata: {len(entries):,} CVEs, {scored:,} scored, {advised:,} with advisories, "
        f"{rejected:,} rejected | {changed:,} shards changed, {removed:,} removed"
    )
    print(f"processed {processed:,} NVD records; {len(seen):,} matched local CVEs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
