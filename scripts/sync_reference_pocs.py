#!/usr/bin/env python3
"""Discover NVD reference candidates and publish only reviewed reproductions."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import os
import re
import signal
import tempfile
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib import error, parse, request

import update_cves

INDEX = update_cves.INDEX
REVIEWS = INDEX / "reference_poc_reviews.json"
QUEUE = INDEX / "reference_poc_queue.json"
VERIFIED = INDEX / "reference_poc_verified.json"
CACHE = update_cves.ROOT / "data" / "reference-pocs"
FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/2.0"
MAX_BODY = 2_000_000


class BudgetExpired(Exception):
    pass


class Budget:
    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds
        self.failures = 0

    def remaining(self) -> float:
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise BudgetExpired
        return seconds

    def read(self, req, *, opener=None, limit=None) -> bytes:
        remaining = self.remaining()
        timeout = min(10, remaining)

        def expired(signum, frame):
            if remaining <= 10:
                raise BudgetExpired
            self.remaining()
            raise TimeoutError("Reference request exceeded 10 seconds")

        handler = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            open_url = opener.open if opener is not None else request.urlopen
            with open_url(req, timeout=timeout) as response:
                body = response.read() if limit is None else response.read(limit)
            self.remaining()
            return body
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, handler)


def supported(url: str) -> bool:
    parsed = parse.urlsplit(url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return False
    if host == "gist.github.com":
        return bool(re.fullmatch(r"/(?:[^/]+/)?[a-fA-F0-9]{20,40}/?", parsed.path))
    if host == "openwall.com":
        return bool(re.fullmatch(r"/lists/(?:oss-security|fulldisclosure)/\d{4}/\d{2}/\d{2}/\d+/?", parsed.path))
    if host == "seclists.org":
        return bool(re.fullmatch(r"/(?:(?:bugtraq|fulldisclosure)/\d{4}/[A-Za-z]+|oss-sec/\d{4}/q[1-4])/\d+(?:\.html)?/?", parsed.path))
    return False


class Preformatted(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks: list[str] = []
        self.parts: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.parts = []
        elif tag == "br" and self.parts is not None:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.parts is not None:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == "pre" and self.parts is not None:
            self.blocks.append("".join(self.parts).replace("\r\n", "\n").strip())
            self.parts = None


def html_artifacts(body: bytes) -> dict[str, str]:
    parser = Preformatted()
    parser.feed(body.decode("utf-8", "replace"))
    return {f"pre:{index}": text for index, text in enumerate(parser.blocks)}


class MailText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_endtag(self, tag):
        if tag in {"pre", "tt", "p", "div"}:
            self.parts.append("\n")

    def handle_starttag(self, tag, attrs):
        if tag == "br":
            self.parts.append("\n")


def mail_artifacts(url: str, body: bytes) -> dict[str, str]:
    artifacts = html_artifacts(body)
    host = parse.urlsplit(url).hostname.removeprefix("www.")
    if host == "openwall.com":
        complete = any(all(re.search(rf"^{field}: .+", text, re.M) for field in ("Date", "From", "Subject")) for text in artifacts.values())
    else:
        complete = all(marker in body for marker in (b"<!--X-Body-of-Message-->", b"<!--X-Body-of-Message-End-->"))
    if not complete or not any(artifacts.values()):
        raise ValueError("Unrecognized or incomplete mail archive response")
    if host == "seclists.org":
        message = body.split(b"<!--X-Body-of-Message-->", 1)[1].split(b"<!--X-Body-of-Message-End-->", 1)[0]
        if not any(html_artifacts(message).values()):
            raise ValueError("Missing mail archive message body")
        parser = MailText()
        parser.feed(message.decode("utf-8", "replace"))
        artifacts["mail:body"] = "".join(parser.parts).replace("\r\n", "\n").strip()
    return artifacts


def gist_artifacts(payload: dict) -> dict[str, str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), dict) or payload.get("truncated"):
        raise ValueError("Incomplete Gist response")
    artifacts = {}
    for name, file in payload["files"].items():
        if not isinstance(file, dict) or file.get("truncated") or not isinstance(file.get("content"), str):
            raise ValueError("Incomplete Gist file")
        artifacts[f"file:{name}"] = file["content"]
    return artifacts


class SourceRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not supported(newurl) or parse.urlsplit(newurl).hostname.removeprefix("www.") != parse.urlsplit(req.full_url).hostname.removeprefix("www."):
            raise ValueError("Unexpected reference redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_artifacts(url: str, *, budget: Budget | None = None) -> dict[str, str]:
    if not supported(url):
        raise ValueError("Unsupported reference host/path")
    headers = {"User-Agent": "pocindex-reference-pocs"}
    is_gist = parse.urlsplit(url).hostname == "gist.github.com"
    if is_gist:
        gist = parse.urlsplit(url).path.rstrip("/").split("/")[-1]
        endpoint = "https://api.github.com/gists/" + gist
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    else:
        endpoint = re.sub(r"^http:", "https:", url)
    opener = request.build_opener(SourceRedirect())
    budget = budget or Budget(10)
    body = budget.read(request.Request(endpoint, headers=headers), opener=opener, limit=MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("Reference response exceeds content limit")
    return gist_artifacts(json.loads(body)) if is_gist else mail_artifacts(url, body)


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)


def feed_candidates(payload: dict) -> dict[str, list[str]]:
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("format") != "NVD_CVE" or payload.get("version") != "2.0" or not isinstance(rows, list) or payload.get("totalResults") != len(rows):
        raise ValueError("Incomplete NVD feed")
    found = {}
    for wrapper in rows:
        cve = wrapper.get("cve") or {}
        cid = str(cve.get("id") or "")
        if not update_cves.is_valid_cve(cid) or cid in found or not isinstance(cve.get("references", []), list):
            raise ValueError("Invalid NVD CVE entry")
        found[cid] = []
        if cve.get("vulnStatus") == "Rejected":
            continue
        for reference in cve.get("references", []):
            url = str(reference.get("url") or "")
            if "Exploit" in reference.get("tags", []) and supported(url):
                found[cid].append(url)
        found[cid] = sorted(set(found[cid]))
    return found


def load_feeds(directory: Path | None, *, budget: Budget | None = None) -> dict[str, list[str]]:
    found = {}
    budget = budget or Budget(180)
    if directory is not None:
        paths = sorted(directory.glob("nvd-*.json.gz"))
        if not paths:
            raise ValueError("No local NVD feeds")
        for path in paths:
            budget.remaining()
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                found.update(feed_candidates(json.load(handle)))
    else:
        for name in ("recent", "modified"):
            req = request.Request(f"{FEED_ROOT}/nvdcve-2.0-{name}.json.gz", headers={"User-Agent": "pocindex-reference-pocs"})
            found.update(feed_candidates(json.loads(gzip.decompress(budget.read(req)))))
    return found


def load_reviews(path: Path = REVIEWS) -> list[dict]:
    payload = load_json(path, {})
    rows = payload.get("reviews") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or payload.get("version") != 1:
        raise ValueError("Invalid reviewed reference manifest")
    for row in rows:
        if not isinstance(row, dict) or not update_cves.is_valid_cve(row.get("cve", "")) or not supported(row.get("url", "")) or not re.fullmatch(r"[a-f0-9]{64}", row.get("sha256", "")) or not row.get("artifact") or not row.get("evidence"):
            raise ValueError("Invalid reviewed reference evidence")
    return rows


def load_exclusions(path: Path | None = None) -> set[tuple[str, str]]:
    payload = load_json(path or REVIEWS, {})
    rows = payload.get("exclusions") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or payload.get("version") != 1:
        raise ValueError("Invalid reference exclusion registry")
    for row in rows:
        if not isinstance(row, dict) or not update_cves.is_valid_cve(row.get("cve", "")) or not supported(row.get("url", "")) or not row.get("reason"):
            raise ValueError("Invalid reference exclusion")
    return {(row["cve"], update_cves.poc_link_key(row["url"])) for row in rows}


def approvals(reviews: list[dict], candidates: dict, checks: dict, previous: dict) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {}
    for row in reviews:
        cve, url = row["cve"], row["url"]
        if url not in candidates.get(cve, []):
            continue
        check = checks.get(url, {})
        if check.get("error"):
            accepted = url in previous.get(cve, [])
        else:
            accepted = check.get("digests", {}).get(row["artifact"]) == row["sha256"]
        if accepted:
            found.setdefault(cve, set()).add(url)
    return {cve: sorted(urls) for cve, urls in found.items()}


def refresh_checks(state: dict, reviews: list[dict], *, limit: int, days: int, cache: Path, dry_run: bool, budget: Budget | None = None) -> int:
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    cutoff = (now.date() - timedelta(days=days)).isoformat()
    urls = {url for values in state["candidates"].values() for url in values}
    reviewed = {row["url"] for row in reviews}
    checks = state["checks"]
    for url in set(checks) - urls:
        del checks[url]
    due = [url for url in urls if checks.get(url, {}).get("checked", "") <= (today if checks.get(url, {}).get("error") else cutoff)]
    due.sort(key=lambda url: (url not in reviewed, checks.get(url, {}).get("checked", ""), url))
    failures = 0
    for url in due[:limit]:
        try:
            if budget is not None:
                budget.remaining()
            artifacts = fetch_artifacts(url, budget=budget) if budget is not None else fetch_artifacts(url)
            digests = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in artifacts.items()}
            if not dry_run:
                cache.mkdir(parents=True, exist_ok=True)
                for name, text in artifacts.items():
                    (cache / (digests[name] + ".txt")).write_text(text, encoding="utf-8")
            checks[url] = {"checked": today, "digests": digests}
        except error.HTTPError as problem:
            if problem.code in {404, 410}:
                checks[url] = {"checked": today, "digests": {}, "missing": problem.code}
            else:
                failures += 1
                checks[url] = {**checks.get(url, {}), "checked": today, "error": f"HTTP {problem.code}"}
        except (OSError, ValueError, http.client.HTTPException) as problem:
            failures += 1
            checks[url] = {**checks.get(url, {}), "checked": today, "error": str(problem)[:160]}
        if budget is not None:
            budget.failures = failures
        if not dry_run:
            save_json(QUEUE, state)
    return failures


def retain_previous(accepted: dict, previous: dict, *, dry_run: bool) -> None:
    if not dry_run:
        retained = {cve: [url for url in urls if url in accepted.get(cve, [])] for cve, urls in previous.items()}
        save_json(VERIFIED, {cve: urls for cve, urls in retained.items() if urls})


def published_entries(accepted: dict, previous: dict, args, budget: Budget) -> dict:
    statuses = load_json(args.record_states, {}) if args.record_states else {}
    if args.record_states and (not isinstance(statuses, dict) or any(cve not in statuses for cve in accepted)):
        raise ValueError("Incomplete official CVE state snapshot")
    with tempfile.TemporaryDirectory(prefix="pocindex-reference-records-") as directory:
        local = Path(directory)
        for cve in accepted:
            budget.remaining()
            path = update_cves.CVES / cve.split("-")[1] / f"{cve}.md"
            if not args.record_states and cve in previous and path.exists():
                # Previously admitted records retain their official publication
                # evidence; metadata sync handles later rejections.
                statuses[cve] = "PUBLISHED"
            if statuses.get(cve) in {"RESERVED", "REJECTED"} or (cve in statuses and path.exists()):
                continue
            record = None
            if args.cvelist_dir:
                record = update_cves.read_record(update_cves.cvelist_record_path(args.cvelist_dir, cve))
            if record is None:
                req = request.Request(update_cves.CVE_API_URL.format(cve_id=cve), headers={"User-Agent": "pocindex-reference-pocs"})
                try:
                    record = json.loads(budget.read(req))
                except error.HTTPError as problem:
                    if problem.code != 404:
                        raise
                    statuses[cve] = "UNAVAILABLE"
                    continue
            status = (record.get("cveMetadata") or {}).get("state")
            if update_cves.record_cve_id(record) != cve or status not in {"PUBLISHED", "RESERVED", "REJECTED"} or (status == "PUBLISHED" and update_cves.details_from_record(record) is None):
                raise ValueError(f"Incomplete or mismatched official record: {cve}")
            statuses[cve] = status
            if not path.exists():
                save_json(update_cves.cvelist_record_path(local, cve), record)
        accepted = {cve: urls for cve, urls in accepted.items() if statuses.get(cve) == "PUBLISHED"}
        # Every missing record is now local: the shared helper cannot start
        # unbounded network retries after this command's budget expires.
        _, unavailable = update_cves.ensure_cve_entries(accepted, dry_run=args.dry_run, cvelist_dir=local)
    return {cve: urls for cve, urls in accepted.items() if cve not in unavailable}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed-dir", type=Path, help="Local complete nvd-YEAR.json.gz feeds")
    parser.add_argument("--record-states", type=Path, help="Local official CVE ID to record-state snapshot")
    parser.add_argument("--cvelist-dir", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=CACHE)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--recheck-days", type=int, default=7)
    parser.add_argument("--max-seconds", type=float, default=180)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.limit < 1 or args.recheck_days < 1 or args.max_seconds <= 0:
        parser.error("Limits must be positive")
    budget = Budget(args.max_seconds)
    excluded = load_exclusions()
    reviews = [row for row in load_reviews() if (row["cve"], update_cves.poc_link_key(row["url"])) not in excluded]
    state = load_json(QUEUE, {"candidates": {}, "checks": {}})
    previous = load_json(VERIFIED, {})
    try:
        candidates = load_feeds(args.feed_dir, budget=budget)
        for cve, urls in candidates.items():
            if urls:
                state["candidates"][cve] = urls
            else:
                state["candidates"].pop(cve, None)
        failures = refresh_checks(state, reviews, limit=args.limit, days=args.recheck_days,
                                  cache=args.cache_dir, dry_run=args.dry_run, budget=budget)
        accepted = approvals(reviews, state["candidates"], state["checks"], previous)
        retain_previous(accepted, previous, dry_run=args.dry_run)
        accepted = published_entries(accepted, previous, args, budget)
        for cve, urls in accepted.items():
            path = update_cves.CVES / cve.split("-")[1] / f"{cve}.md"
            if path.exists():
                update_cves.update_existing_markdown(path, [], urls, dry_run=args.dry_run)
        update_cves.append_inventory(update_cves.REFERENCE_LIST, accepted, dry_run=args.dry_run)
        if not args.dry_run:
            save_json(QUEUE, state)
            save_json(VERIFIED, accepted)
        pairs = sum(len(urls) for urls in accepted.values())
        print(f"Reference PoCs: {pairs} reviewed links for {len(accepted)} published CVEs; {len(state['checks'])} URLs checked")
        if failures:
            raise RuntimeError(f"{failures} reference fetches failed; prior approvals and retry work preserved")
    except BudgetExpired:
        if not args.dry_run:
            save_json(QUEUE, state)
            retain_previous(approvals(reviews, state["candidates"], state["checks"], previous), previous, dry_run=False)
        print(f"Reference PoCs: time budget reached; {len(state['checks'])} URLs checked, remaining work pending")
        if budget.failures:
            raise RuntimeError(f"{budget.failures} reference fetches failed before the budget expired") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
