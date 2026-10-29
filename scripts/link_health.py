"""Confirmed public-link failures shared by ingestion, audits and publication."""

from __future__ import annotations

import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from http.client import HTTPException
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit, urlunsplit

STATE = Path(__file__).resolve().parents[1] / "index" / "link_health.json"


def repository(url: str) -> str:
    from build_site import GITHUB_NON_REPOS
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if parsed.hostname not in {"github.com", "www.github.com", "raw.githubusercontent.com"}:
        return ""
    parts = parsed.path.strip("/").split("/")
    if (len(parts) < 2 or not all(parts[:2]) or parts[0].lower() in GITHUB_NON_REPOS
            or not parts[1].lower().removesuffix(".git")):
        return ""
    return "/".join(parts[:2]).lower().removesuffix(".git")


def url_key(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    host = parsed.netloc.lower()
    if host == "www.github.com":
        host = "github.com"
    path = parsed.path
    if host in {"github.com", "raw.githubusercontent.com"}:
        parts = path.split("/")
        parts[1:3] = [part.lower() for part in parts[1:3]]
        path = "/".join(parts)
    # A fragment never reaches the server; path case and query strings do.
    return urlunsplit((parsed.scheme.lower(), host, path, parsed.query, ""))


@lru_cache(maxsize=1)
def load() -> dict:
    try:
        state = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"repositories": {}, "urls": {}}
    if not isinstance(state, dict) or any(
        not isinstance(state.get(field), dict)
        or any(not isinstance(key, str) or not isinstance(stamp, str)
               for key, stamp in state[field].items())
        for field in ("repositories", "urls")
    ):
        raise ValueError("Invalid link health state; refusing to forget confirmed dead links")
    if any(not name or repository(f"https://github.com/{name}") != name
           for name in state["repositories"]):
        raise ValueError("Invalid repository key in link health state")
    return state


def unavailable(url: str) -> bool:
    state = load()
    name = repository(url)
    return bool(name and name in state["repositories"]) or url_key(url) in state["urls"]


def unavailable_since(url: str) -> str:
    state = load()
    stamps = [value for value in (state['repositories'].get(repository(url)),
                                  state['urls'].get(url_key(url))) if value]
    return min(stamps, default='')


def record(*, missing=(), healthy=(), dead_urls=(), live_urls=(), now: str | None = None) -> None:
    state = {field: dict(values) for field, values in load().items()}
    stamp = now or datetime.now(timezone.utc).isoformat()
    for name in healthy:
        if key := repository(f"https://github.com/{name}"):
            state["repositories"].pop(key, None)
    for name in missing:
        if key := repository(f"https://github.com/{name}"):
            state["repositories"].setdefault(key, stamp)
    for url in live_urls:
        state["urls"].pop(url_key(url), None)
    for url in dead_urls:
        state["urls"].setdefault(url_key(url), stamp)
    if state == load():
        return
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=STATE.parent, delete=False) as handle:
        json.dump(state, handle, sort_keys=True, indent=2)
        handle.write("\n")
        temporary = Path(handle.name)
    try:
        temporary.replace(STATE)
    finally:
        temporary.unlink(missing_ok=True)
    load.cache_clear()


def check_url(url: str, timeout: int = 8) -> bool | None:
    """Anonymous GET: True live, False confirmed 404/410, None inconclusive.

    Follow redirects and read only one byte. HEAD is not authoritative: several
    hosts serve different routes or statuses for HEAD and GET.
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        req = request.Request(url, headers={"User-Agent": "pocindex-link-audit", "Accept": "*/*"})
        with request.urlopen(req, timeout=timeout) as response:
            response.read(1)
            status = response.status
            final_url = response.geturl()
            if isinstance(final_url, str):
                final = urlsplit(final_url)
                if (parsed.path.strip("/") and not final.path.strip("/")) or (
                    final.hostname == "github.com" and final.path.rstrip("/") in {"/login", "/session"}
                ):
                    return None
            return True if isinstance(status, int) and 200 <= status < 300 else None
    except error.HTTPError as exc:
        code = exc.code
        exc.close()
        return False if code in {404, 410} else None
    except (OSError, error.URLError, ValueError, HTTPException):
        return None


def survey_urls(urls: list[str], *, workers: int = 8, timeout: int = 8) -> tuple[set[str], set[str]]:
    dead, live = set(), set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for url, result in zip(urls, pool.map(lambda url: check_url(url, timeout), urls)):
            if result is False:
                dead.add(url)
            elif result is True:
                live.add(url)
    return dead, live
