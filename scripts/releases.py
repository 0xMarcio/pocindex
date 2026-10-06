#!/usr/bin/env python3
"""Durable release evidence for published CVE/artifact pairs.

Observing a link is not evidence of its publication date. Imports remain
undated until source history supplies evidence; removed links stay recorded.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import Request, urlopen

import source_artifacts
from update_cves import CODE_FILE_RE, INDEX, POC_RE, poc_link_key

DIRECTORY = INDEX / "releases"
VERSION = 1
DATE_ORDER = {"commit": 1, "source": 2, "created": 3, "public": 4, "merged": 5, "seen": 6}
EXCLUDED_DIRS = {".git", ".github", "docs", "doc", "images", "img", "assets", "screenshots", "media",
                 "tests", "test", "node_modules", "vendor", "third_party", "__pycache__"}
BUILD_FILES = {"setup.py", "conftest.py", "__init__.py", "requirements.txt", "package.json", "package-lock.json",
               "go.mod", "go.sum", "cargo.toml", "cargo.lock", "makefile", "cmakelists.txt", "dockerfile",
               "docker-compose.yml", "pyproject.toml"}
DATA_SUFFIXES = {".json", ".yml", ".yaml", ".toml", ".lock", ".txt", ".csv", ".xml", ".ini", ".cfg", ".md",
                 ".rst", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".gz", ".zip", ".xz", ".bz2",
                 ".tar", ".7z", ".o", ".so", ".a", ".dll", ".exe"}
PAPERWORK = re.compile(r"^(?:readme|license|licence|security|contributing|changelog|code.of.conduct)(?:\.|$)", re.I)
SUPPORT_FILE = re.compile(r"^(?:setup|install|example|demo|test|conftest|helper|util|common)(?:[_.-]|$)", re.I)
HISTORY_VERSION = 3
HISTORY_FIELDS = {"paths", "rev", "blobs", "commit", "sha", "commit_verified", "history_paths",
                  "merged", "merged_verified", "history_version", "bulk"}


class Ledger(dict):
    """Keep identity comparisons local to one CVE during large backfills."""
    def __init__(self, values=()):
        super().__init__()
        self.by_cve = defaultdict(set)
        for identity, row in dict(values).items():
            self[identity] = row

    def __setitem__(self, identity, row):
        super().__setitem__(identity, row)
        self.by_cve[row["cve"]].add(identity)

    def __deepcopy__(self, memo):
        return Ledger((identity, copy.deepcopy(row, memo)) for identity, row in self.items())


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def key(cve: str, url: str) -> str:
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        raise ValueError(f"Invalid CVE: {cve}")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid artifact URL")
    return f"{cve} {poc_link_key(url)}"


def artifact_paths(entries: list[dict], cve: str, *, readme_path: str | None = None,
                   readme_qualified: bool = False, limit: int = 12) -> list[str]:
    """Select paths in an already qualified repository, before applying a cap.

    A selected directory still needs its qualifying files checked for dating.
    README fallback is explicit: an advisory/claim alone is not an artifact.
    """
    ranked = []
    for entry in entries:
        path = str(entry.get("path") or entry.get("name") or "")
        parts = path.split("/")
        name = parts[-1].lower()
        if (not path or any(part.lower() in EXCLUDED_DIRS for part in parts)
                or name in BUILD_FILES or PAPERWORK.match(name) or SUPPORT_FILE.match(name)):
            continue
        kind = str(entry.get("type") or "blob").lower()
        code = bool(CODE_FILE_RE.search(name)) or name.endswith((".html", ".asm", ".lua"))
        if not code and Path(name).suffix in DATA_SUFFIXES:
            continue
        rank = (0 if cve.lower() in name else 1 if code else 2 if POC_RE.search(name)
                else 3 if kind == "tree" else 4)
        ranked.append((rank, path))
    selected = [path for _, path in sorted(set(ranked))[:limit]]
    return selected or ([readme_path] if readme_qualified and readme_path else [])


def artifact_identity(entries: list[dict], paths: list[str]) -> dict:
    """Fingerprint selected content, independently of path moves or paperwork."""
    selected = {entry.get("path") or entry.get("name"): entry for entry in entries}
    objects, blobs = [], []
    for path in paths:
        entry = selected.get(path) or {}
        oid = entry.get("sha256") or entry.get("oid") or entry.get("sha")
        if not isinstance(oid, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            continue
        kind = str(entry.get("type") or "blob").lower()
        objects.append((kind, oid))
        size = entry.get("size", entry.get("byteSize", 0))
        if kind == "blob" and isinstance(size, int) and size >= 256:
            blobs.append(oid)
    result = {"paths": sorted(paths)}
    if objects:
        result["rev"] = hashlib.sha256(json.dumps(sorted(set(objects)), separators=(",", ":")).encode()).hexdigest()
    if blobs:
        result["blobs"] = sorted(set(blobs))
    return result


def date_release(evidence: dict, *, now: str | None = None) -> tuple[str | None, str]:
    """Latest evidenced lower bound; client commit clocks have strict ceilings."""
    if evidence.get("pending"):
        return None, "pending"
    current = timestamp(now or utcnow())
    ceiling = current
    for name in ("seen", "pushed_at"):
        if parsed := timestamp(evidence.get(name)):
            ceiling = min(ceiling, parsed)
    bounds = []
    for name in ("created", "public", "commit", "merged", "source"):
        value = evidence.get(name)
        moment = timestamp(value)
        if moment is None or moment > ceiling:
            continue
        if name in {"commit", "merged"} and evidence.get(f"{name}_verified") is not True:
            continue
        bounds.append((moment, DATE_ORDER[name], value, name))
    chosen = max(bounds) if bounds else None
    absent, seen = timestamp(evidence.get("absent")), timestamp(evidence.get("seen"))
    # Parser/gate changes and import baselines never establish absence.
    if (not evidence.get("imported") and evidence.get("absence_verified") is True
            and evidence.get("previous_head") and absent and seen and absent < seen <= current
            and (chosen is None or chosen[0] <= absent)):
        return evidence["seen"], "seen"
    return (chosen[2], chosen[3]) if chosen else (None, "unknown")


def load_ledger(directory: Path | None = None) -> dict[str, dict]:
    result = Ledger()
    for path in sorted((directory or DIRECTORY).glob("[12][0-9][0-9][0-9].json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("version") != VERSION or not isinstance(payload.get("entries"), dict):
            raise ValueError(f"Invalid release shard: {path}")
        for identity, row in payload["entries"].items():
            if (not isinstance(row, dict) or identity != key(row.get("cve", ""), row.get("url", ""))
                    or row["cve"].split("-")[1] != path.stem or identity in result):
                raise ValueError(f"Invalid release entry: {path}")
            result[identity] = row
    return result


def save_ledger(ledger: dict[str, dict], directory: Path | None = None) -> None:
    directory = directory or DIRECTORY
    previous = load_ledger(directory)
    if not previous.keys() <= ledger.keys():
        raise ValueError("Release history cannot shrink; retain removed entries as tombstones")
    for identity, old in previous.items():
        if old.get("seen") != ledger[identity].get("seen") or old.get("imported") != ledger[identity].get("imported"):
            raise ValueError("First release observation and import provenance are immutable")
    shards = defaultdict(dict)
    for identity, row in sorted(ledger.items()):
        if identity != key(row["cve"], row["url"]):
            raise ValueError("Release key differs from its artifact")
        shards[row["cve"].split("-")[1]][identity] = row
    directory.mkdir(parents=True, exist_ok=True)
    for year, entries in shards.items():
        # One sorted entry per line keeps backfills and hourly diffs reviewable.
        body = '{"version":1,"entries":{\n' + ",\n".join(
            json.dumps(identity) + ":" + json.dumps(row, sort_keys=True, separators=(",", ":"))
            for identity, row in entries.items()) + "\n}}\n"
        path = directory / f"{year}.json"
        if path.exists() and path.read_text(encoding="utf-8") == body:
            continue
        temporary = path.with_suffix(".tmp")
        temporary.write_text(body, encoding="utf-8")
        temporary.replace(path)


def _repository_artifact(url: str) -> tuple[str, str] | None:
    parsed = urlsplit(url)
    parts = unquote(parsed.path).strip("/").split("/")
    if parsed.hostname not in {"github.com", "www.github.com"} or len(parts) < 2:
        return None
    if len(parts) == 2:
        return "/".join(parts[:2]).lower(), ""
    if len(parts) >= 5 and parts[2] in {"blob", "tree"}:
        return "/".join(parts[:2]).lower(), "/".join(parts[4:])
    return None


def _same_artifact(row: dict, candidate: dict) -> bool:
    left, right = _repository_artifact(row["url"]), _repository_artifact(candidate["url"])
    if (left and right and row.get("rev") and row.get("rev") == candidate.get("rev")
            and (left[0] == right[0] or row.get("repo") and row.get("repo") == candidate.get("repo"))):
        return True
    # Repository IDs identify transfers, but never collapse different variants.
    return bool(left and right and row.get("repo") and row.get("repo") == candidate.get("repo")
                and left[1] == right[1] and left[0] != right[0])


def record(ledger: dict[str, dict], cve: str, url: str, evidence: dict | None = None, *,
           observed_at: str | None = None, import_mode: bool = False) -> dict:
    observed_at = observed_at or utcnow()
    identity = key(cve, url)
    old = ledger.get(identity)
    row = copy.deepcopy(old) if old else {"cve": cve, "url": url, "basis": "unknown", "released": None}
    row.pop("gone", None)
    if not old:
        if import_mode:
            row["imported"] = True
        else:
            row["seen"] = observed_at
    evidence = evidence or {}
    if evidence.get("error") and row.get("released"):
        # A failed refresh may advance retry bookkeeping, never valid evidence.
        evidence = {name: value for name, value in evidence.items() if name in {"error", "checked", "head"}}
    method = evidence.get("history_version", 0)
    method = method if type(method) is int and method > 0 else 0
    old_method = row.get("history_version", 0)
    old_method = old_method if type(old_method) is int and old_method > 0 else 0
    moment = timestamp(evidence.get("commit"))
    ceiling = min(timestamp(value) for value in (
        observed_at, row.get("seen"), evidence.get("pushed_at", row.get("pushed_at"))
    ) if timestamp(value))
    verified_history = bool(not evidence.get("error") and evidence.get("commit_verified") is True
                            and moment and moment <= ceiling)
    correction = bool(old and verified_history and method > old_method)
    if old_method and evidence.get("commit_verified") and method < old_method:
        evidence = {name: value for name, value in evidence.items() if name not in HISTORY_FIELDS}
    if correction:
        for name in HISTORY_FIELDS | {"copy", "absence_verified"}:
            row.pop(name, None)
        row.update(released=None, basis="unknown")
    for name in ("created", "public", "repo", "paths", "rev", "blobs", "source", "absent", "previous_head",
                 "absence_verified", "commit", "sha", "commit_verified", "merged", "merged_verified", "pushed_at", "bulk", "checked", "head", "history_paths"):
        if name not in evidence:
            continue
        value = evidence[name]
        if name in {"paths", "rev", "blobs", "absent", "previous_head", "absence_verified"} and name in row:
            continue
        if name in {"commit", "merged", "source"} and timestamp(row.get(name)):
            if not timestamp(value) or timestamp(value) >= timestamp(row[name]):
                continue
        if name == "sha" and row.get("commit") != evidence.get("commit"):
            continue
        row[name] = value
    if verified_history and method >= old_method and method:
        row["history_version"] = method
    if evidence.get("error"):
        if not row.get("released"):
            row.update(basis="pending", pending=True)
    else:
        if evidence.get("commit_verified") or evidence.get("source") or evidence.get("absence_verified"):
            row.pop("pending", None)
        released, basis = date_release(row, now=observed_at)
        if released:
            # Re-adds and subsequent observations are not another release.
            if row.get("basis") != "seen" or not row.get("released"):
                row.update(released=released, basis=basis)
    if (not old or correction or not any(old.get(field) for field in ("repo", "rev", "blobs"))) and any(row.get(field) for field in ("repo", "rev", "blobs")):
        identities = ledger.by_cve.get(cve, ()) if isinstance(ledger, Ledger) else ledger.keys()
        candidates = [(other_key, ledger[other_key]) for other_key in identities
                      if other_key != identity and ledger[other_key]["cve"] == cve]
        matches = [(other_key, other) for other_key, other in candidates if _same_artifact(row, other)]
        copies = [(other_key, other) for other_key, other in candidates
                  if row.get("blobs") and set(row["blobs"]) == set(other.get("blobs", []))]
        if matches or copies:
            other_key, other = min(matches or copies, key=lambda item: (item[1].get("released") or "9999", item[0]))
            row["copy"] = other.get("copy", other_key)
            row["released"], row["basis"] = other.get("released"), other.get("basis", "unknown")
    elif row.get("copy") in ledger:
        original = ledger[row["copy"]]
        row["released"], row["basis"] = original.get("released"), original.get("basis", "unknown")
    ledger[identity] = row
    return row


def mark_bulk(ledger: dict[str, dict]) -> None:
    groups = defaultdict(list)
    for identity, row in ledger.items():
        source = row.get("repo") or (_repository_artifact(row["url"]) or (row["url"],))[0]
        if row.get("sha") and row.get("commit_verified"):
            groups[(str(source), row["sha"], "commit")].append(identity)
        elif row.get("basis") == "seen":
            groups[(str(source), row["seen"], "seen")].append(identity)
    for (*_, basis), identities in groups.items():
        count = len({ledger[identity]["cve"] for identity in identities}) if basis == "commit" else len(identities)
        if count > (10 if basis == "commit" else 25):
            for identity in identities:
                ledger[identity]["bulk"] = True


def resolve_copies(ledger: dict[str, dict], *, now: str | None = None) -> None:
    """Resolve identities after a batch, independent of enrichment order.

    Entire selected nontrivial blob sets must match. One shared helper cannot
    collapse distinct variants. Tombstones still supply original provenance.
    """
    groups, parents = defaultdict(list), {}
    for identity, row in ledger.items():
        location = _repository_artifact(row["url"])
        if blobs := row.get("blobs"):
            groups[(row["cve"], "content", tuple(sorted(set(blobs))))].append(identity)
        if row.get("rev") and location:
            groups[(row["cve"], "revision", str(row.get("repo") or location[0]), row["rev"])].append(identity)
        if row.get("repo") and location:
            groups[(row["cve"], "transfer", str(row["repo"]), location[1])].append(identity)

    def root(identity):
        parents.setdefault(identity, identity)
        if parents[identity] != identity:
            parents[identity] = root(parents[identity])
        return parents[identity]

    for signature, identities in groups.items():
        if len(identities) < 2:
            continue
        if signature[1] == "transfer" and len({_repository_artifact(ledger[item]["url"])[0] for item in identities}) < 2:
            continue
        first = min(identities)
        for identity in identities:
            parents[root(identity)] = root(first)
    components = defaultdict(list)
    for identity in parents:
        components[root(identity)].append(identity)
    for identities in components.values():
        own_dates = {identity: date_release(ledger[identity], now=now) for identity in identities}
        original = min(identities, key=lambda identity: (
            timestamp(own_dates[identity][0]) or datetime.max.replace(tzinfo=timezone.utc), identity))
        released, basis = own_dates[original]
        for identity in identities:
            row = ledger[identity]
            row["released"], row["basis"] = released, basis
            if identity == original:
                row.pop("copy", None)
            else:
                row["copy"] = original
    for identity, row in ledger.items():
        if row.get("copy") and identity not in parents:
            row.pop("copy", None)
            row["released"], row["basis"] = date_release(row, now=now)


def reconcile(ledger: dict[str, dict], pairs: list[tuple[str, str]], *, evidence: dict[str, dict] | None = None,
              observed_at: str | None = None, import_mode: bool = False, complete: bool = True) -> dict[str, dict]:
    observed_at = observed_at or utcnow()
    result = copy.deepcopy(ledger) if isinstance(ledger, Ledger) else Ledger(copy.deepcopy(ledger))
    present = set()
    for cve, url in sorted(set(pairs)):
        identity = key(cve, url)
        present.add(identity)
        record(result, cve, url, (evidence or {}).get(identity), observed_at=observed_at, import_mode=import_mode)
    if complete:
        for identity, row in result.items():
            if identity not in present:
                row.setdefault("gone", observed_at)
    resolve_copies(result, now=observed_at)
    mark_bulk(result)
    return result


def landed(ledger: dict[str, dict], *, now: str | None = None, days: int = 10) -> list[dict]:
    moment = timestamp(now or utcnow())
    found = [(identity, row) for identity, row in ledger.items()
             if not any(row.get(flag) for flag in ("gone", "copy", "bulk"))
             and row.get("basis") not in {"unknown", "pending"}
             and timestamp(row.get("released")) is not None
             and moment - timedelta(days=days) <= timestamp(row["released"]) <= moment]
    found.sort(key=lambda item: item[0])
    found.sort(key=lambda item: timestamp(item[1]["released"]), reverse=True)
    return [dict(row) for _, row in found]


def published_pairs(entries: list[dict] | None = None) -> list[tuple[str, str]]:
    if entries is None:
        # Lazy import also lets the site builder consume this ledger.
        from build_site import build_cve_list, load_blacklist
        entries, _ = build_cve_list(load_blacklist())
    return sorted({(row["cve"], url) for row in entries
                   for field in ("poc", "nuclei", "edb", "msf", "vulhub", "collections")
                   for url in row.get(field, [])})


def qualifying_content(repository: str, cve: str, path: str, source: bytes, reviews: list[dict]) -> bool:
    """Confirm that a historical file contains reproduction material, not a stub.

    This only dates already accepted links. It is not a discovery/approval gate.
    Ambiguous historical content stays undated until reviewed.
    """
    if cve in source_artifacts.approved_cves_for_artifact(repository, path, source, reviews=reviews):
        return True
    if source_artifacts.identity_cves(path) - {cve}:
        return False
    if len(source.strip()) < 40:
        return False
    text = source.decode("utf-8", "replace")
    name = Path(path).name.lower()
    if repository.lower() == "github/securitylab" and name in {"bug.pdf", "fuzzer-poc.djvu", "poc.bin"}:
        return bool(source)
    if repository.lower() == "github/securitylab" and name.endswith(".cue"):
        return bool(re.search(r"(?m)^\s*(?:FILE|TRACK|INDEX)\b", text))
    if name.endswith((".md", ".rst")) or name == "readme":
        context = ""
        for chunk in re.split(r"(```[^\n]*\n.*?```)", text, flags=re.S):
            if not chunk.startswith("```"):
                context = chunk[-1000:]
                continue
            if not POC_RE.search(context) or re.search(r"(?im)^#+\s*(?:install|setup|requirements|mitigation)", context):
                continue
            if re.search(r"(?m)^\s*(?:curl\s+(?!.*(?:install|update)\.).*(?:https?://|--url)|(?:GET|POST|PUT)\s+/|.*(?:requests\.(?:get|post)|\.sendall)\s*\()", chunk):
                return True
        return False
    if repository in {"tenable/poc", "pedrib/PoC"}:
        from sync_collections import author_artifact_ids
        if cve not in author_artifact_ids(repository, path, text):
            return False
    if name in {"diff.txt", "stroke_patch.txt"} and repository.lower() == "github/securitylab":
        return bool(re.search(r"(?m)^@@ .*@@", text) and re.search(r"(?m)^\+[^+]", text))
    if not (CODE_FILE_RE.search(name) or name.endswith((".html", ".asm", ".lua"))):
        return False
    # Imports/comments alone and placeholder text do not establish introduction.
    executable = "\n".join(line for line in text.splitlines()
                           if line.strip() and not re.match(r"\s*(?:#|//|/\*|\*|import\b|from\s+\S+\s+import\b)", line))
    # Function/class declarations, pass/return stubs and arbitrary method calls
    # are not historical exploit evidence. Require an actual action/payload.
    return bool(re.search(r"(?:\b(?:socket|send|sendto|sendmsg|sendmmsg|write|ioctl|syscall|mmap|mprotect|ptrace|"
                          r"prctl|setsockopt|msgsnd|msgrcv|setxattr|execve|system|memcpy|strcpy|gets|"
                          r"remote|process|fetch|eval|unserialize)\s*\(|"
                          r"\b(?:requests|urllib|http|axios|Net::HTTP)\W.{0,40}\b(?:get|post|request|open|start)\s*\(|"
                          r"\.(?:send|sendall|send_request_cgi|write|Write|writeObject|Dial|NewRequest|"
                          r"connect|Connect|exec|execute|communicate)\s*\(|"
                          r"<(?:form|script)\b|\bcurl\s+(?:.*(?:https?://|--url)))", executable))


class GitHubHistory:
    """Pinned, bounded history reads. Failed requests never become absence."""
    def __init__(self, headers: dict, *, fetch=None):
        self.headers, self.fetch, self.cache = headers, fetch, {}
        self.reviews = source_artifacts.load_reviews()
        self.budget = threading.local()

    def begin(self, *, budget_seconds: float = 45, max_requests: int = 24) -> None:
        self.budget.deadline = time.monotonic() + budget_seconds
        self.budget.remaining = max_requests

    def get(self, path: str):
        if path not in self.cache:
            if not hasattr(self.budget, "deadline"):
                self.begin()
            remaining = self.budget.deadline - time.monotonic()
            if remaining <= 0 or self.budget.remaining <= 0:
                raise TimeoutError("Artifact history inspection budget exhausted")
            self.budget.remaining -= 1
            url = "https://api.github.com" + path
            if self.fetch is not None:
                payload = self.fetch(url, headers=self.headers, timeout=min(15, remaining))
            else:
                request = Request(url, headers={"User-Agent": "pocindex-release-evidence", **self.headers})
                with urlopen(request, timeout=min(15, remaining)) as response:
                    payload = json.load(response)
            self.cache[path] = payload
        return self.cache[path]

    def tree(self, repository: str, revision: str, scope: str = "") -> list[dict]:
        expression = revision + (":" + scope if scope else "")
        payload = self.get(f"/repos/{repository}/git/trees/{quote(expression, safe='')}?recursive=1")
        if not isinstance(payload, dict) or payload.get("truncated") is not False or not isinstance(payload.get("tree"), list):
            raise ValueError("Incomplete artifact tree")
        result = []
        for item in payload["tree"]:
            if not isinstance(item, dict) or not source_artifacts.valid_path(str(item.get("path") or "")):
                raise ValueError("Invalid artifact tree entry")
            if item.get("type") == "blob" and item.get("mode") in {"100644", "100755"}:
                result.append({**item, "path": (scope + "/" if scope else "") + item["path"]})
        return result

    def blob(self, repository: str, entry: dict) -> bytes:
        if not isinstance(entry.get("size"), int) or not 0 < entry["size"] <= 2_000_000:
            raise ValueError("Artifact blob is empty or exceeds the history inspection bound")
        payload = self.get(f"/repos/{repository}/git/blobs/{entry['sha']}")
        if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
            raise ValueError("Missing artifact blob")
        source = base64.b64decode("".join(payload["content"].split()), validate=True)
        digest = hashlib.sha1(f"blob {len(source)}\0".encode() + source).hexdigest()
        if len(source) != entry["size"] or digest != entry["sha"]:
            raise ValueError("Artifact blob differs from its pinned tree")
        return source

    def qualifying(self, repository: str, revision: str, paths: list[str], cve: str) -> list[dict]:
        # Read each parent tree once; a requested directory is expanded into its
        # real files so its initial README/config commit cannot date the PoC.
        found = {}
        for path in paths:
            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            rows = self.tree(repository, revision, parent)
            candidates = [r for r in rows if r["path"] == path or r["path"].startswith(path.rstrip("/") + "/")]
            explicit = [r for r in candidates if r["path"] == path]
            selected = {r["path"] for r in explicit} or set(artifact_paths(candidates, cve))
            if repository.lower() == "github/securitylab":
                selected.update(r["path"] for r in candidates if Path(r["path"]).name.lower() in {
                    "bug.pdf", "fuzzer-poc.djvu", "poc.bin", "diff.txt", "stroke_patch.txt"} or r["path"].endswith(".cue"))
            for entry in candidates:
                size = entry.get("size")
                if not isinstance(size, int) or not 0 < size <= 2_000_000:
                    continue
                if entry["path"] in selected and qualifying_content(repository, cve, entry["path"], self.blob(repository, entry), self.reviews):
                    found[entry["path"]] = entry
        return list(found.values())

    def history(self, repository: str, revision: str, path: str) -> list[dict]:
        result = []
        for page in range(1, 21):
            query = urlencode({"sha": revision, "path": path, "per_page": 100, "page": page})
            rows = self.get(f"/repos/{repository}/commits?{query}")
            if not isinstance(rows, list) or any(not isinstance(row, dict) or not re.fullmatch(r"[a-f0-9]{40}", str(row.get("sha") or "")) for row in rows):
                raise ValueError("Incomplete artifact history")
            result.extend(rows)
            if len(rows) < 100:
                return list(reversed(result))
        raise ValueError("Artifact history exceeds the bounded scan; use the local backfill")

    def introduction(self, repository: str, revision: str, path: str, cve: str, *, depth: int = 0) -> dict:
        if depth > 8:
            raise ValueError("Artifact rename history exceeds inspection bound")
        for commit in self.history(repository, revision, path):
            # First path existence alone is insufficient: inspect those bytes.
            entries = self.qualifying(repository, commit["sha"], [path], cve)
            if not entries:
                continue
            detail = self.get(f"/repos/{repository}/commits/{commit['sha']}")
            files = detail.get("files")
            if not isinstance(files, list) or not any(item.get("filename") == path for item in files):
                raise ValueError("Missing introduction diff")
            renamed = next((item.get("previous_filename") for item in files
                            if item.get("filename") == path and item.get("status") == "renamed"), None)
            if renamed and detail.get("parents"):
                parent = detail["parents"][0]["sha"]
                if self.qualifying(repository, parent, [renamed], cve):
                    return self.introduction(repository, parent, renamed, cve, depth=depth + 1)
            result = {"commit": commit["commit"]["committer"]["date"], "sha": commit["sha"],
                      "commit_verified": True, "history_paths": [entry["path"] for entry in entries]}
            introduced = {cve for item in files if item.get("status") == "added"
                          for cve in source_artifacts.identity_cves(item.get("filename", ""))}
            if len(introduced) > 10:
                result["bulk"] = True
            return result
        raise ValueError("No verified qualifying artifact introduction in source history")

    def absent(self, repository: str, revision: str, paths: list[str]) -> bool:
        # A complete known commit tree is stronger than an ambiguous 404 from
        # a contents endpoint (which may mean the commit/repository is missing).
        entries = self.tree(repository, revision)
        present = {entry["path"] for entry in entries}
        return all(path not in present for path in paths)


def current_repository_evidence(repo: dict, paths: list[str], headers: dict, *, cve: str | None = None,
                                cache_dir: Path | None = None, observed_at: str | None = None,
                                history: GitHubHistory | None = None, budget_seconds: float = 45,
                                max_requests: int = 24) -> dict:
    """Verify first qualifying file history for an already accepted repository.

    The supplied HEAD must be captured by the caller. Complete results are
    cached by HEAD, paths and review rules; errors return pending evidence.
    """
    name = str(repo.get("full_name") or repo.get("nameWithOwner") or "")
    revision = str(repo.get("revision") or repo.get("head") or
                   ((repo.get("defaultBranchRef") or {}).get("target") or {}).get("oid") or "")
    cve = cve or repo.get("cve")
    if not cve:
        cves = source_artifacts.identity_cves(name)
        cve = next(iter(cves)) if len(cves) == 1 else None
    evidence = {"repo": repo.get("id", repo.get("databaseId")),
                "created": repo.get("created_at", repo.get("createdAt")),
                "pushed_at": repo.get("pushed_at", repo.get("pushedAt")),
                "checked": observed_at or utcnow(), "head": revision}
    evidence = {k: v for k, v in evidence.items() if v is not None}
    if not cve or not re.fullmatch(r"[0-9a-f]{40}", revision) or not paths:
        return {**evidence, "error": "Missing CVE, pinned HEAD or qualifying artifact paths"}
    history = history or GitHubHistory(headers)
    history.begin(budget_seconds=budget_seconds, max_requests=max_requests)
    rules = [(r["cve"], r["path"], r["sha256"]) for r in history.reviews if r["repository"].lower() == name.lower()]
    cache_key = hashlib.sha256(json.dumps([HISTORY_VERSION, name.lower(), revision, cve, sorted(paths), sorted(rules)]).encode()).hexdigest()
    cache_dir = cache_dir or Path(tempfile.gettempdir()) / "pocindex-release-cache"
    cache_path = cache_dir / f"{cache_key}.json"
    try:
        if cache_path.exists():
            cached = json.loads(cache_path.read_text())
            if cached.get("history_version") == HISTORY_VERSION and cached.get("commit_verified") is True:
                return {**cached, **evidence}
        entries = history.qualifying(name, revision, paths, cve)
        if not entries:
            raise ValueError("Selected paths contain no verified reproduction material")
        entrypoints = [entry for entry in entries if source_artifacts.PAYLOAD_RE.search(Path(entry["path"]).name)
                       or cve.lower() in Path(entry["path"]).name.lower()]
        if entrypoints:
            entries = entrypoints
        identity = artifact_identity(entries, [entry["path"] for entry in entries])
        introductions = [history.introduction(name, revision, entry["path"], cve) for entry in entries]
        first = min(introductions, key=lambda row: timestamp(row["commit"]))
        result = {**evidence, **identity, **first, "history_version": HISTORY_VERSION}
        cache_dir.mkdir(parents=True, exist_ok=True)
        temporary = cache_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, sort_keys=True) + "\n")
        temporary.replace(cache_path)
        return result
    except Exception as problem:
        return {**evidence, "error": str(problem)}


def record_collection_snapshot(previous: dict, current: dict, pairs: list[tuple[str, str]], *,
                               directory: Path | None = None, observed_at: str | None = None,
                               history: GitHubHistory | None = None, limit: int = 8) -> None:
    """Record only applied source links, after every collection completed.

    Existing undated imports belong to the historical backfill. New/pending
    pairs get bounded evidence reads; skipped work remains pending for retry.
    """
    directory = directory or DIRECTORY
    if not directory.exists():
        return  # Establish the explicit historical baseline before enabling hooks.
    observed_at = observed_at or utcnow()
    ledger = load_ledger(directory)
    old_sources, sources = previous.get("sources", {}), current.get("sources", {})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    history = history or GitHubHistory({"Authorization": f"Bearer {token}"} if token else {})
    present, attempted = set(), 0
    ordered = sorted(set(pairs), key=lambda pair: (
        timestamp(ledger.get(key(*pair), {}).get("checked")) or datetime.min.replace(tzinfo=timezone.utc), pair))
    for cve, url in ordered:
        identity = key(cve, url)
        present.add(identity)
        location = _repository_artifact(url)
        if not location:
            continue
        repository = next((name for name in sources if name.lower() == location[0]), None)
        if repository is None:
            continue
        snapshot, prior = sources[repository], old_sources.get(repository, {})
        old = ledger.get(identity) or {}
        # A newly indexed historical source or newly published CVE record is
        # not evidence of an artifact appearing at this observation.
        already_in_source = url in (prior.get("links", {}).get(cve) or [])
        import_mode = bool(old.get("imported")) if old else not prior.get("observed_at") or already_in_source
        evidence = None
        if not old or old.get("basis") == "pending" or old.get("basis") == "unknown" and not old.get("imported"):
            previous_head = old.get("previous_head") or prior.get("revision")
            absent_at = old.get("absent") or prior.get("observed_at")
            evidence = {"error": "Deferred by collection history budget"}
            if previous_head and absent_at:
                evidence.update(previous_head=previous_head, absent=absent_at)
            if attempted < limit:
                attempted += 1
                evidence.update(checked=observed_at, head=snapshot["revision"])
                try:
                    history.begin(budget_seconds=15, max_requests=3)
                    repo = history.get(f"/repos/{repository}")
                    # The parser and these reads use exactly the same captured HEAD.
                    path = unquote(url.split(f"/{snapshot['branch']}/", 1)[1])
                    verified = current_repository_evidence({**repo, "revision": snapshot["revision"]}, [path], {},
                               cve=cve, history=history, observed_at=observed_at, budget_seconds=30, max_requests=20)
                    evidence.update(verified)
                    if "error" not in verified:
                        evidence.pop("error", None)
                        if previous_head and absent_at and not import_mode:
                            evidence["absence_verified"] = history.absent(repository, previous_head, verified["paths"])
                except Exception as problem:
                    evidence["error"] = str(problem)
        record(ledger, cve, url, evidence, observed_at=observed_at, import_mode=import_mode)
    previously_owned = {key(cve, url) for snapshot in old_sources.values()
                        for cve, urls in snapshot.get("links", {}).items() for url in urls}
    removed = previously_owned.intersection(ledger) - present
    if removed:
        published = {key(*pair) for pair in published_pairs()}
        for identity in removed:
            if identity in published:
                ledger[identity].pop("gone", None)
            else:
                ledger[identity].setdefault("gone", observed_at)
    resolve_copies(ledger, now=observed_at)
    mark_bulk(ledger)
    save_ledger(ledger, directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--seed", action="store_true", help="historical import; no observation or release dates")
    mode.add_argument("--record", action="store_true", help="reconcile the complete published artifact set")
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--input", type=Path, help="published CVE_list.json; otherwise parse the current corpus")
    parser.add_argument("--evidence", type=Path, help="JSON mapping of artifact keys to verified evidence")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    entries = json.loads(args.input.read_text()) if args.input else None
    evidence = json.loads(args.evidence.read_text()) if args.evidence else {}
    ledger = reconcile(load_ledger(args.directory), published_pairs(entries), evidence=evidence, import_mode=args.seed)
    if not args.dry_run:
        save_ledger(ledger, args.directory)
    print(f"releases: {len(ledger):,} pairs, {sum(bool(row.get('released')) for row in ledger.values()):,} dated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
