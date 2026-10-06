"""Pinned source evidence for PoCs that the repository metadata gate misses.

Only locally reviewed bytes authorize a new link. Remote names and README text
select files to inspect, never assert that those files have been reviewed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
REVIEWS = ROOT / "index/source_artifact_reviews.json"
CANDIDATES = ROOT / "index/source_artifact_candidates.json"
MAX_FILES = 8
MAX_BYTES = 500_000
MAX_TREE = 10_000
CVE_RE = re.compile(r"(?<![A-Z0-9])CVE[-_ ](\d{4})[-_ ](\d{4,})(?![A-Z0-9])", re.I)
SOURCE_RE = re.compile(r"\.(?:c|cc|cpp|cs|go|java|js|mjs|nse|php|pl|ps1|py|rb|rs|sh|ts|asm|s|swift|lua|cna)$", re.I)
PAYLOAD_RE = re.compile(r"(?:^|[/_. -])(?:poc|pocs|exploit|exploits|expl|reproduce|reproducer|payload|trigger)(?:$|[/_. -])", re.I)
SUPPORT = {".git", "node_modules", "vendor", "third_party", "__pycache__"}
_LOCK = threading.Lock()


@dataclass(frozen=True)
class ArtifactEvidence:
    cve: str
    repository: str
    path: str
    revision: str
    sha256: str
    review_id: str
    released_at: str | None = None

    @property
    def url(self) -> str:
        return f"https://github.com/{self.repository}/blob/{self.revision}/{quote(self.path, safe='/')}"


def identity_cves(repository: str) -> set[str]:
    # Treat underscores as separators, including adjacent CVE identifiers.
    return {f"CVE-{year}-{number}" for year, number in CVE_RE.findall(repository.replace("_", " "))}


def valid_path(path: str) -> bool:
    return bool(path) and not path.startswith("/") and all(p not in {"", ".", ".."} for p in path.split("/"))


def load_reviews(path: Path | None = None) -> list[dict]:
    payload = json.loads((path or REVIEWS).read_text(encoding="utf-8"))
    if payload.get("version") != 1 or not isinstance(payload.get("reviews"), list):
        raise ValueError("Invalid source artifact review registry")
    for row in payload["reviews"]:
        if (not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(row.get("cve", "")))
                or not re.fullmatch(r"[^/]+/[^/]+", str(row.get("repository", "")))
                or not valid_path(str(row.get("path", "")))
                or not re.fullmatch(r"[0-9a-f]{40}", str(row.get("revision", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))
                or row.get("official_state") != "PUBLISHED"
                or not re.fullmatch(r"[0-9a-f]{40}", str(row.get("official_record_revision", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("official_record_sha256", "")))
                or not row.get("review_basis") or not row.get("id")):
            raise ValueError("Incomplete source artifact review")
    return payload["reviews"]



def reviewed_cves(repository: str) -> set[str]:
    return {row["cve"] for row in load_reviews() if row["repository"].lower() == repository.lower()}


def excluded_cves(repository: str) -> set[str]:
    payload = json.loads(REVIEWS.read_text(encoding="utf-8"))
    rows = payload.get("exclusions", [])
    if not isinstance(rows, list):
        raise ValueError("Invalid source artifact exclusions")
    for row in rows:
        if (not isinstance(row, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(row.get("cve", "")))
                or not row.get("repository") or not row.get("reason")
                or not re.fullmatch(r"[0-9a-f]{40}", str(row.get("revision", "")))):
            raise ValueError("Incomplete source artifact exclusion")
    return {row["cve"] for row in rows if row["repository"].lower() == repository.lower()}


def approved_cves_for_artifact(repository: str, path: str, source: bytes, *,
                               reviews: list[dict] | None = None) -> set[str]:
    """Exact author/path/content exceptions for strict collection attribution."""
    digest = hashlib.sha256(source).hexdigest()
    return {row["cve"] for row in (load_reviews() if reviews is None else reviews)
            if row["repository"].lower() == repository.lower() and row["path"] == path
            and row["sha256"] == digest}


def _evidence(repository: str, revision: str, artifacts: list[dict], cves: set[str], reviews: list[dict]) -> tuple[ArtifactEvidence, ...]:
    approved: dict[tuple[str, str], list[dict]] = {}
    for row in reviews:
        if row["repository"].lower() == repository.lower():
            approved.setdefault((row["cve"], row["sha256"]), []).append(row)
    result = []
    for artifact in artifacts:
        if not valid_path(str(artifact.get("path", ""))):
            continue
        for cve in sorted(cves):
            matches = approved.get((cve, artifact.get("sha256")), [])
            if matches:
                review = next((r for r in matches if r["repository"].lower() == repository.lower()
                               and r["path"] == artifact["path"]), matches[0])
                # Preserve the reviewed revision and its sibling context. A
                # copied harness alone is not evidence for another repository.
                result.append(ArtifactEvidence(cve, review["repository"], review["path"], review["revision"],
                                               artifact["sha256"], review["id"], review.get("released_at")))
    return tuple(result)


def reviewed_artifacts(repo: dict) -> tuple[ArtifactEvidence, ...]:
    """Only the local collector can attach typed evidence; JSON cannot forge it."""
    name = str(repo.get("nameWithOwner") or "")
    return tuple(item for item in (repo.get("_source_artifacts") or ())
                 if isinstance(item, ArtifactEvidence) and item.repository.lower() == name.lower()
                 and item.cve not in excluded_cves(name))


def approved_artifact_links(repo: dict, cve: str) -> list[str]:
    return sorted({item.url for item in reviewed_artifacts(repo) if item.cve == cve})


def _load_candidates(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "repositories": {}}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != 1 or not isinstance(payload.get("repositories"), dict):
        raise ValueError("Invalid source artifact candidate state")
    return payload


def _save_candidate(path: Path, name: str, row: dict) -> None:
    with _LOCK:
        payload = _load_candidates(path)
        payload["repositories"][name.lower()] = row
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)


class InspectionDeferred(Exception):
    pass


def pending_reviewed_names(limit: int = 16, *, cves: set[str] | None = None) -> list[str]:
    known = {row["repository"].lower() for row in load_reviews()
             if cves is None or row["cve"] in cves}
    with _LOCK:
        rows = _load_candidates(CANDIDATES)["repositories"]
    pending = [(row.get("last_checked_at") or row.get("last_attempt_at") or "", name) for name, row in rows.items()
               if name in known and row.get("scan_complete") is False]
    return [name for _, name in sorted(pending)[:limit]]


def mark_pending_checked(names: list[str]) -> None:
    """Rotate inaccessible replay entries without pretending their scans finished."""
    with _LOCK:
        rows = _load_candidates(CANDIDATES)["repositories"]
    now = datetime.now(timezone.utc).isoformat()
    for name in names:
        row = rows.get(name.lower())
        if row and row.get("scan_complete") is False:
            _save_candidate(CANDIDATES, name, {**row, "last_checked_at": now})


class InspectionBudget:
    def __init__(self, requests: int = 64, seconds: float = 120):
        self.remaining = requests
        self.exhausted = False
        self.deadline = time.monotonic() + seconds

    def fetch(self, fetch_json, name: str, url: str, **kwargs):
        remaining_time = self.deadline - time.monotonic()
        if self.exhausted or self.remaining <= 0 or remaining_time <= 0:
            raise InspectionDeferred("budget_deferred")
        self.remaining -= 1
        kwargs["timeout"] = min(15, remaining_time)
        try:
            return fetch_json(url, **kwargs)
        except HTTPError as exc:
            if exc.code in {403, 429} and str((exc.headers or {}).get("X-RateLimit-Remaining")) == "0":
                self.exhausted = True
                raise InspectionDeferred("rate_limited") from exc
            raise


_AUTOMATIC_BUDGET: InspectionBudget | None = None


def automatic_budget() -> InspectionBudget:
    global _AUTOMATIC_BUDGET
    if _AUTOMATIC_BUDGET is None:
        _AUTOMATIC_BUDGET = InspectionBudget()
    return _AUTOMATIC_BUDGET


def inspect_repository(repo: dict, cves: set[str], readme: str, fetch_json, headers: dict,
                       *, reviews_path: Path | None = None, candidates_path: Path | None = None,
                       persist: bool = True, budget: InspectionBudget | None = None) -> tuple[ArtifactEvidence, ...]:
    """Verify reviewed paths first; retain bounded deferred work without rejecting it."""
    name = str(repo.get("nameWithOwner") or "")
    reviews = [r for r in load_reviews(reviews_path) if r["repository"].lower() == name.lower()]
    known = {row["cve"] for row in reviews}
    cves = set(cves) & (identity_cves(name) | known)
    if not cves or repo.get("isFork") or ("defaultBranchRef" in repo and repo["defaultBranchRef"] is None):
        return ()
    reviews = [r for r in reviews if r["cve"] in cves]
    state_path = candidates_path or CANDIDATES
    with _LOCK:
        cached = _load_candidates(state_path)["repositories"].get(name.lower()) or {}
    revision = str(((repo.get("defaultBranchRef") or {}).get("target") or {}).get("oid") or "")
    review_set = hashlib.sha256(json.dumps(reviews, sort_keys=True).encode()).hexdigest()
    artifacts, skipped_paths, known_checked = [], set(), set()
    attempted = False
    status, complete = "needs_review", False

    def read(url, *, allow_not_found=False):
        nonlocal attempted
        prior = budget.remaining if budget else None
        try:
            if budget:
                return budget.fetch(fetch_json, name, url, headers=headers, allow_not_found=allow_not_found)
            attempted = True
            return fetch_json(url, headers=headers, allow_not_found=allow_not_found)
        finally:
            if budget and budget.remaining != prior:
                attempted = True

    def accept_blob(path, size, oid, blob):
        if (not isinstance(size, int) or not 0 < size <= MAX_BYTES
                or not re.fullmatch(r"[0-9a-f]{40}", str(oid or ""))):
            raise RuntimeError(f"Invalid blob identity for {name}/{path}")
        if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
            raise RuntimeError(f"Incomplete source blob for {name}/{path}")
        raw = base64.b64decode("".join(blob["content"].split()), validate=True)
        if len(raw) != size:
            raise RuntimeError(f"Source blob size mismatch for {name}/{path}")
        if hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() != oid:
            raise RuntimeError(f"Source blob identity mismatch for {name}/{path}")
        if b"\0" in raw:
            skipped_paths.add(path)
        else:
            artifacts.append({"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})

    try:
        if not revision:
            try:
                commit = read(f"https://api.github.com/repos/{name}/commits/HEAD", allow_not_found=True)
            except HTTPError as exc:
                if exc.code != 409:
                    raise
                commit = None
            if commit is None:
                return ()
            revision = str(commit.get("sha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise RuntimeError(f"Invalid artifact revision for {name}")
        same_revision = cached.get("revision") == revision
        if same_revision:
            artifacts = list(cached.get("artifacts", []))
            skipped_paths = set(cached.get("skipped_paths", []))
            known_checked = set(cached.get("known_checked", []))
        same_rules = cached.get("review_set_sha256") == review_set
        if same_revision and same_rules and cves <= set(cached.get("cves", [])):
            if cached.get("scan_complete", True) or cached.get("status") == "tree_limited":
                if persist and cached.get("status") == "tree_limited":
                    _save_candidate(state_path, name, {**cached, "last_checked_at": datetime.now(timezone.utc).isoformat()})
                return _evidence(name, revision, artifacts, cves, reviews)
        known_paths = {r["path"] for r in reviews}
        inspected = {a["path"] for a in artifacts} | skipped_paths
        pending_paths = sorted(known_paths - known_checked - inspected)
        for path in pending_paths[:MAX_FILES]:
            blob = read(f"https://api.github.com/repos/{name}/contents/{quote(path, safe='/')}?ref={revision}", allow_not_found=True)
            if blob is not None and not isinstance(blob, (dict, list)):
                raise RuntimeError(f"Incomplete source contents for {name}/{path}")
            if isinstance(blob, dict) and blob.get("type") not in {"file", "dir", "symlink", "submodule"}:
                raise RuntimeError(f"Incomplete source contents for {name}/{path}")
            if isinstance(blob, dict) and blob.get("type") == "file":
                size = blob.get("size")
                if isinstance(size, int) and 0 < size <= MAX_BYTES:
                    accept_blob(path, size, blob.get("sha"), blob)
            known_checked.add(path)
        if len(pending_paths) > MAX_FILES:
            raise InspectionDeferred("file_limited")
        expected = {(r["cve"], r["sha256"]) for r in reviews}
        matched = {(item.cve, item.sha256) for item in _evidence(name, revision, artifacts, cves, reviews)}
        if expected and expected <= matched:
            complete = True
        else:
            tree = read(f"https://api.github.com/repos/{name}/git/trees/{revision}?recursive=1")
            if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list) or not isinstance(tree.get("truncated"), bool):
                raise RuntimeError(f"Incomplete artifact tree for {name}")
            if tree["truncated"] or len(tree["tree"]) > MAX_TREE:
                raise InspectionDeferred("tree_limited")
            eligible = []
            for entry in tree["tree"]:
                path = str(entry.get("path") or "")
                if entry.get("type") != "blob" or entry.get("mode") not in {"100644", "100755"} or not valid_path(path):
                    continue
                if any(part.lower() in SUPPORT for part in path.split("/")[:-1]):
                    continue
                size = entry.get("size")
                if not isinstance(size, int) or not 0 < size <= MAX_BYTES:
                    continue
                named = bool(PAYLOAD_RE.search(path)) or bool(identity_cves(path) & cves)
                mentioned = path.lower() in readme.lower()
                if path not in known_paths and not ((SOURCE_RE.search(path) or (named and not Path(path).suffix)) and (named or mentioned)):
                    continue
                eligible.append((path not in known_paths, not mentioned, not named, path.count("/"), path, entry))
            inspected = {a["path"] for a in artifacts} | skipped_paths
            eligible = [item for item in eligible if item[-2] not in inspected]
            for *_, path, entry in sorted(eligible)[:MAX_FILES]:
                blob = read(f"https://api.github.com/repos/{name}/git/blobs/{entry.get('sha')}")
                accept_blob(path, entry["size"], entry.get("sha"), blob)
            complete = len(eligible) <= MAX_FILES
            if not complete:
                status = "file_limited"
    except InspectionDeferred as deferred:
        status = str(deferred)
    evidence = _evidence(name, revision, artifacts, cves, reviews)
    if complete:
        status = "reviewed" if evidence else "needs_review" if artifacts else "no_candidate_artifact"
    observed = datetime.now(timezone.utc).isoformat()
    row = {"revision": revision, "cves": sorted(cves), "artifacts": artifacts,
           "skipped_paths": sorted(skipped_paths), "known_checked": sorted(known_checked), "review_set_sha256": review_set,
           "status": status, "first_observed_at": cached.get("first_observed_at") or observed,
           "revision_observed_at": observed, "last_attempt_at": observed if attempted else cached.get("last_attempt_at"),
           "last_checked_at": observed if attempted else cached.get("last_checked_at"),
           "scan_limited": not complete, "scan_complete": complete}
    if persist:
        _save_candidate(state_path, name, row)
    return evidence
