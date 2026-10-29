#!/usr/bin/env python3
"""Discover immutable source files for published PoC links."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from http.client import HTTPException
from pathlib import Path
from urllib import error, parse, request

import archive_pocs as archive
import releases
import source_artifacts

MANIFEST = archive.DIRECTORY / 'sources.json'
SCAN_VERSION = 3
IGNORE = {'.git', '.github', 'node_modules', 'vendor', 'third_party', '__pycache__', 'venv', '.venv'}


def repository_source(url: str) -> bool:
    parts = parse.urlsplit(url).path.strip('/').split('/')
    return bool(archive.link_health.repository(url) and
                (len(parts) == 2 or len(parts) >= 4 and parts[2] in {'blob', 'tree', 'raw'}))


class Deferred(Exception):
    pass


class GitHub:
    def __init__(self, token: str, requests: int, seconds: int):
        self.token, self.remaining = token, requests
        self.deadline = time.monotonic() + seconds
        self.last_request = 0.0

    def read(self, url: str, *, limit=2_000_000) -> bytes:
        if self.remaining <= 0 or time.monotonic() >= self.deadline:
            raise Deferred('run-budget')
        time.sleep(max(0, .25 - (time.monotonic() - self.last_request)))
        self.remaining -= 1
        self.last_request = time.monotonic()
        headers = {'User-Agent': archive.AGENT, 'Accept': 'application/vnd.github+json'}
        if parse.urlsplit(url).netloc == 'api.github.com' and self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        try:
            with request.build_opener(archive.NoRedirect).open(request.Request(url, headers=headers), timeout=20) as response:
                remaining = response.headers.get('X-RateLimit-Remaining')
                if remaining is not None and int(remaining) < 300:
                    raise Deferred('github-quota-reserve')
                return archive.response_bytes(response, limit)
        except error.HTTPError as exc:
            code = exc.code
            limited = bool(exc.headers.get('Retry-After')) or exc.headers.get('X-RateLimit-Remaining') == '0'
            exc.close()
            if code in {401, 429} or code == 403 and limited:
                raise Deferred(f'github-http-{code}') from None
            raise

    def json(self, url: str):
        return json.loads(self.read(url, limit=8_000_000))


def reproduction_path(path: str) -> bool:
    parts = path.replace('_', ' ').split('/')
    return any(releases.POC_RE.search(part) or
               re.search(r'(?:^|[. -])exp(?:$|[. -])', part, re.I)
               for part in (re.sub(r'\bpayload\b', '', p, flags=re.I) for p in parts))


def source_rank(path: str, cves) -> tuple:
    named = bool(source_artifacts.identity_cves(path) & set(cves))
    reproduction = reproduction_path(path)
    code = bool(source_artifacts.SOURCE_RE.search(path)) or path.lower().endswith('.html')
    return (not named, not reproduction, not code, path)


def candidate_paths(tree: list[dict], target: dict, readme: str = '') -> list[dict]:
    parsed = parse.urlsplit(target['original'])
    parts = parse.unquote(parsed.path).strip('/').split('/')
    scope = '/'.join(parts[4:]) if len(parts) > 4 and parts[2] in {'blob', 'tree', 'raw'} else ''
    exact = len(parts) > 4 and parts[2] in {'blob', 'raw'}
    result = []
    for entry in tree:
        path = entry.get('path', '')
        if (entry.get('type') != 'blob' or entry.get('mode') not in {'100644', '100755'}
                or not source_artifacts.valid_path(path)
                or not 0 < entry.get('size', 0) <= 2_000_000
                or any(part.lower() in IGNORE for part in path.split('/'))):
            continue
        if scope and (path != scope if exact else not path.startswith(scope.rstrip('/') + '/')):
            continue
        named = source_artifacts.identity_cves(path)
        if named and not named.intersection(target['cves']):
            continue
        name = Path(path).name.lower()
        if not (exact or releases.CODE_FILE_RE.search(path) or name.endswith(('.md', '.rst', '.html', '.asm', '.lua'))
                or name == 'readme'):
            continue
        result.append(entry)
    if len(result) > 100 and not exact:
        readme = parse.unquote(readme).lower()
        evidence = [entry for entry in result if source_artifacts.identity_cves(entry['path'])
                    or reproduction_path(entry['path']) or entry['path'].lower() in readme]
        folders = {str(Path(entry['path']).parent) for entry in evidence}
        readmes = {scope.lower() + '/' + name if scope else name for name in ('readme', 'readme.md', 'readme.rst')}
        result = [entry for entry in result if str(Path(entry['path']).parent) in folders or entry['path'].lower() in readmes]
    return sorted(result, key=lambda e: source_rank(e['path'], target['cves']))


def inspect(target: dict, old: dict, client: GitHub, *, file_limit=40) -> dict:
    repo = archive.link_health.repository(target['original'])
    base = f'https://api.github.com/repos/{repo}'
    parts = parse.unquote(parse.urlsplit(target['original']).path).strip('/').split('/')
    ref = parts[3] if len(parts) > 3 and parts[2] in {'blob', 'tree', 'raw'} else 'HEAD'
    revision = client.json(base + '/commits/' + parse.quote(ref, safe=''))['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('invalid-revision')
    compatible = old.get('scan_version') == SCAN_VERSION and old.get('cves') == sorted(target['cves'])
    same = compatible and old.get('revision') == revision
    row = {**old} if same else {'files': [], 'checked_paths': []}
    row.update(repository=repo, original=target['original'], revision=revision,
               cves=sorted(target['cves']), checked_at=archive.now(), scan_version=SCAN_VERSION)
    if same and row.get('complete'):
        row['next_check_at'] = archive.after(7 * 86400)
        return row
    explicit = len(parts) > 4 and parts[2] in {'blob', 'raw'}
    scope = '/'.join(parts[4:-1]) if explicit else '/'.join(parts[4:]) if len(parts) > 4 and parts[2] == 'tree' else ''
    expression = revision + (':' + scope if scope else '')
    tree = client.json(base + '/git/trees/' + parse.quote(expression, safe='') + ('' if explicit else '?recursive=1'))
    if not isinstance(tree.get('tree'), list) or tree.get('truncated') is not False:
        raise ValueError('incomplete-github-tree')
    if scope:
        tree['tree'] = [{**entry, 'path': scope + '/' + entry['path']} for entry in tree['tree']]
    readme = ''
    if len(tree['tree']) > 100 and not explicit:
        readme_entry = next((entry for entry in tree['tree'] if entry.get('path', '').lower() in
                            {scope.lower() + '/' + name if scope else name for name in ('readme', 'readme.md', 'readme.rst')}), None)
        if readme_entry and 0 < readme_entry.get('size', 0) <= 2_000_000:
            raw = f'https://raw.githubusercontent.com/{repo}/{revision}/{parse.quote(readme_entry["path"], safe="/")}'
            body = client.read(raw)
            oid = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
            if oid != readme_entry.get('sha'):
                raise ValueError('readme-hash-mismatch')
            readme = body.decode('utf-8', 'replace')
    entries = candidate_paths(tree['tree'], target, readme)
    collection = len({cve for entry in tree['tree'] for cve in source_artifacts.identity_cves(entry.get('path', ''))}) > 5
    if compatible and not same:
        previous = {f['path']: f for f in old.get('files', [])}
        row['files'] = [{**previous[e['path']], 'revision': previous[e['path']].get('revision', old['revision'])}
                        for e in entries if e['path'] in previous and previous[e['path']]['oid'] == e['sha']]
        previous_oids = {**{path: f['oid'] for path, f in previous.items()}, **old.get('checked_oids', {})}
        row['checked_oids'] = {e['path']: e['sha'] for e in entries if previous_oids.get(e['path']) == e['sha']}
        row['checked_paths'] = sorted(row['checked_oids'])
    checked = set(row.get('checked_paths', []))
    checked_oids = dict(row.get('checked_oids', {}))
    failed = dict(row.get('failed_paths', {}))
    remaining = [entry for entry in entries if entry['path'] not in checked]
    reviews = source_artifacts.load_reviews()
    previous_files = {entry['path']: entry for entry in old.get('files', [])}
    for entry in remaining[:file_limit]:
        path = entry['path']
        raw = f'https://raw.githubusercontent.com/{repo}/{revision}/{parse.quote(path, safe="/")}'
        try:
            body = client.read(raw)
        except Deferred as exc:
            row.update(error=str(exc), complete=False, checked_paths=sorted(checked), checked_oids=checked_oids,
                       next_check_at=archive.after(3600))
            exc.partial = row
            raise
        except (OSError, HTTPException, EOFError, archive.ArchiveError) as exc:
            failed[path] = type(exc).__name__
            continue
        oid = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        if oid != entry.get('sha'):
            row.update(error='source-hash-mismatch', complete=False)
            failed[path] = 'source-hash-mismatch'
            continue
        # Published file links have already passed artifact validation.
        named = source_artifacts.identity_cves(path)
        associated = named or set(target['cves'])
        if collection and not explicit and not named:
            associated = source_artifacts.identity_cves(body.decode('utf-8', 'replace'))
        scoped = set(target['cves']) & associated
        cves = [cve for cve in scoped if explicit or
                releases.qualifying_content(repo, cve, path, body, reviews, related_cves=named)]
        if cves:
            selected = {'path': path, 'oid': oid, 'bytes': len(body), 'cves': sorted(cves)}
            previous = previous_files.get(path, {})
            prior_revision = previous.get('revision', old.get('revision', ''))
            if previous.get('oid') == oid and re.fullmatch(r'[0-9a-f]{40}', prior_revision) and prior_revision != revision:
                selected['revision'] = prior_revision
            row['files'].append(selected)
        checked.add(path)
        checked_oids[path] = oid
        failed.pop(path, None)
    row['checked_paths'] = sorted(checked)
    row['checked_oids'] = checked_oids
    row['failed_paths'] = failed
    row['complete'] = not failed and all(entry['path'] in checked for entry in entries)
    row['candidate_files'] = len(entries)
    row['next_check_at'] = archive.after(7 * 86400 if row['complete'] else 3600 if failed else 300)
    if row['complete']:
        row.pop('error', None)
    return row


def save(path: Path, payload: dict):
    from sync_repo_metadata import save as atomic_save
    atomic_save(path, payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--requests', type=int, default=800)
    parser.add_argument('--max-seconds', type=int, default=600)
    parser.add_argument('--min-year', type=int, default=2026)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    parser.add_argument('--url', action='append', help='Inspect specific published repository URLs')
    args = parser.parse_args()
    if min(args.limit, args.requests, args.max_seconds) < 1:
        parser.error('Run limits must be positive')
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN') or ''
    if not token:
        parser.error('GITHUB_TOKEN is required for bounded source discovery')
    payload = json.loads(args.manifest.read_text()) if args.manifest.exists() else {'version': 1, 'repositories': {}}
    manifests = payload['repositories']
    payload['repositories'] = manifests = {k: r for k, r in manifests.items() if repository_source(k)}
    targets = {k: r for k, r in archive.inventory(args.min_year).items()
               if not r.get('parent') and repository_source(r['original'])
               and not archive.link_health.unavailable(r['original'])}
    if args.url:
        keys = {archive.identity(url) for url in args.url}
        if keys - targets.keys():
            parser.error('Requested URL is not an available published repository')
        targets = {key: targets[key] for key in keys}
    due = {key: {**row, 'next_check_at': ''} if row.get('scan_version', SCAN_VERSION) != SCAN_VERSION and not row.get('error') else row
           for key, row in manifests.items()}
    queue = archive.select_targets(targets, due)
    client = GitHub(token, args.requests, args.max_seconds)
    for count, key in enumerate(queue[:args.limit], 1):
        old = manifests.get(key, {})
        try:
            manifests[key] = inspect(targets[key], old, client)
        except Deferred as exc:
            manifests[key] = getattr(exc, 'partial', {**old, 'checked_at': archive.now(), 'error': str(exc),
                                                      'next_check_at': archive.after(3600)})
            save(args.manifest, payload)
            print(f'Source discovery paused: {exc}', flush=True)
            break
        except (OSError, HTTPException, EOFError, ValueError, KeyError, archive.ArchiveError) as exc:
            manifests[key] = {**old, 'checked_at': archive.now(), 'next_check_at': archive.after(86400),
                              'error': type(exc).__name__}
        save(args.manifest, payload)
        print(f'{count}: {key}: {len(manifests[key].get("files", []))} source files; '
              f'{"complete" if manifests[key].get("complete") else "pending"}', flush=True)
        if client.remaining <= 0 or time.monotonic() >= client.deadline:
            break
    print(json.dumps({'repositories': len(manifests), 'files': sum(len(r.get('files', [])) for r in manifests.values())}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
