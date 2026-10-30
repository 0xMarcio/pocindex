#!/usr/bin/env python3
"""Resumable Wayback lookup/capture of published PoC pages and source artifacts."""
from __future__ import annotations

import argparse
import copy
import hashlib
import gzip
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from pathlib import Path
from urllib import error, parse, request

import link_health

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'index' / 'archives'
API = 'https://web.archive.org/save'
AVAILABILITY = 'https://archive.org/wayback/available'
AGENT = 'pocindex/1.0 (+https://pocindex.io)'
CAPTURE_INTERVAL = 30
PENDING_INTERVAL = 5
REPLAY_LOCK = threading.Lock()
LAST_REPLAY = 0.0


def now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def public_url(url: str) -> bool:
    try:
        p = parse.urlsplit(url)
        if (p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password
                or p.port not in {None, 80, 443} or any(c.isspace() for c in url)):
            return False
        host = p.hostname.lower()
        if '.' not in host or host.endswith(('.localhost', '.local', '.internal')):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return True
    except (ValueError, TypeError):
        return False


def identity(url: str) -> str:
    return link_health.url_key(url)


def pinned_file(url: str) -> bool:
    parsed = parse.urlsplit(url)
    return parsed.hostname == 'raw.githubusercontent.com' and bool(re.fullmatch(r'/[^/]+/[^/]+/[0-9a-f]{40}/.+', parsed.path))


def snapshot_url(url: str, stamp: str) -> str:
    if not re.fullmatch(r'\d{14}', stamp) or not public_url(url):
        raise ValueError('Invalid Wayback capture identity')
    datetime.strptime(stamp, '%Y%m%d%H%M%S')
    return f'https://web.archive.org/web/{stamp}/{parse.urldefrag(url).url}'


def valid_snapshot(row: dict) -> bool:
    snap = row.get('snapshot') or {}
    try:
        p = parse.urlsplit(snap.get('url', ''))
        match = re.fullmatch(r'/web/(\d{14})/(https?://.+)', p.path + ('?' + p.query if p.query else ''))
        return bool(p.scheme == 'https' and p.netloc == 'web.archive.org' and match
                    and snap.get('timestamp') == match[1]
                    and snapshot_url(match[2], match[1]) == snap['url']
                    and (not row.get('original') or equivalent(match[2], row['original']))
                    and snap.get('verified_at'))
    except (ValueError, TypeError):
        return False


def load_records(directory: Path = DIRECTORY) -> dict:
    rows = {}
    for path in sorted(directory.glob('[0-9a-f][0-9a-f].json')):
        payload = json.loads(path.read_text())
        if payload.get('version') != 1 or not isinstance(payload.get('entries'), dict):
            raise ValueError(f'Invalid archive shard: {path}')
        for key, row in payload['entries'].items():
            if not isinstance(row, dict) or identity(row.get('original', '')) != key or not public_url(key):
                raise ValueError(f'Invalid archive record: {path}')
            if row.get('snapshot') and not valid_snapshot(row):
                raise ValueError(f'Invalid archive snapshot: {path}')
            rows[key] = row
    return rows


def save_records(rows: dict, changed: set[str], directory: Path = DIRECTORY) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    shards = {hashlib.sha256(key.encode()).hexdigest()[:2] for key in changed}
    for shard in sorted(shards):
        entries = {k: v for k, v in sorted(rows.items()) if hashlib.sha256(k.encode()).hexdigest()[:2] == shard}
        with tempfile.NamedTemporaryFile('w', dir=directory, delete=False) as handle:
            json.dump({'version': 1, 'entries': entries}, handle, sort_keys=True, separators=(',', ':'))
            handle.write('\n')
            temporary = Path(handle.name)
        temporary.replace(directory / (shard + '.json'))


def load_source_manifests() -> dict:
    path = DIRECTORY / 'sources.json'
    return json.loads(path.read_text()).get('repositories', {}) if path.exists() else {}


def source_selection(row: dict, parent: str, manifests: dict) -> dict | None:
    manifest = manifests.get(parent, {})
    if not (pinned_file(row['original']) and manifest.get('complete') and manifest.get('scan_version', 0) >= 3):
        return None
    parts = parse.unquote(parse.urlsplit(row['original']).path).strip('/').split('/')
    path = '/'.join(parts[3:])
    same_blob = manifest.get('checked_oids', {}).get(path) in row.get('expected_blobs', [])
    if manifest.get('revision') != parts[2] and not same_blob:
        return None
    return next((entry for entry in manifest.get('files', []) if entry['path'] == path), {})


def published_snapshots(records: dict | None = None, allowed: set | None = None, *, manifests: dict | None = None) -> dict:
    rows = load_records() if records is None else records
    manifests = load_source_manifests() if manifests is None else manifests
    result = {}
    for key, row in rows.items():
        parents = row.get('parents') or ({row['parent']: row.get('parent_original', row['parent'])} if row.get('parent') else {})
        if parents and pinned_file(row['original']):
            parents = {parent: original for parent, original in parents.items()
                       if source_selection(row, parent, manifests) != {}}
            if not parents and (allowed is None or key not in allowed):
                continue
        if not valid_snapshot(row) or allowed is not None and key not in allowed and not (parents.keys() & allowed):
            continue
        snap = {k: row['snapshot'][k] for k in ('url', 'timestamp')}
        result.setdefault(row['original'], {}).update(snap)
        for parent_key, original in parents.items():
            if allowed is not None and parent_key not in allowed:
                continue
            parent = rows.get(parent_key, {}).get('original') or original
            result.setdefault(parent, {}).setdefault('files', []).append({'original': row['original'], **snap})
    for original, value in list(result.items()):
        if not pinned_file(original):
            for file in value.get('files', []):
                if allowed is not None and identity(file['original']) in allowed:
                    result[file['original']]['files'] = value['files']
    for value in list(result.values()):
        if value.get('url'):
            original = value['url'].split('/', 5)[-1]
            result.setdefault(original, value)
    return result


def archived_fallbacks(records: dict | None = None, blacklist=(), exclusions=()) -> dict:
    """Recover the preserved artifact, never republish its unavailable original."""
    result = defaultdict(list)
    records = load_records() if records is None else records
    rows = [row for row in records.values() if valid_snapshot(row)]
    if not rows:
        return result
    eligible = defaultdict(dict)
    for row in eligible_ledger():
        eligible[identity(row['url'])][row['cve']] = row
    manifests, selected = load_source_manifests(), {}
    from archive_sources import source_rank
    for row in rows:
        sources = list(row.get('parents', {})) or [row.get('parent') or row['original']]
        for source in sources:
            if link_health.repository(source) in blacklist:
                continue
            selection = source_selection(row, source, manifests) if source != row['original'] else None
            if selection == {}:
                continue
            cves = selection.get('cves', row.get('cves', [])) if selection else row.get('cves', [])
            for cve, pair in eligible.get(identity(source), {}).items():
                if source != row['original'] and cve not in cves:
                    continue
                if (re.fullmatch(r'CVE-\d{4}-\d{4,}', cve)
                        and (cve, link_health.repository(source)) not in exclusions
                        and pair and (link_health.unavailable(source) or pair.get('gone_reason') == 'unavailable')):
                    field = pair.get('field', 'poc')
                    path = '/'.join(parse.unquote(parse.urlsplit(row['original']).path).strip('/').split('/')[3:])
                    rank = (source != row['original'], source_rank(path, [cve]), row['original'])
                    key = (cve, identity(source))
                    if key not in selected or rank < selected[key][0]:
                        selected[key] = (rank, field, row['snapshot']['url'])
    for (cve, _), (_, field, url) in sorted(selected.items()):
        if (field, url) not in result[cve]:
            result[cve].append((field, url))
    return result


class ArchiveError(Exception):
    def __init__(self, reason: str, *, cooldown: int = 0, fatal: bool = False):
        super().__init__(reason)
        self.cooldown = cooldown
        self.fatal = fatal


def service_error(reason: str) -> ArchiveError | None:
    if reason in {'error:max-daily-bandwidth', 'error:max-daily-bandwidth-from-ip'}:
        return ArchiveError(reason, cooldown=86400)
    if reason == 'error:user-session-limit':
        return ArchiveError(reason, cooldown=300)
    if reason == 'error:blocked-client-ip':
        return ArchiveError(reason, cooldown=3600)
    if reason in {'error:celery', 'error:job-failed', 'error:internal-server-error',
                  'error:no-browsers-available', 'error:proxy-error', 'error:capture-location-error', 'error:cannot-fetch'}:
        return ArchiveError(reason, cooldown=600)
    return None


class NoRedirect(request.HTTPRedirectHandler):
    # IA credentials are never forwarded to a redirected origin.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def response_bytes(response, limit: int) -> bytes:
    encoding = response.headers.get('Content-Encoding', '').lower()
    if encoding in {'', 'identity'}:
        body = response.read(limit + 1)
    elif encoding == 'gzip':
        try:
            with gzip.GzipFile(fileobj=response) as stream:
                body = stream.read(limit + 1)
        except (gzip.BadGzipFile, EOFError, zlib.error):
            raise ArchiveError('invalid-compressed-response') from None
    else:
        raise ArchiveError('unsupported-response-encoding')
    if len(body) > limit:
        raise ArchiveError('response-too-large')
    return body


class ReplayRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = parse.urlsplit(newurl)
        if destination.scheme != 'https' or destination.netloc != 'web.archive.org':
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def after(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


def retry_delay(value: str, default: int = 300) -> int:
    try:
        seconds = int(value) if value.isdigit() else (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        return max(default, int(seconds))
    except (ValueError, TypeError, OverflowError):
        return default


class Client:
    def __init__(self, access: str = '', secret: str = '', interval: float = CAPTURE_INTERVAL):
        self.auth = f'LOW {access}:{secret}' if access and secret else ''
        self.interval = max(CAPTURE_INTERVAL if self.auth else 21, interval)
        self.last_submit = 0.0
        self.last_request = 0.0
        self.request_lock = threading.Lock()
        self.lookup_retry_after = ''
        self.replay_retry_after = ''
        self.local = threading.local()
        self.failures = {}

    @property
    def operation(self):
        return getattr(self.local, 'operation', 'request')

    @operation.setter
    def operation(self, value):
        self.local.operation = value

    def failure(self, key: str, problem: ArchiveError) -> ArchiveError:
        message = str(problem)
        if message.startswith('transport-') or message.startswith('replay-') and not message.startswith('replay-http-'):
            with self.request_lock:
                failures = (self.failures.get(self.operation, []) + [key])[-5:]
                self.failures[self.operation] = failures
                if len(failures) >= 5 and len(set(failures)) >= 3:
                    return ArchiveError('service-transport-failures', cooldown=900)
        else:
            self.responded()
        return problem

    def responded(self):
        with self.request_lock:
            self.failures.pop(self.operation, None)

    def json(self, url: str, data: dict | None = None, *, auth: bool = False) -> dict:
        self.operation = ('capture' if data is not None else 'availability' if url.startswith(AVAILABILITY)
                          else 'account' if '/status/user' in url else 'capture-status')
        # Space lookups and status requests too, not just capture submissions.
        with self.request_lock:
            time.sleep(max(0, 1 - (time.monotonic() - self.last_request)))
            if self.operation == 'availability' and self.lookup_retry_after > now():
                delay = (datetime.fromisoformat(self.lookup_retry_after.replace('Z', '+00:00'))
                         - datetime.now(timezone.utc)).total_seconds()
                raise ArchiveError('lookup-cooldown', cooldown=max(1, int(delay) + 1))
            self.last_request = time.monotonic()
        headers = {'Accept': 'application/json', 'User-Agent': AGENT, 'Accept-Encoding': 'identity'}
        if auth and self.auth:
            if parse.urlsplit(url).netloc != 'web.archive.org':
                raise ValueError('Credentials may only be sent to Wayback')
            headers['Authorization'] = self.auth
        payload = None if data is None else parse.urlencode(data).encode()
        req = request.Request(url, data=payload, headers=headers)
        try:
            # Busy-host captures can be queued before SPN returns a job ID.
            # Allow that delay without issuing duplicate submission requests.
            with request.build_opener(NoRedirect).open(req, timeout=90 if data is not None else 20) as response:
                self.responded()
                value = json.loads(response_bytes(response, 1_000_000))
            if not isinstance(value, dict):
                raise ArchiveError('invalid-response', cooldown=600)
            return value
        except error.HTTPError as exc:
            code = exc.code
            retry = exc.headers.get('Retry-After', '')
            exc.close()
            delay = retry_delay(retry) if code == 429 else 600 if code >= 500 else 0
            if self.operation == 'availability' and delay:
                self.lookup_retry_after = max(self.lookup_retry_after, after(delay))
            self.responded()
            if code in {401, 403} and parse.urlsplit(url).path != '/save/status/user' and auth:
                # SPN can return the target's access failure at this endpoint.
                # Confirm account access before declaring credentials invalid.
                operation = self.operation
                self.account()
                self.operation = operation
                raise ArchiveError(f'target-http-{code}') from None
            raise ArchiveError(f'http-{code}', cooldown=delay or (900 if code in {401, 403} and not auth else 0),
                               fatal=auth and code in {401, 403}) from None
        except (ValueError, EOFError):
            raise ArchiveError('invalid-response', cooldown=600) from None
        except (OSError, error.URLError, HTTPException) as exc:
            cause = getattr(exc, 'reason', exc)
            raise ArchiveError('transport-' + type(cause).__name__) from None

    def lookup(self, url: str, timestamp: str = '') -> dict | None:
        query = {'url': parse.urldefrag(url).url}
        if timestamp:
            query['timestamp'] = re.sub(r'\D', '', timestamp)[:14]
        result = self.json(AVAILABILITY + '?' + parse.urlencode(query))
        if not isinstance(result.get('archived_snapshots'), dict):
            raise ArchiveError('invalid-availability-response', cooldown=600)
        row = result['archived_snapshots'].get('closest') or {}
        if not row:
            return None
        if row.get('available') is not True or str(row.get('status')) != '200':
            return None
        replay = str(row.get('url', '')).replace('http://web.archive.org/', 'https://web.archive.org/', 1)
        candidate = {'url': replay, 'timestamp': row.get('timestamp'), 'verified_at': now()}
        if not valid_snapshot({'snapshot': candidate}):
            raise ArchiveError('invalid-snapshot-response', cooldown=600)
        captured = replay.split('/web/' + candidate['timestamp'] + '/', 1)[1]
        if not equivalent(captured, url):
            return None
        return candidate

    def submit(self, url: str, *, retry: bool = False) -> dict:
        time.sleep(max(0, self.interval - (time.monotonic() - self.last_submit)))
        self.last_submit = time.monotonic()
        pinned = pinned_file(url)
        payload = {'url': parse.urldefrag(url).url, 'capture_all': '0', 'capture_outlinks': '0',
                   'skip_first_archive': '1', 'if_not_archived_within': '1s' if retry else '36500d' if pinned else '30d'}
        if pinned:
            payload.update(force_get='1', js_behavior_timeout='0')
        return self.json(API, payload, auth=True)

    def status(self, job: str) -> dict:
        if not re.fullmatch(r'[a-zA-Z0-9-]+', job):
            raise ArchiveError('invalid-job-id')
        return self.json(API + '/status/' + job, auth=True)

    def account(self) -> dict:
        row = self.json(API + '/status/user?' + parse.urlencode({'_t': int(time.time() * 1000)}), auth=True)
        if not isinstance(row.get('available'), int):
            raise ArchiveError('invalid-capacity-response', cooldown=300)
        return row

    def capacity(self) -> int:
        row = self.account()
        for field in ('daily_captures', 'daily_status'):
            used, limit = row.get(field), row.get(field + '_limit')
            if isinstance(used, int) and isinstance(limit, int) and used >= limit:
                raise ArchiveError('daily-quota-exhausted', cooldown=86400)
        available = row.get('available')
        if not isinstance(available, int) or available < 0:
            raise ArchiveError('invalid-capacity-response', cooldown=300)
        return min(3, available)


def verify_snapshot(snap: dict, original: str, expected_blobs=(), repo_id=None, *, strict_blobs=False, client=None) -> bool:
    """Replay must load content, not a login page or an archive error wrapper."""
    replay = snap['url'].replace('/' + snap['timestamp'] + '/', '/' + snap['timestamp'] + 'id_/', 1)
    global LAST_REPLAY
    with REPLAY_LOCK:
        time.sleep(max(0, PENDING_INTERVAL - (time.monotonic() - LAST_REPLAY)))
        if client is not None and isinstance(client.replay_retry_after, str) and client.replay_retry_after > now():
            raise ArchiveError('replay-cooldown')
        LAST_REPLAY = time.monotonic()
    try:
        with request.build_opener(ReplayRedirect).open(request.Request(replay, headers={'User-Agent': AGENT}), timeout=30) as response:
            final = parse.urlsplit(response.url)
            if (response.status != 200 or final.hostname != 'web.archive.org'
                    or not final.path.startswith('/web/' + snap['timestamp'] + 'id_/')):
                return False
            final_original = (final.path + ('?' + final.query if final.query else '')).split(
                '/web/' + snap['timestamp'] + 'id_/', 1)[1]
            if not equivalent(final_original, original):
                return False
            body = response_bytes(response, 2_000_000)
            mime = response.headers.get('Content-Type', '').lower()
        if not body:
            return False
        raw = parse.urlsplit(original).hostname == 'raw.githubusercontent.com'
        verified_raw = False
        if raw and expected_blobs and (strict_blobs or len(body) >= 256):
            digest = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
            if digest not in expected_blobs:
                return False
            verified_raw = True
        if not verified_raw and body.strip() in {b'404: Not Found', b'Not Found', b'Access Denied'}:
            return False
        if not verified_raw and ('html' in mime or body.lstrip().lower().startswith(b'<!doctype html')):
            text = body.decode('utf-8', errors='replace')
            if repo_id and parse.urlsplit(original).hostname in {'github.com', 'www.github.com'}:
                found = re.search(r'<meta\s+name="octolytics-dimension-repository_id"\s+content="(\d+)"', text)
                if not found or found[1] != str(repo_id):
                    return False
            title = re.search(r'<title[^>]*>(.*?)</title>', text, re.I | re.S)
            if title and re.search(r'^\s*(404\b|(?:page )?not found\b|page unavailable\b|access denied\b|sign in\b|log in\b|just a moment\b|Wayback Machine\s*$)', title[1], re.I):
                return False
            if parse.urlsplit(original).hostname in {'hackerone.com', 'www.hackerone.com'}:
                # A 200 HackerOne application shell is not a saved public report.
                if not re.search(r'"vulnerability_information"\s*:\s*"[^"\s]|report-content[^>]*>\s*\S', text):
                    return False
        if parse.urlsplit(original).path.endswith('.json') and 'hackerone.com' == parse.urlsplit(original).hostname:
            report = json.loads(body)
            if not isinstance(report, dict) or not report.get('disclosed_at') or not report.get('vulnerability_information'):
                return False
        snap['verified_at'] = now()
        return True
    except ArchiveError as exc:
        if str(exc) in {'response-too-large', 'unsupported-response-encoding', 'invalid-compressed-response'}:
            return False
        raise
    except error.HTTPError as exc:
        status = exc.code
        retry = exc.headers.get('Retry-After', '')
        exc.close()
        if status in {404, 429} or status >= 500:
            raise ArchiveError(f'replay-http-{status}', cooldown=retry_delay(retry) if status == 429 else 0) from None
        return False
    except (OSError, error.URLError, HTTPException, EOFError) as exc:
        raise ArchiveError('replay-' + type(exc).__name__) from None
    except ValueError:
        return False


def eligible_ledger(min_year: int = 2026) -> list[dict]:
    import releases
    from build_site import load_blacklist, load_source_exclusions, load_reference_exclusions, link_key, METADATA_INPUT
    blacklist, exclusions, references = load_blacklist(), load_source_exclusions(), load_reference_exclusions()
    rejected = set()
    for path in METADATA_INPUT.glob('*.json'):
        if path.stem.isdigit() and int(path.stem) >= min_year:
            rejected.update(cve for cve, meta in json.loads(path.read_text()).items() if meta.get('rejected'))
    result = []
    for row in releases.load_ledger().values():
        url = row['url']
        cve = re.fullmatch(r'CVE-(\d{4})-\d{4,}', row.get('cve', ''))
        if (not cve or int(cve[1]) < min_year or not public_url(url) or row['cve'] in rejected
                or parse.urlsplit(url).hostname == 'web.archive.org'
                or link_health.repository(url) in blacklist
                or (row['cve'], link_health.repository(url)) in exclusions
                or (row['cve'], link_key(url)) in references
                or row.get('gone') and row.get('gone_reason') != 'unavailable'):
            continue
        result.append(row)
    return result


def inventory(min_year: int = 2026) -> dict:
    import releases
    result = {}
    for row in eligible_ledger(min_year):
        url = row['url']
        key = identity(url)
        target = result.setdefault(key, {'original': url, 'cves': [], 'priority': ''})
        if row['cve'] not in target['cves']:
            target['cves'].append(row['cve'])
        target['priority'] = max(target['priority'], row.get('seen') or row.get('released') or '')
        # First observation does not establish the publication date.
        released, _ = releases.date_release(row)
        earliest = releases.timestamp(released)
        if earliest:
            bound = earliest.strftime('%Y-%m-%dT%H:%M:%SZ')
            target['not_before'] = min(target.get('not_before', bound), bound)
        if row.get('repo'):
            target['repo_id'] = str(row['repo'])
        # Pin actual code bytes when source inspection already identified a revision.
        sha = row.get('sha') if row.get('commit_verified') else None
        repo = link_health.repository(url)
        files = set()
        if repo and re.fullmatch(r'[0-9a-f]{40}', sha or ''):
            files.update((sha, path) for path in row.get('history_paths', []))
        pinned = re.fullmatch(r'/[^/]+/[^/]+/(?:blob|raw)/([0-9a-f]{40})/(.+)', parse.urlsplit(url).path)
        if repo and pinned:
            files.add((pinned[1], parse.unquote(pinned[2])))
        for revision, path in sorted(files):
            raw = f'https://raw.githubusercontent.com/{repo}/{revision}/{parse.quote(path, safe="/")}'
            item = result.setdefault(identity(raw), {'original': raw, 'cves': [],
                                                     'priority': target['priority'], 'parent': key,
                                                     'parent_original': url})
            item.setdefault('parents', {})[key] = url
            if row.get('head') == revision and path in row.get('history_paths', []) and row.get('blobs'):
                item['expected_blobs'] = row['blobs']
            if row['cve'] not in item['cves']:
                item['cves'].append(row['cve'])
    manifests = load_source_manifests()
    from archive_sources import SCAN_VERSION, repository_source, source_rank
    for parent, manifest in manifests.items():
        if parent not in result or not repository_source(result[parent]['original']):
            continue
        if manifest.get('scan_version') != SCAN_VERSION and manifest.get('candidate_files', 0) > 100:
            continue
        target = result[parent]
        repo, revision = manifest.get('repository', ''), manifest.get('revision', '')
        if repo != link_health.repository(target['original']) or not re.fullmatch(r'[0-9a-f]{40}', revision):
            continue
        files = sorted(manifest.get('files', []), key=lambda entry: source_rank(entry.get('path', ''), target['cves']))
        for rank, entry in enumerate(files):
            path, oid = entry.get('path', ''), entry.get('oid', '')
            revision = entry.get('revision') or manifest.get('revision', '')
            if (not path or any(p in {'', '.', '..'} for p in path.split('/'))
                    or not re.fullmatch(r'[0-9a-f]{40}', oid) or not re.fullmatch(r'[0-9a-f]{40}', revision)):
                continue
            raw = f'https://raw.githubusercontent.com/{repo}/{revision}/{parse.quote(path, safe="/")}'
            cves = sorted(set(entry.get('cves', target['cves'])) & set(target['cves']))
            if not cves:
                continue
            item = {'original': raw, 'cves': cves, 'priority': target['priority'],
                                     'parent': parent, 'parent_original': target['original'], 'expected_blobs': [oid],
                                     'strict_blobs': True, 'rank': rank}
            previous = result.get(identity(raw), {})
            parents = dict(previous.get('parents', {}))
            if previous.get('parent'):
                parents[previous['parent']] = previous.get('parent_original', previous['parent'])
            parents[parent] = target['original']
            item.update(cves=sorted(set(cves) | set(previous.get('cves', []))), parents=parents)
            result[identity(raw)] = item
    return result


def equivalent(left: str, right: str) -> bool:
    def parts(url):
        parsed = parse.urlsplit(identity(url))
        return parsed.netloc.lower().removeprefix('www.'), parsed.path.rstrip('/'), parsed.query
    return public_url(left) and public_url(right) and parts(left) == parts(right)


def active_job(row: dict) -> bool:
    return bool(row.get('job_id') and row.get('submitted_at', '') > after(-3600))


def verify_candidate(row: dict, client: Client | None = None) -> None:
    if client is not None:
        client.operation = 'replay'
        if isinstance(client.replay_retry_after, str) and client.replay_retry_after > now():
            row.update(status='pending', next_check_at=client.replay_retry_after)
            return
    snap = row['candidate']
    if snap['timestamp'] == row.get('expired_capture'):
        row.pop('candidate', None)
        row.pop('candidate_seen_at', None)
        row.pop('verify_attempts', None)
        row.update(error='capture-replay-missing', next_check_at=after(30 * 86400 if row.get('unavailable_since') else 3600))
        if not row.get('unavailable_since'):
            row['bad_capture'] = True
        return
    first_seen = row.setdefault('candidate_seen_at', now())
    captured = snap['url'].split('/web/' + snap['timestamp'] + '/', 1)[1]
    moment = datetime.strptime(snap['timestamp'], '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
    lower = datetime.fromisoformat(row['not_before'].replace('Z', '+00:00')) if row.get('not_before') else None
    upper = datetime.fromisoformat(row['unavailable_since'].replace('Z', '+00:00')) if row.get('unavailable_since') else None
    row['next_check_at'] = after(60)
    row['verify_attempts'] = row.get('verify_attempts', 0) + 1
    row['next_check_at'] = after(min(3600, 60 * 2 ** min(row['verify_attempts'] - 1, 6)))
    valid = equivalent(captured, row['original']) and (lower is None or moment >= lower - timedelta(minutes=5))
    valid = valid and (upper is None or moment <= upper)
    try:
        valid = valid and verify_snapshot(snap, row['original'], row.get('expected_blobs', ()), row.get('repo_id'),
                                          strict_blobs=bool(row.get('strict_blobs')), client=client)
    except ArchiveError as exc:
        if str(exc) == 'replay-cooldown' and client is not None:
            row.update(status='pending', next_check_at=client.replay_retry_after)
            row['verify_attempts'] -= 1
            return
        if str(exc) == 'replay-http-404' and row['verify_attempts'] >= 3 and first_seen <= after(-48 * 3600):
            row.pop('candidate', None)
            row.pop('candidate_seen_at', None)
            row.pop('verify_attempts', None)
            row.update(expired_capture=snap['timestamp'], lookup_required=True, next_check_at=after(3600))
        raise
    if client is not None:
        client.responded()
    if valid:
        snap['verified_at'] = now()
        if not valid_snapshot({'original': row['original'], 'snapshot': snap}):
            row.pop('candidate', None)
            row.update(error='invalid-capture-response', next_check_at=after(86400))
            return
        # Retain the earliest verified capture.
        if not valid_snapshot(row):
            row['snapshot'] = snap
        else:
            row['latest_snapshot'] = snap
        row.update(status='available', attempts=0, next_check_at=after(30 * 86400))
        row.pop('error', None)
        row.pop('bad_capture', None)
        row.pop('lookup_required', None)
        row.pop('expired_capture', None)
        row.pop('empty_lookups', None)
    else:
        row.update(error='capture-content-unverified', bad_capture=True,
                   next_check_at=after(min(7 * 86400, 3600 * 2 ** min(row.get('attempts', 0), 8))))
        if row.get('unavailable_since'):
            defer_dead_lookup(row)
    row.pop('candidate', None)
    row.pop('candidate_seen_at', None)
    row.pop('verify_attempts', None)


def defer_dead_lookup(row: dict) -> None:
    count = row.get('empty_lookups', 0) + 1
    delays = (3600, 6 * 3600, 86400, 3 * 86400, 30 * 86400)
    row.update(empty_lookups=count, next_check_at=after(delays[min(count - 1, len(delays) - 1)]))


def capture_failure(row: dict, reason: str) -> None:
    row['error'] = reason
    if problem := service_error(reason):
        raise problem
    if reason == 'error:too-many-daily-captures':
        row['next_check_at'] = after(86400)
    if reason in {'error:too-many-requests', 'error:max-daily-bandwidth-host', 'error:too-many-daily-captures-host'}:
        row['host_retry_after'] = after(60 if reason == 'error:too-many-requests' else 86400)


def process(key: str, target: dict, rows: dict, client: Client, *, capture: bool,
            directory: Path | None = None, allow_submit: bool = True) -> None:
    row = rows.setdefault(key, {**target, 'attempts': 0})
    for field in ('not_before', 'repo_id', 'parent', 'parent_original', 'parents', 'expected_blobs', 'strict_blobs'):
        row.pop(field, None)
    row.update(target)  # Drop corrected CVE associations; don't union stale ones.
    row.update(checked_at=now(), status='retry')
    unavailable = link_health.unavailable(row['original'])
    if unavailable:
        row.setdefault('unavailable_since', link_health.unavailable_since(row['original']) or now())
        if valid_snapshot(row):
            row.pop('job_id', None)
            row.pop('candidate', None)
            row.pop('lookup_required', None)
            row.update(status='available', next_check_at=after(30 * 86400))
            return
    else:
        row.pop('unavailable_since', None)
        row.pop('empty_lookups', None)
    if row.get('candidate'):
        verify_candidate(row, client)
        return
    recover_job = bool(row.get('lookup_required'))
    if row.get('job_id'):
        row['next_check_at'] = after(30)
        try:
            status = client.status(row['job_id']) if active_job(row) else {}
        except ArchiveError as exc:
            if str(exc) not in {'http-404', 'http-410'}:
                raise
            status = {}
        if status.get('status') == 'pending':
            row.update(status='pending', next_check_at=after(10))
            return
        row.pop('job_id', None)
        if status.get('status') == 'success':
            try:
                row['candidate'] = {'url': snapshot_url(status.get('original_url', row['original']), status['timestamp']),
                                    'timestamp': status['timestamp']}
                row['candidate_seen_at'] = now()
            except (ValueError, TypeError, KeyError):
                row.update(error='invalid-capture-response', next_check_at=after(3600))
                return
            verify_candidate(row, client)
            return  # Never resubmit a terminal job in the same run.
        if status.get('status') == 'error':
            row['next_check_at'] = after(3600)
            capture_failure(row, str(status.get('status_ext') or 'capture-error'))
            return
        recover_job = True
    row['next_check_at'] = after(3600)
    needs_lookup = (not capture or unavailable or recover_job or
                    not row.get('parent') and not valid_snapshot(row) and row.get('lookup_checked_at', '') < after(-30 * 86400))
    lookup_blocked = isinstance(client.lookup_retry_after, str) and client.lookup_retry_after > now()
    if needs_lookup and lookup_blocked and (not capture or unavailable or recover_job):
        row.update(error='lookup-cooldown', next_check_at=client.lookup_retry_after)
        return
    if needs_lookup and not lookup_blocked:
        snap = client.lookup(row['original'], row['unavailable_since']) if row.get('unavailable_since') else client.lookup(row['original'])
        row['lookup_checked_at'] = now()
        row.pop('lookup_required', None)
        if snap:
            row['candidate'] = snap
            row['candidate_seen_at'] = now()
            verify_candidate(row, client)
            return
        if unavailable:
            defer_dead_lookup(row)
    if not capture or unavailable:
        row['status'] = 'not-found'
        if not unavailable:
            row['next_check_at'] = ''  # A negative lookup is ready for capture now.
        return
    if not allow_submit:
        row.update(status='queued', next_check_at='')
        return
    day = now()[:10]
    budget = row.setdefault('submissions', {'date': day, 'count': 0})
    if budget['date'] != day:
        budget.update(date=day, count=0)
    if budget['count'] >= 2:
        row['next_check_at'] = after(86400)
        return
    row['attempts'] = row.get('attempts', 0) + 1
    row['next_check_at'] = after(min(7 * 86400, 3600 * 2 ** min(row['attempts'], 8)))
    budget['count'] += 1
    row['submitted_at'] = now()
    row['lookup_required'] = True
    if directory is not None:
        save_records(rows, {key}, directory)
    try:
        response = client.submit(row['original'], retry=bool(row.get('bad_capture')))
    except ArchiveError as exc:
        if str(exc).startswith(('http-4', 'target-http-')):
            row.pop('lookup_required', None)
        if str(exc).startswith('transport-'):
            row['attempts'] -= 1
            row['next_check_at'] = after(3600)
            if str(exc) == 'transport-ConnectionRefusedError':
                budget['count'] -= 1
                row.pop('lookup_required', None)
        raise
    finally:
        # submit() may first wait for its pacing slot. Persist the completion
        # time so a restarted worker cannot underestimate the last request.
        row['submitted_at'] = now()
    row.pop('lookup_required', None)
    job = response.get('job_id')
    if job and re.fullmatch(r'[a-zA-Z0-9-]+', str(job)):
        row.update(job_id=job, status='pending', next_check_at=after(10))
        row.pop('error', None)
    else:
        capture_failure(row, str(response.get('status_ext') or 'capture-not-accepted')[:160])


def credentials() -> tuple[str, str]:
    access, secret = os.environ.get('IA_ACCESS_KEY', ''), os.environ.get('IA_SECRET_KEY', '')
    if bool(access) != bool(secret):
        raise ValueError('Both Internet Archive credentials must be set')
    if not access and not os.environ.get('GITHUB_ACTIONS'):
        path = Path.home() / '.config' / 'pocindex' / 'internet-archive.json'
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise ValueError('Internet Archive credential file must be private (chmod 600)')
            stored = json.loads(path.read_text())
            access, secret = stored['access'], stored['secret']
    return access, secret


def select_targets(targets: dict, rows: dict, *, capture=False) -> list[str]:
    eligible = [key for key in targets if not rows.get(key, {}).get('job_id')
                and not rows.get(key, {}).get('candidate')
                and not rows.get(key, {}).get('lookup_required')
                and rows.get(key, {}).get('next_check_at', '') <= now()]
    pages = [key for key in eligible if not targets[key].get('parent')]
    checked = 'submitted_at' if capture else 'checked_at'
    fresh = sorted(pages, key=lambda k: (valid_snapshot(rows.get(k, {})),
                   bool(rows.get(k, {}).get(checked) or capture and rows.get(k, {}).get('empty_lookups')), targets[k]['priority'], k))
    recent = sorted(pages, key=lambda k: (not valid_snapshot(rows.get(k, {})),
                    not bool(rows.get(k, {}).get(checked) or capture and rows.get(k, {}).get('empty_lookups')), targets[k]['priority'], k), reverse=True)
    files = sorted((k for k in eligible if targets[k].get('parent')
                    and not (capture and pinned_file(targets[k]['original']) and valid_snapshot(rows.get(k, {})))),
                   key=lambda k: (valid_snapshot(rows.get(k, {})), rows.get(k, {}).get('status') != 'queued',
                                  bool(rows.get(k, {}).get('submitted_at')),
                                  rows.get(k, {}).get('checked_at', ''), targets[k].get('rank', 0), k))
    grouped = defaultdict(list)
    for key in files:
        grouped[targets[key]['parent']].append(key)
    from itertools import zip_longest
    parents = list(grouped)
    recent_parents = sorted(parents, key=lambda parent: max(targets[k]['priority'] for k in grouped[parent]), reverse=True)
    parents = list(dict.fromkeys(p for pair in zip_longest(recent_parents, parents) for p in pair if p is not None))
    files = [key for group in zip_longest(*(grouped[parent] for parent in parents)) for key in group if key is not None]
    result, seen = [], set()
    # Alternate recent and old pages; reserve four slots per page for files.
    file_queue = iter(files)
    pages = iter(dict.fromkeys(key for group in zip_longest(recent, fresh) for key in group if key is not None))
    for group in zip_longest(pages, file_queue, file_queue, file_queue, file_queue):
        for key in group:
            if key is not None and key not in seen:
                result.append(key)
                seen.add(key)
    return result


def lookup_pages(targets: dict, rows: dict, client: Client, directory: Path, limit: int, seconds: int) -> int:
    """Look up page captures with bounded concurrency and request pacing."""
    deadline = time.monotonic() + seconds
    completed, stopped, fatal = 0, False, False
    control = directory / 'lookup-control.json'
    for name in ('control.json', 'replay-control.json'):
        replay_control = directory / name
        if replay_control.exists():
            client.replay_retry_after = max(client.replay_retry_after, json.loads(replay_control.read_text()).get('retry_after', ''))
    if control.exists():
        client.lookup_retry_after = json.loads(control.read_text()).get('retry_after', '')
    candidates = [k for k in targets if rows.get(k, {}).get('candidate')]
    due = sorted((k for k in candidates if rows[k].get('next_check_at', '') <= now()),
                 key=lambda k: (not targets[k].get('parent'), rows[k].get('next_check_at', ''), k))
    if isinstance(client.replay_retry_after, str) and client.replay_retry_after > now():
        due = []
    pages = {k: r for k, r in targets.items() if not r.get('parent')
             and not valid_snapshot(rows.get(k, {}))
             and rows.get(k, {}).get('lookup_checked_at', '') < after(-30 * 86400)}
    lookups = [k for k in pages if rows.get(k, {}).get('lookup_required')
               and not rows[k].get('job_id') and not rows[k].get('candidate')
               and rows[k].get('next_check_at', '') <= now()]
    lookups += select_targets(pages, rows)
    if isinstance(client.lookup_retry_after, str) and client.lookup_retry_after > now():
        lookups = []
    selected = iter((due[:limit] + lookups[:max(0, limit - len(candidates))])[:limit])

    def read(key):
        # Only the coordinator writes the shared records/shards.
        local = {key: copy.deepcopy(rows[key])} if key in rows else {}
        problem = None
        try:
            process(key, targets[key], local, client, capture=False)
        except ArchiveError as exc:
            problem = client.failure(key, exc) if isinstance(client, Client) else exc
            problem.operation = client.operation
            local[key].update(error=str(problem), status='retry', next_check_at=max(local[key].get('next_check_at', ''), after(problem.cooldown or 3600)))
            if problem.cooldown:
                if problem.operation == 'replay':
                    client.replay_retry_after = local[key]['next_check_at']
                else:
                    client.lookup_retry_after = local[key]['next_check_at']
        return local[key], problem

    with ThreadPoolExecutor(max_workers=4) as pool:
        pending = {}
        while pending or not stopped:
            while not stopped and len(pending) < 4 and time.monotonic() < deadline:
                key = next(selected, None)
                if key is None:
                    stopped = True
                    break
                pending[pool.submit(read, key)] = key
            if not pending:
                break
            done, _ = wait(pending, timeout=1, return_when=FIRST_COMPLETED)
            for future in done:
                key = pending.pop(future)
                row, problem = future.result()
                rows[key] = row
                save_records(rows, {key}, directory)
                completed += 1
                if problem and (problem.cooldown or problem.fatal):
                    stopped = True
                    fatal |= problem.fatal
                    if getattr(problem, 'operation', '') == 'replay':
                        name = 'replay-control.json' if str(problem) == 'service-transport-failures' else 'control.json'
                        destination = directory / name
                    else:
                        destination = control
                    state = json.loads(destination.read_text()) if destination.exists() else {}
                    state.update(retry_after=max(state.get('retry_after', ''), after(problem.cooldown or 300)), reason=str(problem))
                    destination.write_text(json.dumps(state) + '\n')
                    print(f'Archive lookup paused: {problem}', flush=True)
                print(f'{completed}: {row["status"]} {row["original"]}', flush=True)
            if time.monotonic() >= deadline:
                stopped = True
    print(json.dumps({'looked_up': completed, 'snapshots': sum(valid_snapshot(r) for r in rows.values())}), flush=True)
    return int(fatal)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--max-seconds', type=int, default=1200)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--lookup-pages', action='store_true', help='Inventory existing page captures without submitting saves')
    parser.add_argument('--files-only', action='store_true', help='Capture only identified source files')
    parser.add_argument('--directory', type=Path, default=DIRECTORY)
    parser.add_argument('--url', action='append', help='Only process these known inventory URLs')
    parser.add_argument('--merge-from', type=Path)
    parser.add_argument('--stats', action='store_true')
    parser.add_argument('--min-year', type=int, default=2026)
    args = parser.parse_args()
    if args.limit < 1 or args.max_seconds < 1 or args.min_year < 1999:
        parser.error('Run limits must be positive')
    if args.capture and args.lookup_pages:
        parser.error('Choose capture or page lookup')
    rows = load_records(args.directory)
    if args.merge_from:
        incoming = load_records(args.merge_from)
        for key, row in incoming.items():
            old = rows.get(key, {})
            if old.get('checked_at', '') > row.get('checked_at', ''):
                if valid_snapshot(row) and not valid_snapshot(old):
                    rows[key] = {**old, 'snapshot': row['snapshot']}
                continue
            if valid_snapshot(old):
                row['snapshot'] = old['snapshot']
            rows[key] = row
        save_records(rows, set(incoming), args.directory)
        for name in ('control.json', 'lookup-control.json', 'replay-control.json'):
            control = args.merge_from / name
            current = args.directory / name
            if control.exists():
                incoming_control = json.loads(control.read_text())
                existing = json.loads(current.read_text()) if current.exists() else {}
                merged = dict(incoming_control if incoming_control.get('retry_after', '') > existing.get('retry_after', '') else existing)
                if name == 'control.json' and ('capture_interval' in incoming_control or 'capture_interval' in existing):
                    old_pacing = existing.get('pacing_updated_at', '')
                    new_pacing = incoming_control.get('pacing_updated_at', '')
                    if old_pacing != new_pacing:
                        latest = incoming_control if new_pacing > old_pacing else existing
                        merged['capture_interval'] = max(CAPTURE_INTERVAL, latest.get('capture_interval', CAPTURE_INTERVAL))
                        merged['pacing_updated_at'] = latest['pacing_updated_at']
                    else:
                        merged['capture_interval'] = max(CAPTURE_INTERVAL, incoming_control.get('capture_interval', CAPTURE_INTERVAL),
                                                         existing.get('capture_interval', CAPTURE_INTERVAL))
                if merged != existing:
                    current.write_text(json.dumps(merged) + '\n')
        sources = args.merge_from / 'sources.json'
        if sources.exists():
            from archive_sources import save, repository_source
            current = args.directory / 'sources.json'
            merged = json.loads(current.read_text()) if current.exists() else {'version': 1, 'repositories': {}}
            for key, row in json.loads(sources.read_text())['repositories'].items():
                if repository_source(key) and row.get('checked_at', '') >= merged['repositories'].get(key, {}).get('checked_at', ''):
                    merged['repositories'][key] = row
            merged['repositories'] = {k: r for k, r in merged['repositories'].items() if repository_source(k)}
            save(current, merged)
        return 0
    targets = inventory(args.min_year)
    resumed = set()
    # Resume pending captures even when the source revision has changed.
    for key, row in rows.items():
        if key not in targets and (row.get('job_id') or row.get('candidate') or row.get('lookup_required')) and row.get('parent') in targets:
            cves = sorted(set(row.get('cves', [])) & set(targets[row['parent']]['cves']))
            if cves:
                targets[key] = {k: v for k, v in row.items() if k in
                    {'original', 'priority', 'parent', 'parent_original', 'parents', 'expected_blobs', 'strict_blobs'}}
                targets[key]['cves'] = cves
                resumed.add(key)
    if args.stats:
        allowed = {identity(row['url']) for row in eligible_ledger(args.min_year)}
        published = published_snapshots(rows, allowed)
        verified = [row for row in rows.values() if valid_snapshot(row)
                    and published.get(row['original'], {}).get('url') == row['snapshot']['url']]
        print(json.dumps({'min_year': args.min_year, 'targets': len(targets),
                          'original_urls': sum(not r.get('parent') for r in targets.values()),
                          'source_files': sum(bool(r.get('parent')) for r in targets.values()),
                          'processed': sum(k in rows for k in targets),
                          'snapshots': sum(valid_snapshot(rows.get(k, {})) for k in targets),
                          'verified_pages': sum(not r.get('parent') for r in verified),
                          'verified_files': sum(bool(r.get('parent')) for r in verified),
                          'states': dict(Counter(rows[k].get('status') for k in targets if k in rows))}, indent=2))
        return 0
    if args.url:
        keys = {identity(url) for url in args.url}
        targets = {key: value for key, value in targets.items() if key in keys}
        if keys - targets.keys():
            parser.error('Requested URL is not in the published-artifact inventory')
    if args.files_only:
        targets = {key: value for key, value in targets.items() if value.get('parent')}
    client = Client(*credentials())
    if args.lookup_pages:
        return lookup_pages(targets, rows, client, args.directory, args.limit, args.max_seconds)
    lookup_control = args.directory / 'lookup-control.json'
    if lookup_control.exists():
        client.lookup_retry_after = json.loads(lookup_control.read_text()).get('retry_after', '')
    replay_control = args.directory / 'replay-control.json'
    if replay_control.exists():
        client.replay_retry_after = json.loads(replay_control.read_text()).get('retry_after', '')
    if args.capture and not client.auth:
        parser.error('Authenticated captures require IA_ACCESS_KEY and IA_SECRET_KEY')
    submitted = max((row.get('submitted_at', '') for row in rows.values()), default='')
    if submitted:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(submitted.replace('Z', '+00:00'))).total_seconds()
        client.last_submit = time.monotonic() - max(0, elapsed)
    control = args.directory / 'control.json'
    state = {}
    if control.exists():
        state = json.loads(control.read_text())
        if state.get('retry_after', '') > now():
            print(f'Waiting for archive cooldown until {state["retry_after"]}', flush=True)
        client.interval = max(client.interval, state.get('capture_interval', CAPTURE_INTERVAL))
        since = max(state.get('retry_after', ''), state.get('pacing_updated_at', ''))
        healthy = sum(bool(r.get('parent')) and valid_snapshot(r) and r.get('status') == 'available'
                      and r.get('submitted_at', '') > since for r in rows.values())
        if args.capture and healthy >= 10 and client.interval > CAPTURE_INTERVAL:
            client.interval = max(CAPTURE_INTERVAL, client.interval - 15)
            state['pacing_updated_at'] = now()
        if args.capture and state.get('capture_interval') != client.interval:
            state['capture_interval'] = client.interval
            control.write_text(json.dumps(state) + '\n')
    slots = None if args.capture else 1
    capacity_checked = 0.0
    capacity_failures = 0
    selected = select_targets(targets, rows, capture=args.capture)
    start = time.monotonic()
    capture_deadline = start + args.max_seconds - min(120, args.max_seconds / 2)
    completed = 0
    last_was_new = False
    file_checks = 0
    last_pending = None
    while time.monotonic() - start < args.max_seconds:
        remaining = args.max_seconds - (time.monotonic() - start)
        if state.get('retry_after', '') > now():
            if state['retry_after'] >= after(remaining):
                print('Archive cooldown extends past this batch deadline', flush=True)
                break
            time.sleep(min(5, remaining))
            continue
        hosts = {parse.urlsplit(r['original']).hostname for r in rows.values() if r.get('host_retry_after', '') > now()}
        available = next((key for key in selected if parse.urlsplit(targets[key]['original']).hostname not in hosts), None)
        pending = [key for key in targets if rows.get(key, {}).get('job_id') or rows.get(key, {}).get('candidate')
                   or rows.get(key, {}).get('lookup_required')]
        can_submit = (completed < args.limit and time.monotonic() < capture_deadline
                      and (available is not None or any(k not in resumed
                           and (rows[k].get('lookup_required') or rows[k].get('job_id') and not active_job(rows[k]))
                           and parse.urlsplit(targets[k]['original']).hostname not in hosts for k in pending)))
        if args.capture and can_submit and (slots is None or time.monotonic() - capacity_checked >= client.interval):
            capacity_checked = time.monotonic()
            try:
                slots = client.capacity()
                capacity_failures = 0
            except ArchiveError as exc:
                slots = 0
                capacity_failures += 1
                if not exc.cooldown and not exc.fatal and capacity_failures < 3:
                    print(f'Archive capacity check deferred: {exc}', flush=True)
                    continue
                args.directory.mkdir(parents=True, exist_ok=True)
                state.update(retry_after=after(exc.cooldown or 300), reason=str(exc), capture_interval=client.interval)
                control.write_text(json.dumps(state) + '\n')
                print(f'Archive service requested backoff: {exc}', flush=True)
                if exc.fatal:
                    return 1
                continue
        replay_blocked = client.replay_retry_after > now()
        due = [key for key in pending if (rows[key].get('next_check_at', '') <= now()
               or rows[key].get('job_id') and not active_job(rows[key]))
               and not (replay_blocked and rows[key].get('candidate'))]
        submit_wait = max(0, client.interval - (time.monotonic() - client.last_submit)) if client.last_submit else 0
        room = (bool(slots) and completed < args.limit
                and (not args.capture or time.monotonic() + submit_wait < capture_deadline))
        counted = False
        if due and (last_was_new or available is None or completed >= args.limit or not room or submit_wait > 0):
            if last_pending is not None and time.monotonic() - last_pending < PENDING_INTERVAL:
                time.sleep(min(remaining, PENDING_INTERVAL - (time.monotonic() - last_pending)))
                continue
            key = min(due, key=lambda k: (
                not (active_job(rows[k]) and (not room or rows[k]['submitted_at'] < after(-3000))),
                bool(targets[k].get('parent')) if file_checks >= 4 else not bool(targets[k].get('parent')),
                not active_job(rows[k]),
                rows[k].get('next_check_at', '')))
            last_pending = time.monotonic()
            file_checks = file_checks + 1 if targets[key].get('parent') else 0
            last_was_new = False
        elif available is not None and completed < args.limit and room:
            key = available
            selected.remove(key)
            completed += 1
            counted = True
            last_was_new = True
        elif pending:
            if ((available is None or completed >= args.limit or time.monotonic() >= capture_deadline)
                    and all(max(rows[k].get('next_check_at', ''), client.replay_retry_after if rows[k].get('candidate') else '')
                            > after(remaining) for k in pending)):
                break
            time.sleep(5)
            continue
        elif available is not None and completed < args.limit and time.monotonic() < capture_deadline:
            time.sleep(5)
            continue
        elif selected and hosts and completed < args.limit and room:
            time.sleep(5)
            continue
        else:
            break
        attempts = rows.get(key, {}).get('attempts', 0)
        submitted = client.last_submit
        try:
            allow_submit = room and key not in resumed and parse.urlsplit(targets[key]['original']).hostname not in hosts
            process(key, targets[key], rows, client, capture=args.capture, directory=args.directory, allow_submit=allow_submit)
            if rows[key].get('status') == 'queued' and key not in selected and key not in resumed:
                selected.insert(0, key)
        except ArchiveError as exc:
            exc = client.failure(key, exc)
            rows[key]['error'] = str(exc)
            rows[key]['status'] = 'retry'
            if exc.fatal:
                print(f'Archive authentication failed: {exc}', flush=True)
                return 1
            if exc.cooldown:
                rows[key]['attempts'] = attempts
                rows[key]['next_check_at'] = (datetime.now(timezone.utc) + timedelta(seconds=exc.cooldown)).strftime('%Y-%m-%dT%H:%M:%SZ')
                save_records(rows, {key}, args.directory)
                if client.operation == 'availability':
                    client.lookup_retry_after = rows[key]['next_check_at']
                    lookup_control.write_text(json.dumps({'retry_after': client.lookup_retry_after, 'reason': str(exc)}) + '\n')
                    print(f'Archive lookups paused; capture jobs can continue: {exc}', flush=True)
                    continue
                if client.operation == 'replay' and str(exc) == 'service-transport-failures':
                    client.replay_retry_after = rows[key]['next_check_at']
                    replay_control.write_text(json.dumps({'retry_after': client.replay_retry_after, 'reason': str(exc)}) + '\n')
                    print(f'Archive verification paused; capture jobs can continue: {exc}', flush=True)
                    continue
                state.update(retry_after=rows[key]['next_check_at'], reason=str(exc), capture_interval=client.interval)
                if str(exc) == 'http-429' and client.operation == 'capture':
                    state['capture_interval'] = min(120, client.interval * 2)
                    state['pacing_updated_at'] = now()
                control.write_text(json.dumps(state) + '\n')
                client.interval = state['capture_interval']
                slots = None if args.capture else 1
                print(f'Archive service requested backoff during {client.operation}: {exc}', flush=True)
                continue
            if str(exc) in {'response-too-large', 'unsupported-response-encoding', 'invalid-compressed-response'}:
                rows[key].pop('candidate', None)
                rows[key].pop('verify_attempts', None)
                rows[key]['next_check_at'] = after(7 * 86400)
            else:
                rows[key]['next_check_at'] = max(rows[key].get('next_check_at', ''),
                    after(60 if rows[key].get('job_id') or rows[key].get('candidate') else 3600))
            print(f'Archive target deferred during {getattr(client, "operation", "replay")}: {exc}', flush=True)
        finally:
            if args.capture and client.last_submit != submitted:
                if slots is not None:
                    slots = max(0, slots - 1)
                if not counted:
                    completed += 1
            save_records(rows, {key}, args.directory)
        print(f'{completed}: {rows[key]["status"]} {targets[key]["original"]}', flush=True)
    print(json.dumps({'processed': completed, 'snapshots': sum(valid_snapshot(r) for r in rows.values())}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
