#!/usr/bin/env python3
"""Publish packaged bootstrap releases to the R2 bucket behind the UI hostname.

tools/package-bootstrap.py builds releases into a local directory. This tool
uploads them using the layout that ui/worker/index.ts serves:

    bootstrap.sh                 -> https://<origin>/bootstrap.sh (active loader)
    releases/<id>/<file>         -> https://<origin>/bootstrap/releases/<id>/<file>

Published release objects are immutable: an identical object is skipped and a
different one is refused. --activate switches the loader last, and only after
the whole release reads back intact, so the active loader always names a
complete release.

Activation only moves forward: the candidate's source commit must descend from
the active release's, so a slow publish of an older commit cannot replace a
newer loader. Rolling back is activating an older release ID with --rollback.
Runs sharing a --source directory are serialized with the packager's lock.

By default the bucket is reached with wrangler and its login or
CLOUDFLARE_API_TOKEN. With R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY and
CLOUDFLARE_ACCOUNT_ID set, it is reached through R2's S3 API instead. That is
the only way to use an R2 API token limited to one bucket, which wrangler
refuses: the access key ID is the token's ID and the secret is the SHA-256 of
its value. --check only reads the active loader, to check bucket access.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUCKET = 'controlcenter-bootstrap'
RELEASE_ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}')
# Upload order: the loader is last, so a release is never referenced by its own
# loader before its bundle exists.
RELEASE_FILES = {
    'runtime-bootstrap.tar.gz': 'application/gzip',
    'SHA256SUMS': 'text/plain; charset=utf-8',
    'release.json': 'application/json',
    'bootstrap.sh': 'text/x-shellscript',
}
MISSING = 'The specified key does not exist'
LOADER_RELEASE = re.compile(r'/bootstrap/releases/([a-zA-Z0-9][a-zA-Z0-9._-]{0,127})/runtime-bootstrap\.tar\.gz')
COMMIT = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?')


class PublishError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_release(source, release_id):
    """Read one local release and check that its files agree with each other."""
    if not RELEASE_ID.fullmatch(release_id) or '..' in release_id:
        raise PublishError('release ID must be a single safe path component: ' + release_id)
    directory = source / 'releases' / release_id
    if not directory.is_dir() or directory.is_symlink():
        raise PublishError('release not found: ' + str(directory))
    names = {path.name for path in directory.iterdir()}
    if names != set(RELEASE_FILES):
        raise PublishError(f'release {release_id} must contain exactly {sorted(RELEASE_FILES)}, found {sorted(names)}')
    files = {}
    for name in RELEASE_FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise PublishError(f'unsafe release file: {path}')
        files[name] = path.read_bytes()
    digest = sha256(files['runtime-bootstrap.tar.gz'])
    try:
        record = json.loads(files['release.json'])
    except ValueError as error:
        raise PublishError(f'release {release_id} has invalid release.json: {error}') from error
    loader = files['bootstrap.sh'].decode('utf-8', 'replace')
    checks = [
        files['SHA256SUMS'] == f'{digest}  runtime-bootstrap.tar.gz\n'.encode(),
        record.get('release_id') == release_id,
        record.get('bundle_sha256') == digest,
        record.get('loader_sha256') == sha256(files['bootstrap.sh']),
        f'/bootstrap/releases/{release_id}/runtime-bootstrap.tar.gz' in loader,
        digest in loader,
    ]
    if not all(checks):
        raise PublishError(f'release {release_id} is inconsistent; repackage it with tools/package-bootstrap.py')
    return files


class Bucket:
    def __init__(self, name, wrangler):
        self.name, self.wrangler = name, wrangler

    def run(self, *args):
        result = subprocess.run([*self.wrangler, 'r2', 'object', *args, '--env-file', os.devnull, '--remote'],
                                cwd=ROOT / 'ui', capture_output=True, text=True,
                                env={**os.environ, 'WRANGLER_SEND_METRICS': 'false'})
        return result.returncode, result.stdout + result.stderr

    def get(self, key):
        with tempfile.TemporaryDirectory(prefix='publish-bootstrap-') as temporary:
            target = Path(temporary) / 'object'
            code, output = self.run('get', f'{self.name}/{key}', '--file', str(target))
            if code != 0:
                if MISSING in output:
                    return None
                raise PublishError(f'could not read {key} from {self.name}:\n{output.strip()}')
            return target.read_bytes()

    def put(self, key, data, content_type, cache_control):
        with tempfile.TemporaryDirectory(prefix='publish-bootstrap-') as temporary:
            source = Path(temporary) / 'object'
            source.write_bytes(data)
            code, output = self.run('put', f'{self.name}/{key}', '--file', str(source),
                                    '--content-type', content_type, '--cache-control', cache_control)
            if code != 0:
                raise PublishError(f'could not write {key} to {self.name}:\n{output.strip()}')
        if self.get(key) != data:
            raise PublishError(f'{key} did not read back intact from {self.name}')


def signature_v4(secret, method, path, headers, amz_date, region='auto', service='s3'):
    """AWS Signature Version 4 over the given (lowercase) headers, without a query string."""
    signed = ';'.join(sorted(headers))
    canonical = '\n'.join([method, path, '', *(f'{name}:{headers[name].strip()}' for name in sorted(headers)), '',
                           signed, headers['x-amz-content-sha256']])
    scope = f'{amz_date[:8]}/{region}/{service}/aws4_request'
    key = ('AWS4' + secret).encode()
    for part in scope.split('/'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope, sha256(canonical.encode())])
    return scope, signed, hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()


class S3Bucket:
    """The bucket through R2's S3 API, with the interface of Bucket."""

    def __init__(self, name, account, key_id, secret, opener=None):
        self.name, self.key_id, self.secret = name, key_id, secret
        self.host = f'{account}.r2.cloudflarestorage.com'
        self.opener = opener or build_opener()

    def request(self, method, key, data=b'', headers=None):
        amz_date = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        path = '/' + quote(f'{self.name}/{key}', safe='/-_.~')
        signed_headers = {'host': self.host, 'x-amz-content-sha256': sha256(data), 'x-amz-date': amz_date,
                          **{name.lower(): value for name, value in (headers or {}).items()}}
        scope, signed, signature = signature_v4(self.secret, method, path, signed_headers, amz_date)
        request = Request(f'https://{self.host}{path}', data=data if method == 'PUT' else None, method=method)
        for name, value in signed_headers.items():
            if name != 'host':
                request.add_header(name, value)
        request.add_header('Authorization', f'AWS4-HMAC-SHA256 Credential={self.key_id}/{scope}, '
                                            f'SignedHeaders={signed}, Signature={signature}')
        request.add_header('User-Agent', 'controlcenter-publish-bootstrap/1.0')
        try:
            with self.opener.open(request, timeout=120) as response:
                return response.status, response.read()
        except HTTPError as error:
            with error:
                return error.code, error.read(4096)
        except (URLError, OSError) as error:
            raise PublishError(f'could not reach R2 for {key} in {self.name}: {error}') from None

    def get(self, key):
        status, body = self.request('GET', key)
        if status == 404:
            return None
        if status != 200:
            raise PublishError(f'could not read {key} from {self.name}: HTTP {status} '
                               + body.decode('utf-8', 'replace').strip()[:300])
        return body

    def put(self, key, data, content_type, cache_control):
        status, body = self.request('PUT', key, data, {'Content-Type': content_type, 'Cache-Control': cache_control})
        if status != 200:
            raise PublishError(f'could not write {key} to {self.name}: HTTP {status} '
                               + body.decode('utf-8', 'replace').strip()[:300])
        if self.get(key) != data:
            raise PublishError(f'{key} did not read back intact from {self.name}')


def open_bucket(name, wrangler):
    """Bucket through R2's S3 API when R2_ACCESS_KEY_ID is set, otherwise through wrangler."""
    key_id = os.environ.get('R2_ACCESS_KEY_ID', '')
    if not key_id:
        return Bucket(name, [wrangler])
    secret, account = os.environ.get('R2_SECRET_ACCESS_KEY', ''), os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
    if not (re.fullmatch(r'[A-Za-z0-9]{16,128}', key_id) and re.fullmatch(r'[A-Za-z0-9]{32,128}', secret)
            and re.fullmatch(r'[0-9a-f]{32}', account)):
        raise PublishError('R2_ACCESS_KEY_ID needs R2_SECRET_ACCESS_KEY and CLOUDFLARE_ACCOUNT_ID (the 32-character account ID)')
    return S3Bucket(name, account, key_id, secret)


def publish(bucket, release_id, files, log):
    for name, content_type in RELEASE_FILES.items():
        key = f'releases/{release_id}/{name}'
        remote = bucket.get(key)
        if remote == files[name]:
            log(f'unchanged {key}')
            continue
        if remote is not None:
            raise PublishError(f'{key} is already published with different content; release IDs are immutable')
        bucket.put(key, files[name], content_type, 'public, max-age=31536000, immutable')
        log(f'uploaded {key}')


def source_commit(raw, release_id):
    try:
        commit = json.loads(raw)['source_commit']
    except (TypeError, ValueError, KeyError) as error:
        raise PublishError(f'release {release_id} has no readable release.json source_commit') from error
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise PublishError(f'release {release_id} has an invalid source_commit')
    return commit


def check_forward(bucket, release_id, files, repository):
    """Refuse to replace the active loader with a release that is not newer."""
    loader = bucket.get('bootstrap.sh')
    if loader is None:
        return
    named = set(LOADER_RELEASE.findall(loader.decode('utf-8', 'replace')))
    if len(named) != 1:
        raise PublishError('the active bootstrap.sh does not name exactly one release; pass --rollback to replace it')
    active = named.pop()
    if active == release_id:
        return
    hint = '; pass --rollback to activate it anyway'
    try:
        active_commit = source_commit(bucket.get(f'releases/{active}/release.json'), active)
        commit = source_commit(files['release.json'], release_id)
    except PublishError as error:
        raise PublishError(f'cannot order against the active release {active}: {error}{hint}') from error
    result = subprocess.run(['git', '-C', str(repository), 'merge-base', '--is-ancestor', active_commit, commit],
                            capture_output=True, text=True)
    if result.returncode == 1:
        raise PublishError(f'release {release_id} ({commit[:12]}) is not newer than the active release '
                           f'{active} ({active_commit[:12]}){hint}')
    if result.returncode != 0:
        raise PublishError(f'cannot order release {release_id} against the active release {active} in '
                           f'{repository}: {result.stderr.strip()}; fetch its history{hint}')


def activate(bucket, release_id, files, log, repository=ROOT, rollback=False):
    for name in RELEASE_FILES:
        if bucket.get(f'releases/{release_id}/{name}') != files[name]:
            raise PublishError(f'release {release_id} is not completely published; publish it before activating')
    if not rollback:
        check_forward(bucket, release_id, files, repository)
    bucket.put('bootstrap.sh', files['bootstrap.sh'], RELEASE_FILES['bootstrap.sh'], 'no-cache')
    log(f'activated {release_id} as bootstrap.sh' + (' (rollback)' if rollback else ''))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', type=Path, default=ROOT / 'deploy/bootstrap', help='package-bootstrap.py --output directory')
    parser.add_argument('--bucket', default=DEFAULT_BUCKET)
    parser.add_argument('--release-id', action='append', default=[], help='release to publish; repeatable')
    parser.add_argument('--all', action='store_true', help='publish every local release (for migrating an existing host)')
    parser.add_argument('--activate', metavar='RELEASE_ID', help='switch the active loader to this published release, last')
    parser.add_argument('--rollback', action='store_true', help='let --activate select a release that is not newer than the active one')
    parser.add_argument('--check', action='store_true', help='only read the active loader, to check bucket access')
    parser.add_argument('--repository', type=Path, default=ROOT, help='Git checkout used to order releases by source commit')
    parser.add_argument('--wrangler', default=os.environ.get('WRANGLER', str(ROOT / 'ui/node_modules/.bin/wrangler')),
                        help='wrangler executable (default: $WRANGLER or ui/node_modules/.bin/wrangler)')
    args = parser.parse_args(argv)
    releases = list(args.release_id)
    if args.all:
        root = args.source / 'releases'
        releases += sorted(path.name for path in root.iterdir() if path.is_dir() and not path.name.startswith('.')) if root.is_dir() else []
    if args.check and (releases or args.activate or args.rollback):
        parser.error('--check only reads; pass it alone')
    if not releases and not args.activate and not args.check:
        parser.error('nothing to do: pass --release-id, --all, --activate or --check')
    log = lambda message: print(message, file=sys.stderr)
    if args.rollback and not args.activate:
        parser.error('--rollback requires --activate')
    try:
        bucket = open_bucket(args.bucket, args.wrangler)
        if args.check:
            if bucket.get('bootstrap.sh') is None:
                raise PublishError(f'{args.bucket} has no active bootstrap.sh')
            log(f'read the active bootstrap.sh from {args.bucket}')
            return
        with (args.source / '.publish.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            loaded = {release_id: load_release(args.source, release_id) for release_id in dict.fromkeys(releases)}
            if args.activate and args.activate not in loaded:
                loaded[args.activate] = load_release(args.source, args.activate)
            for release_id in dict.fromkeys(releases):
                publish(bucket, release_id, loaded[release_id], log)
            if args.activate:
                activate(bucket, args.activate, loaded[args.activate], log, args.repository, args.rollback)
    except (PublishError, OSError) as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
