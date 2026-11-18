#!/usr/bin/env python3
"""Publish packaged bootstrap releases to the R2 bucket behind the UI hostname.

tools/package-bootstrap.py builds releases into a local directory. This tool
uploads them with wrangler, using the layout that ui/worker/index.ts serves:

    bootstrap.sh                 -> https://<origin>/bootstrap.sh (active loader)
    releases/<id>/<file>         -> https://<origin>/bootstrap/releases/<id>/<file>

Published release objects are immutable: an identical object is skipped and a
different one is refused. --activate switches the loader last, and only after
the whole release reads back intact, so the active loader always names a
complete release. Rolling back is activating an older release ID.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


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
        result = subprocess.run([*self.wrangler, 'r2', 'object', *args, '--remote'],
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


def activate(bucket, release_id, files, log):
    for name in RELEASE_FILES:
        if bucket.get(f'releases/{release_id}/{name}') != files[name]:
            raise PublishError(f'release {release_id} is not completely published; publish it before activating')
    bucket.put('bootstrap.sh', files['bootstrap.sh'], RELEASE_FILES['bootstrap.sh'], 'no-cache')
    log(f'activated {release_id} as bootstrap.sh')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', type=Path, default=ROOT / 'deploy/bootstrap', help='package-bootstrap.py --output directory')
    parser.add_argument('--bucket', default=DEFAULT_BUCKET)
    parser.add_argument('--release-id', action='append', default=[], help='release to publish; repeatable')
    parser.add_argument('--all', action='store_true', help='publish every local release (for migrating an existing host)')
    parser.add_argument('--activate', metavar='RELEASE_ID', help='switch the active loader to this published release, last')
    parser.add_argument('--wrangler', default=os.environ.get('WRANGLER', str(ROOT / 'ui/node_modules/.bin/wrangler')),
                        help='wrangler executable (default: $WRANGLER or ui/node_modules/.bin/wrangler)')
    args = parser.parse_args(argv)
    releases = list(args.release_id)
    if args.all:
        root = args.source / 'releases'
        releases += sorted(path.name for path in root.iterdir() if path.is_dir() and not path.name.startswith('.')) if root.is_dir() else []
    if not releases and not args.activate:
        parser.error('nothing to do: pass --release-id, --all or --activate')
    bucket = Bucket(args.bucket, [args.wrangler])
    log = lambda message: print(message, file=sys.stderr)
    try:
        loaded = {release_id: load_release(args.source, release_id) for release_id in dict.fromkeys(releases)}
        if args.activate and args.activate not in loaded:
            loaded[args.activate] = load_release(args.source, args.activate)
        for release_id in dict.fromkeys(releases):
            publish(bucket, release_id, loaded[release_id], log)
        if args.activate:
            activate(bucket, args.activate, loaded[args.activate], log)
    except (PublishError, OSError) as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
