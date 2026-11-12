#!/usr/bin/env python3
"""Package a complete bootstrap release; optionally activate its retained loader."""
import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORIGIN = 'https://controlcenter.livepeer.live'
IMAGE_PATTERN = r'[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}'


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()


def activate(output, release_id):
    """Switch only the loader; keep every published release available."""
    loader = output / 'releases' / release_id / 'bootstrap.sh'
    with tempfile.NamedTemporaryFile(dir=output, prefix='.loader-', delete=False) as target:
        temporary = Path(target.name)
        try:
            target.write(loader.read_bytes())
            target.flush()
            os.fsync(target.fileno())
            temporary.chmod(0o644)
            temporary.replace(output / 'bootstrap.sh')
        finally:
            temporary.unlink(missing_ok=True)


def package(root, output, release_id, origin, runtime_image, activate_loader=False):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]*', release_id):
        raise ValueError('release ID must be a single safe path component')
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or not re.fullmatch(r'https://[a-zA-Z0-9.-]+(?::[0-9]+)?/?', origin)):
        raise ValueError('public origin must be an HTTPS origin without credentials, query or fragment')
    if not re.fullmatch(IMAGE_PATTERN, runtime_image):
        raise ValueError('Runtime image must be pinned by sha256 digest')
    origin = origin.rstrip('/')
    # Only repository-approved assets are eligible; never sweep local credentials
    # or generated configuration into a public release.
    names = ['runtime/bootstrap-livepeer.sh'] + git(
        root, 'ls-files', '--', 'runtime/lib', 'runtime/config', 'runtime/manifests').splitlines()
    files = {}
    for name in names:
        path = root / name
        if (not re.fullmatch(r'runtime/[a-zA-Z0-9_./-]+', name) or path.is_symlink()
                or any(parent.is_symlink() for parent in path.parents if parent != root)
                or not path.is_file()):
            raise ValueError('missing or unsafe bootstrap asset: ' + name)
        files[name.removeprefix('runtime/')] = path.read_bytes()
    for directory in ('lib', 'config', 'manifests'):
        if not any(name.startswith(directory + '/') for name in files):
            raise ValueError('missing required asset directory: ' + directory)
    for name in ('lib/preflight.sh', 'lib/recovery.sh', 'lib/components.sh', 'lib/credentials.sh',
                 'manifests/bootstrap/kustomization.yaml', 'manifests/flux/kustomization.yaml',
                 'manifests/runtimeclass.yaml', 'manifests/gvisor-smoke.yaml'):
        if name not in files:
            raise ValueError('missing required bootstrap asset: ' + name)
    files['release-runtime-image'] = (runtime_image + '\n').encode()
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo('runtime/' + name)
                entry.mode, entry.size = 0o644, len(data)
                archive.addfile(entry, io.BytesIO(data))
    bundle = raw.getvalue()
    digest = hashlib.sha256(bundle).hexdigest()
    loader = (root / 'runtime/bootstrap.sh.in').read_text()
    for key, value in {
        '@BUNDLE_URL@': f'{origin}/bootstrap/releases/{release_id}/runtime-bootstrap.tar.gz',
        '@BUNDLE_SHA256@': digest,
        '@REQUIRED_FILES@': ' '.join(sorted(files)),
    }.items():
        loader = loader.replace(key, value)
    record = {
        'release_id': release_id, 'public_origin': origin,
        'runtime_image': runtime_image, 'bundle_sha256': digest,
        'source_commit': git(root, 'rev-parse', 'HEAD'),
        'source_dirty': bool(git(root, 'status', '--porcelain')),
        'loader_sha256': hashlib.sha256(loader.encode()).hexdigest(),
        'assets': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }
    image_record = root / 'deploy/staging-images.json'
    if image_record.exists():
        recorded = json.loads(image_record.read_text())
        if recorded.get('images', {}).get('RuntimeImage') == runtime_image:
            record['runtime_build_provenance'] = recorded
    output.mkdir(parents=True, exist_ok=True)
    releases = output / 'releases'
    releases.mkdir(exist_ok=True)
    # Serialize publication and activation so release IDs cannot be reused by
    # concurrent publishers, and the current loader always names a complete release.
    with (output / '.publish.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        release = releases / release_id
        if release.exists():
            raise ValueError('release already exists: ' + release_id)
        staging = Path(tempfile.mkdtemp(dir=releases, prefix='.staging-'))
        try:
            (staging / 'runtime-bootstrap.tar.gz').write_bytes(bundle)
            (staging / 'SHA256SUMS').write_text(digest + '  runtime-bootstrap.tar.gz\n')
            (staging / 'bootstrap.sh').write_text(loader)
            (staging / 'release.json').write_text(json.dumps(record, indent=2) + '\n')
            for path in staging.iterdir():
                path.chmod(0o644)
            staging.chmod(0o755)
            staging.rename(release)
            if activate_loader:
                activate(output, release_id)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--public-origin', default=DEFAULT_ORIGIN)
    parser.add_argument('--runtime-image', help='default: RuntimeImage in deploy/staging-images.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--activate', action='store_true', help='atomically switch the current loader last')
    args = parser.parse_args()
    try:
        image = args.runtime_image
        if image is None:
            image = json.loads((ROOT / 'deploy/staging-images.json').read_text())['images']['RuntimeImage']
        record = package(ROOT, args.output, args.release_id, args.public_origin, image, args.activate)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'error: {error}\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
