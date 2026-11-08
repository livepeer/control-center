"""Bounded configuration archive validation and atomic file writes."""
import gzip
import hashlib
import io
import os
import pathlib
import tarfile

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_CONTENT = 64 * 1024 * 1024
MAX_FILES = 2048


def atomic_write(path, data, mode=0o600):
    path = pathlib.Path(path)
    temp = path.with_name(path.name + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp, mode)
    os.replace(temp, path)


def validate_archive(data):
    if not data or len(data) > MAX_ARCHIVE or not data.startswith(b'\x1f\x8b'):
        raise ValueError('expected a gzip archive no larger than 16 MiB')
    # Bound decompression as well as compressed size before tarfile parses it.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        content = stream.read(MAX_CONTENT + 1)
    if len(content) > MAX_CONTENT:
        raise ValueError('archive expands beyond 64 MiB')
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:') as archive:
        for count, entry in enumerate(archive, 1):
            name = pathlib.PurePosixPath(entry.name)
            if (count > MAX_FILES or not entry.isfile() or name.is_absolute() or
                    '..' in name.parts or '\\' in entry.name or not name.parts or
                    str(name) != entry.name or entry.name in names):
                raise ValueError('archive must contain unique, relative regular files only')
            total += entry.size
            if total > MAX_CONTENT:
                raise ValueError('archive content exceeds limit')
            names.add(entry.name)
            if len(archive.extractfile(entry).read(entry.size + 1)) != entry.size:
                raise ValueError('truncated archive member')
    if not names.intersection({'kustomization.yaml', 'kustomization.yml', 'Kustomization'}):
        raise ValueError('archive needs a root Kustomize configuration')
    return 'sha256:' + hashlib.sha256(data).hexdigest()



def strict_json(data):
    import json
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('non-JSON number')
    return json.loads(data, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def validate_app_assignments(archive, desired, previous=None):
    """Validate delivery identity only; shared Go schema owns app semantics."""
    import re
    generation = desired.get('apps_generation', 0)
    digest = desired.get('apps_digest', '')
    if type(generation) is not int or not 0 <= generation <= (1 << 63) - 1:
        raise ValueError('invalid app-set generation')
    try:
        member = archive.getmember('app-assignments.json')
    except KeyError:
        member = None
    if generation == 0:
        if member is not None or digest:
            raise ValueError('unexpected app assignment metadata')
    else:
        if member is None or member.size > 900 * 1024 or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('missing or oversized app assignment manifest')
        manifest = strict_json(archive.extractfile(member).read())
        if (manifest.get('apiVersion') != 'v1' or manifest.get('kind') != 'ConfigMap' or
                manifest.get('metadata', {}).get('name') != 'livepeer-app-assignments' or
                manifest['metadata'].get('namespace') != 'livepeer' or
                manifest['metadata'].get('annotations', {}).get('livepeer.io/apps-sha256') != digest or
                set(manifest.get('data', {})) != {'desired.json'}):
            raise ValueError('invalid app assignment ConfigMap')
        raw = manifest['data']['desired.json'].encode('utf-8')
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('app assignment digest mismatch')
        data = strict_json(raw)
        if (type(data.get('schema_version')) is not int or data['schema_version'] != 1 or data.get('node_id') != desired['node_id'] or
                data.get('epoch') != desired['epoch'] or type(data.get('apps_generation')) is not int or
                data['apps_generation'] != generation or not isinstance(data.get('entries'), list) or
                len(data['entries']) > 100):
            raise ValueError('app assignment enrollment/version mismatch')
    if previous is not None:
        old = previous.get('apps_generation', 0)
        if old > generation or (old == generation and previous.get('apps_digest', '') != digest):
            raise ValueError('stale or conflicting app assignment generation')
