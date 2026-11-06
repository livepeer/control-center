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

