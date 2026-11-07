#!/usr/bin/env python3
"""Capture Runtime source and run its checked-in tests over synchronous SSH."""
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
from subprocess import Popen
import sys
import tarfile
import uuid


INSTALL_DIRS = {
    'bin', 'download', 'runtimes', 'credentials', 'state', 'systemd',
    'k3s', 'kubelet', 'volumes', 'logs', 'build', 'dist', 'test-results', 'htmlcov',
}
EXCLUDED_DIRS = {
    '.git', 'secrets', '.venv', 'venv', 'node_modules', '__pycache__',
    '.pytest_cache', '.mypy_cache', '.ruff_cache',
}
OUTCOMES = {'passed', 'test_failed', 'setup_failed', 'cleanup_failed'}

# All arguments are passed to bash through shlex.join, never substituted here.
PREPARE = r'''
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'Remote host must run Linux' >&2; exit 1; }
for tool in bash tar gzip sha256sum mktemp cat rm; do
  command -v "$tool" >/dev/null || { echo "Missing remote tool: $tool" >&2; exit 1; }
done
umask 077
mktemp -d "/tmp/livepeer-runtime-$1.XXXXXXXXXX"
'''
EXECUTE = r'''
set -euo pipefail
dir=$1 digest=$2 run_id=$3 container=$4
cd -- "$dir"
cat > source.tar.gz
printf '%s  source.tar.gz\n' "$digest" | sha256sum --check --status || {
  echo 'Uploaded source checksum mismatch' >&2; exit 1;
}
tar -xzf source.tar.gz
: > runner.started
set +e
LIVEPEER_TEST_STATE_DIR="$dir" LIVEPEER_TEST_RUN_ID="$run_id" \
  LIVEPEER_TEST_CONTAINER_NAME="$container" bash runtime/tests/run.sh 2>&1
code=$?
set -e
test_code=null outcome=setup_failed image=-
if [[ -f runner.result ]]; then
  read -r test_code outcome image < runner.result
fi
printf '%s\n' "$code" > runner.finished
printf '\nREMOTE_TEST_RESULT %s %s %s %s %s\n' "$run_id" "$code" "$test_code" "$outcome" "$image"
'''
CLEANUP = r'''
set -euo pipefail
dir=$1 run_id=$2 execution_pending=${3:-1}
[[ $dir == /tmp/livepeer-runtime-"$run_id".* && ! -L $dir ]] || exit 1
[[ -d $dir ]] || exit 0
cd -- "$dir"
if [[ -f container.cid ]]; then
  cid=$(cat container.cid)
  [[ $cid =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid container ID; retaining source' >&2; exit 1; }
  if owner=$(docker inspect --format '{{index .Config.Labels "livepeer.runtime-test"}}' "$cid" 2>/dev/null); then
    [[ $owner == "$run_id" ]] || { echo 'Container ownership mismatch' >&2; exit 1; }
    docker rm -f "$cid" >/dev/null 2>&1 || true
  fi
  present=$(docker container ls -aq --no-trunc --filter "id=$cid")
  [[ -z $present ]] || { echo 'Container still present; retaining source' >&2; exit 1; }
  # Give the attached runner time to reap the removed container and finish.
  for _ in {1..50}; do
    [[ ! -f runner.started || -f runner.finished ]] && break
    sleep .1
  done
fi
if [[ ! -f runner.finished && ( $execution_pending == 1 || -f runner.started ) ]]; then
  echo 'Runner completion unknown; retaining source directory' >&2
  exit 1
fi
cd /
rm -rf -- "$dir"
'''


class RunError(Exception):
    pass


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True)
    if result.returncode:
        raise RunError(result.stderr.decode(errors='replace').strip())
    return result.stdout


def excluded(path):
    parts = PurePosixPath(path).parts[1:]  # Drop runtime/.
    return (
        not parts or parts[0] in INSTALL_DIRS
        or any(p in EXCLUDED_DIRS for p in parts)
        or any(p == '.env' or p.startswith('.env.') for p in parts)
        or parts[-1].endswith(('.pyc', '.pyo')) or parts[-1] == '.coverage'
        or parts == ('config', 'kubeconfig.yaml')
    )


def capture(root, ref, target):
    """Return source identity after closing a regular-files-only Runtime archive."""
    revision = git(root, 'rev-parse', '--verify', '--end-of-options',
                   (ref or 'HEAD') + '^{commit}').decode().strip()
    tracked = {}
    if ref:
        for entry in git(root, 'ls-tree', '-rz', '--full-tree', revision, '--', 'runtime/').split(b'\0'):
            if entry:
                meta, name = entry.split(b'\t', 1)
                mode, kind, oid = meta.decode().split()
                tracked[os.fsdecode(name)] = (mode, oid)
        names = set(tracked)
    else:
        for entry in git(root, 'ls-files', '--stage', '-z', '--', 'runtime/').split(b'\0'):
            if entry:
                meta, name = entry.split(b'\t', 1)
                mode, oid, stage = meta.decode().split()
                if stage != '0':
                    raise RunError('Resolve the Git conflict before capture: ' + os.fsdecode(name))
                tracked[os.fsdecode(name)] = (mode, oid)
        names = set(tracked) | {
            os.fsdecode(name) for name in
            git(root, 'ls-files', '--others', '--exclude-standard', '-z', '--', 'runtime/').split(b'\0')
            if name
        }
    selected = set()
    with target.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as archive:
            for name in sorted(names):
                if excluded(name):
                    if name in tracked:
                        raise RunError('Forbidden tracked path; remove it from the source or revise the policy: ' + name)
                    continue
                mode, oid = tracked.get(name, ('100644', None))
                if mode not in ('100644', '100755'):
                    raise RunError('Symlinks and submodules are unsupported: ' + name)
                if ref:
                    data = git(root, 'cat-file', 'blob', oid)
                    executable = mode == '100755'
                else:
                    path = root / name
                    if any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
                        raise RunError('Symlinked source directories are unsupported: ' + name)
                    try:
                        info = path.lstat()
                    except FileNotFoundError:
                        if name in tracked:
                            continue  # A working-tree deletion, not a failed read.
                        raise RunError('Untracked file disappeared before capture: ' + name)
                    if not stat.S_ISREG(info.st_mode):
                        raise RunError('Only regular files are supported (no symlinks): ' + name)
                    # Do not follow a link substituted between lstat and open.
                    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                    with os.fdopen(fd, 'rb') as source:
                        info = os.fstat(source.fileno())
                        if not stat.S_ISREG(info.st_mode):
                            raise RunError('Only regular files are supported: ' + name)
                        data = source.read()
                    executable = bool(info.st_mode & 0o111)
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755 if executable else 0o644
                archive.addfile(entry, io.BytesIO(data))
                selected.add(name)
    if 'runtime/tests/run.sh' not in selected:
        raise RunError('Snapshot must contain runtime/tests/run.sh; REF must name a supported combined-repository commit')
    digest = hashlib.sha256()
    with target.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return {'mode': 'commit' if ref else 'working-tree', 'revision': revision,
            'sha256': digest.hexdigest()}


def ssh_command(remote, script, *args):
    if not remote or remote.startswith('-') or any(c.isspace() or c == '\0' for c in remote):
        raise RunError('REMOTE must be an SSH destination (for example livepeer-t4), not an option')
    return ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '--', remote,
            shlex.join(['bash', '-c', script, 'runtime-test', *args])]


def parse_result(line, run_id):
    fields = line.decode(errors='replace').strip().split()
    if len(fields) != 6 or fields[:2] != ['REMOTE_TEST_RESULT', run_id]:
        return None
    _, _, code, test_code, outcome, image = fields
    if not code.isdigit() or not 0 <= int(code) <= 255 or outcome not in OUTCOMES:
        return None
    if test_code != 'null' and (not test_code.isdigit() or not 0 <= int(test_code) <= 255):
        return None
    if image != '-' and not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        return None
    return int(code), None if test_code == 'null' else int(test_code), outcome, None if image == '-' else image


def run(root, remote, ref=''):
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12]
    results = root / '.remote-test-results' / run_id
    results.mkdir(parents=True, mode=0o700)
    record = dict(run_id=run_id, source={'mode': 'commit' if ref else 'working-tree', 'revision': None, 'sha256': None},
                  remote=remote, remote_directory=None,
                  container='livepeer-runtime-' + run_id, started_at=utc_now(), finished_at=None,
                  image=None, test_exit_code=None, outcome='setup_failed', cleanup='not_needed', exit_status=1)
    process = None
    execution_pending = False
    log = (results / 'test.log').open('wb')
    console = sys.stdout

    def emit(data):
        nonlocal console
        if isinstance(data, str):
            data = (data + '\n').encode()
        log.write(data)
        log.flush()
        if console is not None:
            try:
                print(data.decode(errors='replace'), end='', flush=True, file=console)
            except BrokenPipeError:
                # Avoid another broken-pipe flush during interpreter shutdown.
                try:
                    with open(os.devnull, 'w') as sink:
                        os.dup2(sink.fileno(), console.fileno())
                except (AttributeError, OSError):
                    pass
                console = None

    def save():
        temp = results / 'result.json.tmp'
        temp.write_text(json.dumps(record, indent=2) + '\n')
        temp.replace(results / 'result.json')

    save()
    emit('Run: ' + run_id + '\nResults: ' + str(results))
    try:
        prepare_command = ssh_command(remote, PREPARE, run_id)
        archive = results / 'source.tar.gz'
        partial = results / 'source.tar.gz.partial'
        try:
            record['source'] = capture(root, ref, partial)
            partial.replace(archive)
        finally:
            partial.unlink(missing_ok=True)
        emit('Capture complete: SHA-256 ' + record['source']['sha256'])
        save()
        emit('Possible remote directory after allocation: /tmp/livepeer-runtime-' + run_id + '.*')
        prepared = subprocess.run(prepare_command, capture_output=True)
        emit(prepared.stderr)
        if prepared.returncode:
            record['outcome'] = 'transport_failed' if prepared.returncode == 255 else 'setup_failed'
            raise RunError('Remote preflight/allocation failed; possible resource prefix: /tmp/livepeer-runtime-' + run_id + '.')
        directory = prepared.stdout.decode().strip()
        if not re.fullmatch(r'/tmp/livepeer-runtime-' + re.escape(run_id) + r'\.[A-Za-z0-9]+', directory):
            raise RunError('Unexpected remote temporary-directory response: ' + repr(directory))
        record['remote_directory'] = directory
        emit('Remote directory: ' + directory + '\nContainer: ' + record['container'])
        save()
        received = None
        with archive.open('rb') as source:
            execution_pending = True
            process = Popen(
                ssh_command(remote, EXECUTE, directory, record['source']['sha256'], run_id, record['container']),
                stdin=source, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            for line in process.stdout:
                emit(line)
                image_record = re.fullmatch(r'REMOTE_TEST_IMAGE ' + re.escape(run_id)
                                            + r' (sha256:[a-f0-9]{64})\s*', line.decode(errors='replace'))
                if image_record:
                    record['image'] = image_record.group(1)
                parsed = parse_result(line, run_id)
                if parsed is not None:
                    received = parsed
            transport_code = process.wait()
            execution_pending = not 0 <= transport_code < 255
        if received is not None:
            code, test_code, outcome, image = received
            record.update(test_exit_code=test_code, outcome=outcome,
                          exit_status=code or int(outcome != 'passed' or test_code != 0))
            if image:
                record['image'] = image
        if transport_code or received is None:
            record['outcome'] = 'transport_failed' if transport_code == 255 or received is not None else 'setup_failed'
            record['exit_status'] = record['test_exit_code'] or 1
            if received is not None:
                raise RunError('Remote test result was received, but SSH subsequently failed')
            raise RunError('SSH failed or no confirmed remote completion was received; test outcome may be unknown')
    except KeyboardInterrupt:
        record.update(outcome='interrupted', exit_status=130)
        emit('Interrupted; attempting cleanup without assuming the remote runner stopped.')
    except (RunError, OSError, subprocess.SubprocessError) as error:
        record['error'] = str(error)
        emit('Error: ' + str(error))
    finally:
        directory = record['remote_directory']
        if directory:
            try:
                cleaned = subprocess.run(ssh_command(remote, CLEANUP, directory, run_id, str(int(execution_pending))),
                                         capture_output=True, timeout=30)
                emit(cleaned.stdout)
                emit(cleaned.stderr)
                if cleaned.returncode:
                    raise RunError('Remote cleanup did not complete')
                record['cleanup'] = 'ok'
            except KeyboardInterrupt:
                record['cleanup'] = 'incomplete'
                if record['exit_status'] == 0:
                    record.update(outcome='interrupted', exit_status=130)
                emit('Interrupted during cleanup; inspect remote directory ' + directory
                     + ' and container ' + record['container'] + ' before manual removal. See README.')
            except (RunError, OSError, subprocess.SubprocessError) as error:
                record['cleanup'] = 'incomplete'
                if record['exit_status'] == 0:
                    record.update(exit_status=1, outcome='cleanup_failed')
                emit('Cleanup incomplete: ' + str(error))
                emit('Inspect remote directory ' + directory + ' and container ' + record['container']
                     + '; stop this run and confirm its runner finished before removing source. See README.')
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
        record['finished_at'] = utc_now()
        save()
        emit('Outcome: ' + record['outcome'] + '; helper exit status: ' + str(record['exit_status']))
        log.close()
    return record['exit_status']


if __name__ == '__main__':
    if sys.version_info < (3, 10):
        sys.exit('Python 3.10+ is required')
    sys.exit(run(Path(__file__).resolve().parents[1], os.environ.get('REMOTE', ''), os.environ.get('REF', '')))
