"""Host-safe release and POSIX-loader tests; never install Runtime."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('bootstrap_release', ROOT / 'tools/package-bootstrap.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
IMAGE = 'registry.example/runtime@sha256:' + 'd' * 64
TOKEN = 'header.payload.signature'
INSTALLER = r'''#!/bin/bash
set +ax
unset ENROLLMENT_TOKEN
FIXTURE_HAD_TOKEN=0
if [[ ${LIVEPEER_ENROLLMENT_TOKEN:-} == header.payload.signature ]]; then FIXTURE_HAD_TOKEN=1; fi
export FIXTURE_HAD_TOKEN
export FIXTURE_INSTALLER_DIR=${BASH_SOURCE[0]%/*}
unset LIVEPEER_ENROLLMENT_TOKEN
python3 - "$@" <<'PY'
import json, os, sys
from pathlib import Path
Path(os.environ['FIXTURE_RESULT']).write_text(json.dumps({
    'args': sys.argv[1:], 'token': os.environ['FIXTURE_HAD_TOKEN'],
    'api': os.environ.get('LIVEPEER_API_URL'), 'image': os.environ.get('LIVEPEER_RUNTIME_IMAGE'),
    'private': (Path(os.environ['FIXTURE_INSTALLER_DIR']).parent.stat().st_mode & 0o077) == 0,
}))
PY
if [[ -n ${FIXTURE_DESCENDANT_MODE:-} ]]; then
  helper='import os,signal,time; from pathlib import Path; signal.signal(signal.SIGTERM, signal.SIG_IGN) if os.environ.get("FIXTURE_IGNORE_TERM") else None; Path(os.environ["FIXTURE_HELPER"]).write_text(str(os.getpid())); time.sleep(2); Path(os.environ["FIXTURE_HELPER"]+".late").write_text("continued")'
  case "$FIXTURE_DESCENDANT_MODE" in
    foreground) python3 -c "$helper" ;;
    pipeline) python3 -c "$helper" | cat ;;
    subshell) captured=$(python3 -c "$helper") ;;
  esac
fi
if [[ ${FIXTURE_WAIT:-0} == 1 ]]; then
  trap '[[ -d ${BASH_SOURCE[0]%/*} ]] && printf stopped > "$FIXTURE_STOPPED"; exit 143' TERM
  while :; do sleep .05; done
fi
exit "${FIXTURE_EXIT:-0}"
'''


class BootstrapRelease(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        for directory in ('lib', 'config', 'manifests'):
            shutil.copytree(ROOT / 'runtime' / directory, self.source / 'runtime' / directory)
        shutil.copy(ROOT / 'runtime/bootstrap.sh.in', self.source / 'runtime/bootstrap.sh.in')
        (self.source / 'runtime/bootstrap-livepeer.sh').write_text(INSTALLER)
        for args in (('init', '-q'), ('config', 'user.name', 'Fixture'),
                     ('config', 'user.email', 'fixture@example.invalid'),
                     ('config', 'core.hooksPath', '/dev/null'), ('add', '.'),
                     ('-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')):
            subprocess.run(['git', '-C', str(self.source), *args], check=True, capture_output=True)
        self.output = self.root / 'published'
        self.record = release.package(self.source, self.output, 'v1', release.DEFAULT_ORIGIN, IMAGE, True)
        self.directory = self.output / 'releases/v1'
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ('LIVEPEER_ENROLLMENT_TOKEN', 'ENROLLMENT_TOKEN', 'SHELLOPTS', 'BASH_ENV')}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ['PATH'], TMPDIR=str(self.scratch),
                        FIXTURE_RESULT=str(self.root / 'result.json'), FIXTURE_STOPPED=str(self.root / 'stopped'),
                        FIXTURE_BUNDLE=str(self.directory / 'runtime-bootstrap.tar.gz'),
                        FIXTURE_LOADER=str(self.directory / 'bootstrap.sh'), FIXTURE_CURL=str(self.root / 'curl.json'))
        self.executable('curl', r'''import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
assert 'LIVEPEER_ENROLLMENT_TOKEN' not in os.environ
assert '_lp_token' not in os.environ
Path(os.environ['FIXTURE_CURL']).write_text(json.dumps(args))
if '--output' not in args:
    if os.environ.get('FIXTURE_FAIL') == 'loader': sys.exit(22)
    sys.stdout.buffer.write(Path(os.environ['FIXTURE_LOADER']).read_bytes())
elif os.environ.get('FIXTURE_FAIL') == 'bundle':
    sys.exit(22)
else:
    shutil.copyfile(os.environ['FIXTURE_BUNDLE'], args[args.index('--output') + 1])
''')
        if sys.platform != 'linux' or not shutil.which('sha256sum'):
            self.executable('sha256sum', '''import hashlib, pathlib, sys
digest, name = sys.stdin.read().strip().split(None, 1)
sys.exit(0 if hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == digest else 1)
''')
        if not shutil.which('setsid'):
            # macOS is not an installation target. Exercise forwarding there;
            # process-group supervision is verified with real setsid on Linux.
            self.executable('setsid', '''import os, sys
assert sys.argv[1] == '--wait'
os.execvp(sys.argv[2], sys.argv[2:])
''')

    def executable(self, name, body):
        path = self.bin / name
        path.write_text('#!' + shutil.which('python3') + '\n' + body)
        path.chmod(0o755)

    def run_loader(self, shell='/bin/sh', flags=(), env=None, loader=None):
        result = subprocess.run([shell, '-s', '--', *flags],
                                input=loader or (self.directory / 'bootstrap.sh').read_text(),
                                env={**self.env, **(env or {})}, text=True, capture_output=True)
        self.assertEqual(list(self.scratch.iterdir()), [], result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        return result

    def test_complete_package_and_retained_loader_activation(self):
        with tarfile.open(self.directory / 'runtime-bootstrap.tar.gz') as archive:
            self.assertTrue(all(entry.isfile() for entry in archive))
            for name in ('lib/preflight.sh', 'config/k3s.yaml', 'manifests/runtimeclass.yaml',
                         'manifests/bootstrap/deployments.yaml', 'release-runtime-image'):
                self.assertIsNotNone(archive.getmember('runtime/' + name))
            self.assertEqual(archive.extractfile('runtime/release-runtime-image').read(), (IMAGE + '\n').encode())
        bundle = (self.directory / 'runtime-bootstrap.tar.gz').read_bytes()
        self.assertEqual(self.record['bundle_sha256'], hashlib.sha256(bundle).hexdigest())
        old = (self.output / 'bootstrap.sh').read_bytes()
        release.package(self.source, self.output, 'v2', release.DEFAULT_ORIGIN, IMAGE)
        self.assertEqual((self.output / 'bootstrap.sh').read_bytes(), old)
        release.activate(self.output, 'v2')
        self.assertNotEqual((self.output / 'bootstrap.sh').read_bytes(), old)
        release.activate(self.output, 'v1')
        self.assertEqual((self.output / 'bootstrap.sh').read_bytes(), old)
        self.assertEqual((self.directory / 'runtime-bootstrap.tar.gz').read_bytes(), bundle)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            release.package(self.source, self.output, 'v1', release.DEFAULT_ORIGIN, IMAGE, True)

    def test_rejects_unsafe_inputs_and_missing_assets(self):
        for version, origin, image in (
            ('../bad', release.DEFAULT_ORIGIN, IMAGE), ('v3', 'http://example.org', IMAGE),
            ('v3', 'https://user:pass@example.org', IMAGE), ('v3', 'https://example.org/path', IMAGE),
            ('v3', "https://example.org/'bad", IMAGE), ('v3', release.DEFAULT_ORIGIN, 'registry/runtime:latest'),
        ):
            with self.subTest(version=version, origin=origin, image=image), self.assertRaises(ValueError):
                release.package(self.source, self.output, version, origin, image)
        (self.source / 'runtime/lib/credentials.sh').unlink()
        with self.assertRaisesRegex(ValueError, 'missing or unsafe'):
            release.package(self.source, self.output, 'v3', release.DEFAULT_ORIGIN, IMAGE)

    def test_local_configuration_is_excluded_and_asset_symlinks_are_rejected(self):
        secret = self.source / 'runtime/config/local-secret'
        secret.write_text('untracked private configuration')
        release.package(self.source, self.output, 'v2', release.DEFAULT_ORIGIN, IMAGE)
        with tarfile.open(self.output / 'releases/v2/runtime-bootstrap.tar.gz') as archive:
            self.assertNotIn('runtime/config/local-secret', archive.getnames())
        asset = self.source / 'runtime/lib/preflight.sh'
        asset.unlink()
        asset.symlink_to(secret)
        with self.assertRaisesRegex(ValueError, 'unsafe bootstrap asset'):
            release.package(self.source, self.output, 'v3', release.DEFAULT_ORIGIN, IMAGE)

    def test_posix_pipeline_and_sudo_forward_only_execution_environment(self):
        self.executable('sudo', r'''import os, sys
assert sys.argv[1] == '--preserve-env=LIVEPEER_ENROLLMENT_TOKEN'
assert os.environ.get('LIVEPEER_ENROLLMENT_TOKEN') == 'header.payload.signature'
assert all('header.payload.signature' not in arg for arg in sys.argv)
os.execvp(sys.argv[2], sys.argv[2:])
''')
        for shell in dict.fromkeys(('/bin/sh', shutil.which('dash') or '/bin/sh')):
            for sudo in ('', 'sudo --preserve-env=LIVEPEER_ENROLLMENT_TOKEN '):
                with self.subTest(shell=shell, sudo=sudo):
                    command = ('curl -fsSL https://example.invalid/bootstrap.sh | '
                               f'LIVEPEER_ENROLLMENT_TOKEN={shlex.quote(TOKEN)} '
                               f'{sudo}{shlex.quote(shell)} -s -- --install-dir /srv/livepeer')
                    result = subprocess.run([shell, '-c', command], env=self.env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    saved = json.loads(Path(self.env['FIXTURE_RESULT']).read_text())
                    self.assertEqual(saved['token'], '1')
                    self.assertTrue(saved['private'])
                    self.assertEqual(saved['args'], ['--install-dir', '/srv/livepeer'])
                    self.assertEqual(list(self.scratch.iterdir()), [])
                    self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_overrides_read_only_flags_and_inherited_export_controls(self):
        for shell in dict.fromkeys(('/bin/sh', shutil.which('dash') or '/bin/sh')):
            result = self.run_loader(shell, ('--refresh-credentials', '--install-dir', '/srv/livepeer'), {
                'LIVEPEER_ENROLLMENT_TOKEN': TOKEN, '_lp_token': 'inherited',
                'LIVEPEER_API_URL': 'https://custom.example', 'LIVEPEER_RUNTIME_IMAGE': IMAGE,
            })
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = json.loads(Path(self.env['FIXTURE_RESULT']).read_text())
            self.assertEqual((saved['api'], saved['image'], saved['token']), ('https://custom.example', IMAGE, '1'))
        for flag in ('--check-only', '--status', '--reenroll'):
            result = self.run_loader(flags=(flag,))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(Path(self.env['FIXTURE_RESULT']).read_text())['token'], '0')
        loader = (self.directory / 'bootstrap.sh').read_text()
        result = subprocess.run(['bash', '-ax', '-s'], input=loader,
                                env={**self.env, 'LIVEPEER_ENROLLMENT_TOKEN': TOKEN, '_lp_token': TOKEN},
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_bundle_failures_never_run_installer_and_preserve_status(self):
        original = (self.directory / 'runtime-bootstrap.tar.gz').read_bytes()
        for failure in ('bundle', 'checksum', 'extract', 'layout'):
            with self.subTest(failure=failure):
                loader = (self.directory / 'bootstrap.sh').read_text()
                data = original
                if failure in ('checksum', 'extract'):
                    data = b'truncated invalid archive'
                elif failure == 'layout':
                    stream = io.BytesIO()
                    with tarfile.open(fileobj=stream, mode='w:gz'):
                        pass
                    data = stream.getvalue()
                if failure in ('extract', 'layout'):
                    loader = loader.replace(self.record['bundle_sha256'], hashlib.sha256(data).hexdigest())
                (self.directory / 'runtime-bootstrap.tar.gz').write_bytes(data)
                result = self.run_loader(env={'FIXTURE_FAIL': failure}, loader=loader)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(Path(self.env['FIXTURE_RESULT']).exists())
        (self.directory / 'runtime-bootstrap.tar.gz').write_bytes(original)
        result = self.run_loader(env={'FIXTURE_EXIT': '42'})
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_initial_empty_download_boundary(self):
        download = subprocess.Popen([str(self.bin / 'curl'), '-fsSL', 'https://example.invalid/bootstrap.sh'],
                                    env={**self.env, 'FIXTURE_FAIL': 'loader'}, stdout=subprocess.PIPE)
        loader = subprocess.run(['/bin/sh', '-'], stdin=download.stdout, env=self.env, capture_output=True)
        download.stdout.close()
        self.assertEqual(download.wait(), 22)
        self.assertEqual(loader.returncode, 0)  # The documented POSIX pipeline limitation.
        self.assertFalse(Path(self.env['FIXTURE_RESULT']).exists())

    def test_truncated_final_invocation_never_starts_installer(self):
        loader = (self.directory / 'bootstrap.sh').read_text()
        truncated = loader[:loader.rindex('_lp_main') + len('_lp_main')]
        result = self.run_loader(flags=('--check-only', '--install-dir', '/srv/livepeer'), loader=truncated)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(self.env['FIXTURE_RESULT']).exists())

    def test_term_reaps_installer_before_cleanup(self):
        process = subprocess.Popen(['/bin/sh', '-s'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env={**self.env, 'FIXTURE_WAIT': '1'})
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        process.stdin.write((self.directory / 'bootstrap.sh').read_text())
        process.stdin.close()
        process.stdin = None
        deadline = time.monotonic() + 10
        while not Path(self.env['FIXTURE_RESULT']).exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(Path(self.env['FIXTURE_RESULT']).exists())
        time.sleep(.1)  # Allow the fixture to install its signal handler.
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 143, stderr)
        self.assertEqual(Path(self.env['FIXTURE_STOPPED']).read_text(), 'stopped')
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertNotIn(TOKEN, stdout + stderr)

    @unittest.skipUnless(sys.platform == 'linux' and shutil.which('setsid'), 'Linux process-group supervision')
    def test_cancellation_stops_foreground_pipeline_and_subshell_descendants(self):
        cases = ((signal.SIGTERM, 'foreground'), (signal.SIGINT, 'pipeline'), (signal.SIGHUP, 'subshell'))
        for signum, mode in cases:
            with self.subTest(signal=signum, mode=mode):
                marker = self.root / ('helper-' + mode)
                process = subprocess.Popen(['/bin/sh', '-s'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, env={**self.env, 'FIXTURE_DESCENDANT_MODE': mode,
                    'FIXTURE_HELPER': str(marker), 'FIXTURE_IGNORE_TERM': '1' if mode == 'pipeline' else ''})
                try:
                    process.stdin.write((self.directory / 'bootstrap.sh').read_text())
                    process.stdin.close()
                    process.stdin = None
                    deadline = time.monotonic() + 10
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(.02)
                    self.assertTrue(marker.exists())
                    process.send_signal(signum)
                    if mode == 'pipeline':
                        time.sleep(.2)
                        process.send_signal(signum)
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 128 + signum, stderr)
                    self.assertEqual(list(self.scratch.iterdir()), [])
                    time.sleep(1.2)
                    self.assertFalse(marker.with_suffix('.late').exists())
                    self.assertNotIn(TOKEN, stdout + stderr)
                finally:
                    if process.poll() is None:
                        process.kill()


if __name__ == '__main__':
    unittest.main()
