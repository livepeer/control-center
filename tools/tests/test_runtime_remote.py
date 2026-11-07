"""Hermetic source/SSH-boundary tests: no server, network, or Docker daemon."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('runtime_remote', Path(__file__).parents[1] / 'test-runtime-remote.py')
remote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote)
REAL_RUN = subprocess.run


class Repository(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q', '--initial-branch=main')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'core.hooksPath', '/dev/null')
        self.write('runtime/tests/run.sh', '#!/bin/bash\nexit 0\n', 0o755)
        self.write('runtime/config/k3s.yaml', 'source template\n')
        self.write('runtime/lib/helper.sh', '#!/bin/bash\ntrue\n', 0o755)
        self.write('.gitignore', 'runtime/ignored\n')
        self.commit()

    def git(self, *args):
        return REAL_RUN(['git', '-C', str(self.root), *args], check=True, capture_output=True).stdout

    def write(self, name, content, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        return path

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def archive(self, ref=''):
        target = self.root / 'snapshot.tar.gz'
        identity = remote.capture(self.root, ref, target)
        with tarfile.open(target) as archive:
            files = {m.name: (archive.extractfile(m).read(), m.mode) for m in archive}
        return identity, files


class CaptureTests(Repository):
    def test_current_contents_deletions_new_files_and_exclusions(self):
        self.write('runtime/config/k3s.yaml', 'staged\n')
        self.git('add', 'runtime/config/k3s.yaml')
        self.write('runtime/config/k3s.yaml', 'current\n')
        (self.root / 'runtime/lib/helper.sh').unlink()
        self.write('runtime/new file\nwith $quote.txt', 'new\n')
        for name in ('.env', '.env.example', 'secrets/key', 'credentials/token', 'state/install',
                     'config/kubeconfig.yaml', '.venv/lib/dependency', 'ignored', 'services/__pycache__/x.pyc'):
            self.write('runtime/' + name, 'excluded')
        self.write('api/secrets/key', 'not Runtime source')
        identity, files = self.archive()
        self.assertEqual(files['runtime/config/k3s.yaml'][0], b'current\n')
        self.assertEqual(files['runtime/new file\nwith $quote.txt'][0], b'new\n')
        self.assertNotIn('runtime/lib/helper.sh', files)
        self.assertEqual(files['runtime/tests/run.sh'][1], 0o755)
        self.assertEqual(set(files), {'runtime/tests/run.sh', 'runtime/config/k3s.yaml', 'runtime/new file\nwith $quote.txt'})
        self.assertEqual(identity['mode'], 'working-tree')

    def test_committed_source_and_modes_ignore_current_changes(self):
        revision = self.git('rev-parse', 'HEAD').decode().strip()
        self.write('runtime/tests/run.sh', 'changed', 0o644)
        self.write('runtime/config/k3s.yaml', 'staged')
        self.git('add', '.')
        self.write('runtime/untracked', 'new')
        identity, files = self.archive(revision)
        self.assertEqual(identity['revision'], revision)
        self.assertEqual(files['runtime/tests/run.sh'], (b'#!/bin/bash\nexit 0\n', 0o755))
        self.assertEqual(files['runtime/config/k3s.yaml'][0], b'source template\n')
        self.assertNotIn('runtime/untracked', files)

    def test_forbidden_tracked_files_fail_in_both_modes(self):
        self.write('runtime/.env', 'secret')
        revision = self.commit()
        for ref in ('', revision):
            with self.subTest(ref=ref), self.assertRaisesRegex(remote.RunError, 'Forbidden tracked path.*runtime/.env'):
                self.archive(ref)

    def test_links_submodules_and_nonregular_files_are_rejected(self):
        link = self.root / 'runtime/link'
        link.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(remote.RunError, 'regular files'):
            self.archive()
        link.unlink()
        regular = self.root / 'runtime/lib/helper.sh'
        regular.unlink()
        os.mkfifo(regular)
        with self.assertRaisesRegex(remote.RunError, 'regular files'):
            self.archive()
        regular.unlink()
        self.write('runtime/lib/helper.sh', '#!/bin/bash\ntrue\n')
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.git('rev-parse', 'HEAD').decode().strip() + ',runtime/submodule')
        with self.assertRaisesRegex(remote.RunError, 'submodules'):
            self.archive()

    def test_committed_symlink_and_symlinked_parent_are_rejected(self):
        path = self.root / 'runtime/config'
        path.rename(self.root / 'external')
        path.symlink_to(self.root / 'external', target_is_directory=True)
        with self.assertRaisesRegex(remote.RunError, '[Ss]ymlink'):
            self.archive()
        path.unlink()
        (self.root / 'external').rename(path)
        (self.root / 'runtime/link').symlink_to('config/k3s.yaml')
        revision = self.commit()
        with self.assertRaisesRegex(remote.RunError, 'Symlinks'):
            self.archive(revision)

    def test_bad_or_unsupported_revision_and_missing_entrypoint(self):
        for ref in ('does-not-exist', '--help'):
            with self.subTest(ref=ref), self.assertRaises(remote.RunError):
                self.archive(ref)
        (self.root / 'runtime/tests/run.sh').unlink()
        revision = self.commit()
        for ref in ('', revision):
            with self.subTest(ref=ref), self.assertRaisesRegex(remote.RunError, 'combined-repository commit'):
                self.archive(ref)

    def test_read_error_after_enumeration_is_not_a_deletion(self):
        real_open = os.open
        def disappear(path, *args, **kwargs):
            if str(path).endswith('k3s.yaml'):
                raise FileNotFoundError('disappeared while opening')
            return real_open(path, *args, **kwargs)
        with mock.patch.object(remote.os, 'open', side_effect=disappear), self.assertRaises(FileNotFoundError):
            self.archive()

    def test_completed_archive_is_immutable(self):
        identity, files = self.archive()
        target = self.root / 'snapshot.tar.gz'
        before = target.read_bytes()
        self.write('runtime/config/k3s.yaml', 'later edit')
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(hashlib.sha256(before).hexdigest(), identity['sha256'])
        self.assertEqual(files['runtime/config/k3s.yaml'][0], b'source template\n')


class FakeProcess:
    def __init__(self, output, code=0, interrupted=False):
        self.code = code
        self.returncode = None
        self.terminated = False
        if interrupted:
            class InterruptStream(io.BytesIO):
                def __next__(self):
                    if self.tell() == 0:
                        return super().__next__()
                    raise KeyboardInterrupt
            self.stdout = InterruptStream(output)
        else:
            self.stdout = io.BytesIO(output)

    def wait(self, timeout=None):
        self.returncode = self.code
        return self.code

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.terminate()


class WorkflowTests(Repository):
    def execute(self, *, test_code=0, transport=0, cleanup=0, interrupted=False, confirmed=True,
                prepare=0, reported_outcome=None, reported_test=None, cleanup_interrupt=False,
                broken_console=False, prepare_interrupt=False):
        calls = []
        process = None
        def command(args, **kwargs):
            if args[0] == 'git':
                return REAL_RUN(args, **kwargs)
            self.assertEqual(args[0], 'ssh')
            parts = shlex.split(args[-1])
            calls.append(parts)
            if parts[2] == remote.PREPARE:
                if prepare_interrupt:
                    raise KeyboardInterrupt
                run_id = parts[-1]
                return subprocess.CompletedProcess(args, prepare, f'/tmp/livepeer-runtime-{run_id}.abcdefghij\n'.encode(), b'')
            self.assertEqual(parts[2], remote.CLEANUP)
            if cleanup_interrupt:
                raise KeyboardInterrupt
            return subprocess.CompletedProcess(args, cleanup, b'', b'cleanup unavailable\n' if cleanup else b'')
        def launch(args, **kwargs):
            nonlocal process
            parts = shlex.split(args[-1])
            self.assertEqual(parts[2], remote.EXECUTE)
            directory, digest, run_id, container = parts[-4:]
            data = kwargs['stdin'].read()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                self.assertEqual(archive.extractfile('runtime/config/k3s.yaml').read(), b'source template\n')
            # Mutating after submission must not affect the sent bytes.
            self.write('runtime/config/k3s.yaml', 'after capture')
            output = f'REMOTE_TEST_IMAGE {run_id} sha256:{"a" * 64}\n'.encode() + b'test log\n'
            if confirmed:
                outcome = reported_outcome or ('passed' if test_code == 0 else 'test_failed')
                report = test_code if reported_test is None else reported_test
                output += f'REMOTE_TEST_RESULT {run_id} {test_code} {report} {outcome} sha256:{"a" * 64}\n'.encode()
            process = FakeProcess(output, transport, interrupted)
            return process
        class Console(io.StringIO):
            def write(self, text):
                if broken_console and text.startswith('Remote directory:'):
                    raise BrokenPipeError
                return super().write(text)

        with mock.patch.object(remote.subprocess, 'run', side_effect=command), \
                mock.patch.object(remote, 'Popen', side_effect=launch), \
                contextlib.redirect_stdout(Console()):
            code = remote.run(self.root, 'developer-host')
        result_dir = next((self.root / '.remote-test-results').iterdir())
        record = json.loads((result_dir / 'result.json').read_text())
        self.assertIn('Capture complete', (result_dir / 'test.log').read_text())
        return code, record, calls, process

    def test_success_and_test_status_255_are_not_transport_failure(self):
        code, record, calls, _ = self.execute(test_code=255)
        self.assertEqual(code, 255)
        self.assertEqual(record['test_exit_code'], 255)
        self.assertEqual(record['outcome'], 'test_failed')
        self.assertEqual(record['cleanup'], 'ok')
        self.assertEqual(calls[-1][2], remote.CLEANUP)

    def test_success(self):
        code, record, _, _ = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(record['outcome'], 'passed')
        self.assertEqual(record['image'], 'sha256:' + 'a' * 64)

    def test_incomplete_runner_result_cannot_pass(self):
        code, record, _, _ = self.execute(reported_outcome='setup_failed', reported_test='null')
        self.assertEqual(code, 1)
        self.assertEqual(record['outcome'], 'setup_failed')
        self.assertIsNone(record['test_exit_code'])

    def test_interrupt_during_cleanup_preserves_status_130(self):
        code, record, _, _ = self.execute(cleanup_interrupt=True)
        self.assertEqual(code, 130)
        self.assertEqual(record['outcome'], 'interrupted')
        self.assertEqual(record['cleanup'], 'incomplete')

    def test_cleanup_interrupt_does_not_mask_failed_test(self):
        code, record, _, _ = self.execute(test_code=37, cleanup_interrupt=True)
        self.assertEqual(code, 37)
        self.assertEqual(record['outcome'], 'test_failed')
        self.assertEqual(record['cleanup'], 'incomplete')

    def test_broken_console_still_cleans_up_and_finalizes_results(self):
        code, record, calls, _ = self.execute(broken_console=True)
        self.assertEqual(code, 0)
        self.assertEqual(record['cleanup'], 'ok')
        self.assertIsNotNone(record['finished_at'])
        self.assertEqual(calls[-1][2], remote.CLEANUP)
        log = self.root / '.remote-test-results' / record['run_id'] / 'test.log'
        self.assertIn('test log', log.read_text())

    def test_received_result_remains_known_after_transport_failure(self):
        code, record, _, _ = self.execute(transport=255)
        self.assertEqual(code, 1)
        self.assertEqual(record['test_exit_code'], 0)
        self.assertIn('result was received', record['error'])
        self.assertNotIn('unknown', record['error'])

    def test_allocation_interrupt_has_possible_directory_hint(self):
        code, record, _, _ = self.execute(prepare_interrupt=True)
        self.assertEqual(code, 130)
        self.assertIsNone(record['remote_directory'])
        log = self.root / '.remote-test-results' / record['run_id'] / 'test.log'
        self.assertIn('/tmp/livepeer-runtime-' + record['run_id'] + '.*', log.read_text())

    def test_transport_failure_has_unknown_test_result(self):
        code, record, _, _ = self.execute(transport=255, confirmed=False)
        self.assertEqual(code, 1)
        self.assertIsNone(record['test_exit_code'])
        self.assertEqual(record['outcome'], 'transport_failed')

    def test_setup_or_upload_failure_is_saved(self):
        code, record, _, _ = self.execute(transport=1, confirmed=False)
        self.assertEqual(code, 1)
        self.assertEqual(record['outcome'], 'setup_failed')
        self.assertIn('completion', record['error'])

    def test_cleanup_failure_fails_passing_tests(self):
        code, record, _, _ = self.execute(cleanup=255)
        self.assertEqual(code, 1)
        self.assertEqual(record['test_exit_code'], 0)
        self.assertEqual(record['outcome'], 'cleanup_failed')
        self.assertEqual(record['cleanup'], 'incomplete')

    def test_cleanup_failure_does_not_mask_failed_test(self):
        code, record, _, _ = self.execute(test_code=37, cleanup=1)
        self.assertEqual(code, 37)
        self.assertEqual(record['outcome'], 'test_failed')

    def test_interrupt_cleans_up_before_terminating_transport(self):
        code, record, calls, process = self.execute(interrupted=True)
        self.assertEqual(code, 130)
        self.assertEqual(record['outcome'], 'interrupted')
        self.assertEqual(record['image'], 'sha256:' + 'a' * 64)
        self.assertEqual(calls[-1][2], remote.CLEANUP)
        self.assertTrue(process.terminated)

    def test_preflight_failure_does_not_attempt_unknown_directory_cleanup(self):
        code, record, calls, process = self.execute(prepare=255)
        self.assertEqual(code, 1)
        self.assertIsNone(process)
        self.assertIsNone(record['remote_directory'])
        self.assertEqual(len(calls), 1)

    def test_capture_failure_still_has_results_and_never_connects(self):
        self.write('runtime/.env', 'secret')
        self.commit()
        with mock.patch.object(remote, 'Popen') as launched, contextlib.redirect_stdout(io.StringIO()):
            code = remote.run(self.root, 'developer-host')
        self.assertEqual(code, 1)
        launched.assert_not_called()
        record = json.loads(next((self.root / '.remote-test-results').glob('*/result.json')).read_text())
        self.assertEqual(record['source']['mode'], 'working-tree')
        self.assertIn('Forbidden tracked path', record['error'])
        result_dir = self.root / '.remote-test-results' / record['run_id']
        self.assertFalse((result_dir / 'source.tar.gz').exists())
        self.assertFalse((result_dir / 'source.tar.gz.partial').exists())

    def test_capture_interruption_does_not_publish_partial_archive(self):
        def interrupted(root, ref, target):
            target.write_bytes(b'partial')
            raise KeyboardInterrupt
        with mock.patch.object(remote, 'capture', side_effect=interrupted), contextlib.redirect_stdout(io.StringIO()):
            code = remote.run(self.root, 'developer-host')
        result_dir = next((self.root / '.remote-test-results').iterdir())
        self.assertEqual(code, 130)
        self.assertEqual({p.name for p in result_dir.iterdir()}, {'result.json', 'test.log'})

    def test_destination_and_remote_argument_handling(self):
        for destination in ('', '-oProxyCommand=evil', 'host\ncommand', 'two hosts'):
            with self.subTest(destination=destination), self.assertRaises(remote.RunError):
                remote.ssh_command(destination, 'true')
        argument = "a'b $(touch should-not-exist)"
        args = remote.ssh_command('user@developer-host', remote.EXECUTE, argument)
        self.assertEqual(shlex.split(args[-1])[-1], argument)
        self.assertEqual(args[args.index('--') + 1], 'user@developer-host')


class RemoteShellTests(Repository):
    def setUp(self):
        super().setUp()
        self.run_id = 'test-' + self.root.name.replace('_', '-')
        self.remote_dir = Path(tempfile.mkdtemp(prefix='livepeer-runtime-' + self.run_id + '.', dir='/tmp'))
        self.addCleanup(shutil.rmtree, self.remote_dir, True)
        self.bin = self.root / 'fake-bin'
        self.bin.mkdir()
        # Emulate GNU checksum stdin using stdlib so tests need no checksum utility.
        script = self.bin / 'sha256sum'
        script.write_text('#!' + sys.executable + '\n' +
                          'import hashlib, pathlib, sys\n' +
                          'expected, name = sys.stdin.read().strip().split("  ", 1)\n' +
                          'sys.exit(0 if hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == expected else 1)\n')
        script.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH']}

    def shell(self, script, *args, data=None):
        return REAL_RUN(['bash', '-c', script, 'test', *args], input=data, capture_output=True, env=self.env)

    def test_remote_checksum_mismatch_never_starts_runner(self):
        self.archive()
        result = self.shell(remote.EXECUTE, str(self.remote_dir), '0' * 64, self.run_id, 'container',
                            data=(self.root / 'snapshot.tar.gz').read_bytes())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum mismatch', result.stderr)
        self.assertFalse((self.remote_dir / 'runner.started').exists())

    def test_remote_wrapper_confirms_test_failure(self):
        self.write('runtime/tests/run.sh', '#!/bin/bash\nprintf "37 test_failed -\\n" > "$LIVEPEER_TEST_STATE_DIR/runner.result"\nexit 37\n')
        identity, _ = self.archive()
        result = self.shell(remote.EXECUTE, str(self.remote_dir), identity['sha256'], self.run_id, 'container',
                            data=(self.root / 'snapshot.tar.gz').read_bytes())
        self.assertEqual(result.returncode, 0, result.stderr)
        record = next(remote.parse_result(line, self.run_id) for line in result.stdout.splitlines()
                      if line.startswith(b'REMOTE_TEST_RESULT'))
        self.assertEqual(record[:3], (37, 37, 'test_failed'))
        self.assertTrue((self.remote_dir / 'runner.finished').exists())

    def test_cleanup_retains_active_source_and_never_touches_other_directory(self):
        sentinel = self.root / 'unrelated'
        sentinel.mkdir()
        (self.remote_dir / 'runner.started').touch()
        result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.remote_dir.exists())
        (self.remote_dir / 'runner.finished').touch()
        result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.remote_dir.exists())
        self.assertTrue(sentinel.exists())
        result = self.shell(remote.CLEANUP, str(sentinel), self.run_id)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(sentinel.exists())

    def test_cleanup_retains_pending_execution_without_start_marker(self):
        result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id, '1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.remote_dir.exists())
        # Once SSH confirms execution ended before starting a runner, deletion is safe.
        result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id, '0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.remote_dir.exists())

    def fake_docker(self, owner, vanish=''):
        script = self.bin / 'docker'
        script.write_text('#!' + sys.executable + '\n' + r'''import os, sys
from pathlib import Path
a=sys.argv[1:]
present=Path(os.environ['FAKE_PRESENT'])
if a[:2]==['container','ls']:
    if present.exists(): print(os.environ['FAKE_ID'])
elif a[0]=='inspect':
    if os.environ['FAKE_VANISH']=='inspect': present.unlink(missing_ok=True)
    if not present.exists(): sys.exit(1)
    print(os.environ['FAKE_OWNER'])
elif a[:2]==['rm','-f']:
    Path(os.environ['FAKE_REMOVED']).write_text(a[-1])
    present.unlink(missing_ok=True)
    sys.exit(1 if os.environ['FAKE_VANISH']=='remove' else 0)
else: sys.exit(2)
''')
        script.chmod(0o755)
        self.env.update(FAKE_ID='c' * 64, FAKE_OWNER=owner, FAKE_VANISH=vanish,
                        FAKE_PRESENT=str(self.root / 'container-present'),
                        FAKE_REMOVED=str(self.root / 'removed-container'))
        (self.root / 'container-present').touch()
        (self.remote_dir / 'container.cid').write_text('c' * 64 + '\n')
        (self.remote_dir / 'runner.started').touch()
        (self.remote_dir / 'runner.finished').touch()

    def test_cleanup_removes_only_recorded_owned_container(self):
        self.fake_docker(self.run_id)
        result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'removed-container').read_text(), 'c' * 64)
        self.assertFalse(self.remote_dir.exists())

    def test_cleanup_refuses_container_with_another_owner(self):
        self.fake_docker('another-run')
        result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.remote_dir.exists())
        self.assertFalse((self.root / 'removed-container').exists())
    def test_cleanup_accepts_container_removed_by_another_cleanup(self):
        for phase in ('inspect', 'remove'):
            with self.subTest(phase=phase):
                self.remote_dir.mkdir(exist_ok=True)
                self.fake_docker(self.run_id, vanish=phase)
                result = self.shell(remote.CLEANUP, str(self.remote_dir), self.run_id)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.remote_dir.exists())



class RunnerTests(Repository):
    def setUp(self):
        super().setUp()
        source = Path(remote.__file__).parents[1] / 'runtime/tests/run.sh'
        self.runner = self.root / 'runtime/tests/run.sh'
        shutil.copyfile(source, self.runner)
        self.write('runtime/bootstrap-livepeer.sh', '#!/bin/bash\ntrue\n')
        self.write('runtime/tests/firewall-network.sh', '#!/bin/bash\ntrue\n')
        self.state = self.root / 'runner-state'
        self.state.mkdir()
        self.bin = self.root / 'fake-bin'
        self.bin.mkdir()
        driver = self.bin / 'driver'
        driver.write_text('#!' + sys.executable + '\n' + r'''import os, sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
if name=='uname': print('Linux')
elif name=='docker':
    present=Path(os.environ['FAKE_PRESENT'])
    if args[:2]==['context','inspect']: print('unix:///test-docker.sock')
    elif args[:2]==['image','inspect']: print('sha256:'+'a'*64)
    elif args[0]=='run':
        Path(args[args.index('--cidfile')+1]).write_text('c'*64+'\n')
        present.touch()
        print('LIVEPEER_FIREWALL_TEST_STARTED')
        if not os.environ.get('FAKE_VANISH'): present.unlink()
    elif args[0]=='inspect':
        if os.environ.get('FAKE_VANISH')=='inspect': present.unlink(missing_ok=True)
        if not present.exists(): sys.exit(1)
        print('runner-fixture')
    elif args[:2]==['rm','-f']:
        present.unlink(missing_ok=True)
        sys.exit(1 if os.environ.get('FAKE_VANISH')=='remove' else 0)
    elif args[:2]==['container','ls']:
        if present.exists(): print('c'*64)
elif name=='tee':
    data=sys.stdin.buffer.read()
    Path(args[0]).write_bytes(data)
    sys.stdout.buffer.write(data)
    sys.exit(int(os.environ.get('TEE_EXIT','0')))
''')
        driver.chmod(0o755)
        for name in ('uname', 'python3', 'shellcheck', 'docker', 'tee', 'jq', 'bzip2', 'sha256sum'):
            (self.bin / name).symlink_to(driver)
        for name in ('bash', 'tar', 'gzip', 'curl', 'awk', 'sed', 'grep', 'stat', 'diff', 'find', 'cat', 'rm', 'mktemp', 'dirname'):
            (self.bin / name).symlink_to(shutil.which(name))
        self.env = {**os.environ, 'PATH': str(self.bin), 'LIVEPEER_TEST_STATE_DIR': str(self.state),
                    'LIVEPEER_TEST_RUN_ID': 'runner-fixture', 'FAKE_PRESENT': str(self.root / 'container-present')}
        self.env.pop('DOCKER_HOST', None)
        self.env.pop('DOCKER_CONTEXT', None)

    def run_runner(self):
        result = REAL_RUN(['/bin/bash', str(self.runner)], env=self.env, capture_output=True)
        report = (self.state / 'runner.result').read_text().split()
        return result, report

    def test_firewall_log_failure_cannot_pass(self):
        self.env['TEE_EXIT'] = '1'
        result, report = self.run_runner()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report[:2], ['0', 'setup_failed'])

    def test_runner_accepts_concurrent_container_removal(self):
        for phase in ('inspect', 'remove'):
            with self.subTest(phase=phase):
                self.env['FAKE_VANISH'] = phase
                result, report = self.run_runner()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(report[:2], ['0', 'passed'])

    def test_missing_test_utilities_are_setup_failures(self):
        for name in ('jq', 'bzip2'):
            with self.subTest(name=name):
                shim = self.bin / name
                shim.unlink()
                result, report = self.run_runner()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(('Missing prerequisite: ' + name).encode(), result.stderr)
                self.assertEqual(report[:2], ['null', 'setup_failed'])
                shim.symlink_to(self.bin / 'driver')


if __name__ == '__main__':
    unittest.main()
