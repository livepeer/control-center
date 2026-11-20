"""R2 publication tests for bootstrap releases, using a fake wrangler."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load('bootstrap_release', 'tools/package-bootstrap.py')
publisher = load('bootstrap_publish', 'tools/publish-bootstrap.py')
IMAGE = 'registry.example/runtime@sha256:' + 'd' * 64

# Mirrors the wrangler behaviour the publisher relies on: `get` creates the
# output file before it fails on a missing key, and errors go to stderr.
FAKE_WRANGLER = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, shutil, sys
    from pathlib import Path
    store, meta = Path(os.environ['FAKE_R2']), Path(os.environ['FAKE_R2_META'])
    args = sys.argv[1:]
    with open(os.environ['FAKE_R2_CALLS'], 'a') as log:
        log.write(json.dumps(args) + '\\n')
    assert args[:2] == ['r2', 'object'] and args[-1] == '--remote', args
    op, path, options = args[2], args[3], dict(zip(args[4:-1:2], args[5:-1:2]))
    assert options.pop('--env-file') == os.devnull, args
    bucket, key = path.split('/', 1)
    if os.environ.get('FAKE_R2_FAIL') == op + ':' + key:
        sys.exit('✘ [ERROR] Authentication error [code: 10000]')
    target = store / bucket / key
    if op == 'get':
        Path(options['--file']).write_bytes(b'')
        if not target.is_file():
            sys.exit('✘ [ERROR] The specified key does not exist.')
        shutil.copyfile(target, options['--file'])
    elif op == 'put':
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(options['--file'], target)
        if os.environ.get('FAKE_R2_CORRUPT') == key:
            target.write_bytes(b'corrupted')
        record = meta / bucket / (key + '.json')
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(json.dumps(options))
    else:
        sys.exit('unsupported ' + op)
''')


class BootstrapPublish(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / 'bootstrap'
        for release_id in ('r1', 'r2'):
            release.package(ROOT, self.source, release_id, release.DEFAULT_ORIGIN, IMAGE)
        # History used to order releases: c1 <- c2 on main, and c3 branching from c1.
        self.repository = self.root / 'repository'
        self.repository.mkdir()
        self.git('init', '-q')
        self.commits = {}
        for name, parent in (('c1', None), ('c2', 'c1'), ('c3', 'c1')):
            if parent:
                self.git('checkout', '-q', '--detach', self.commits[parent])
            self.git('commit', '-q', '--allow-empty', '-m', name)
            self.commits[name] = self.git('rev-parse', 'HEAD')
        self.set_commit('r1', 'c1')
        self.set_commit('r2', 'c2')
        self.store, self.meta, self.calls = self.root / 'r2', self.root / 'meta', self.root / 'calls.jsonl'
        self.wrangler = self.root / 'wrangler'
        self.wrangler.write_text(FAKE_WRANGLER)
        self.wrangler.chmod(0o755)
        self.environment = {'FAKE_R2': str(self.store), 'FAKE_R2_META': str(self.meta), 'FAKE_R2_CALLS': str(self.calls)}
        patcher = unittest.mock.patch.dict(os.environ, self.environment)
        patcher.start()
        self.addCleanup(patcher.stop)

    def git(self, *args):
        environment = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
                       'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                       'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid'}
        return subprocess.check_output(['git', '-C', str(self.repository), *args], env=environment, text=True).strip()

    def set_commit(self, release_id, commit):
        """Record a source commit; release.json is not covered by the loader's checksums."""
        path = self.source / 'releases' / release_id / 'release.json'
        record = json.loads(path.read_text())
        record['source_commit'] = self.commits.get(commit, commit)
        path.write_text(json.dumps(record, indent=2) + '\n')

    def run_publish(self, *args):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            try:
                publisher.main(['--source', str(self.source), '--wrangler', str(self.wrangler),
                                '--repository', str(self.repository), *args])
                code = 0
            except SystemExit as exit:
                code = exit.code
        return code, stderr.getvalue()

    def remote(self, key):
        path = self.store / publisher.DEFAULT_BUCKET / key
        return path.read_bytes() if path.is_file() else None

    def local(self, release_id, name):
        return (self.source / 'releases' / release_id / name).read_bytes()

    def puts(self):
        if not self.calls.exists():
            return []
        return [json.loads(line)[3].split('/', 1)[1] for line in self.calls.read_text().splitlines() if json.loads(line)[2] == 'put']

    def test_publishes_then_activates_the_loader_last(self):
        code, output = self.run_publish('--release-id', 'r1', '--activate', 'r1')
        self.assertEqual(code, 0, output)
        for name in publisher.RELEASE_FILES:
            self.assertEqual(self.remote(f'releases/r1/{name}'), self.local('r1', name))
        self.assertEqual(self.remote('bootstrap.sh'), self.local('r1', 'bootstrap.sh'))
        self.assertEqual(self.puts(), ['releases/r1/runtime-bootstrap.tar.gz', 'releases/r1/SHA256SUMS',
                                       'releases/r1/release.json', 'releases/r1/bootstrap.sh', 'bootstrap.sh'])
        bundle = json.loads((self.meta / publisher.DEFAULT_BUCKET / 'releases/r1/runtime-bootstrap.tar.gz.json').read_text())
        self.assertEqual(bundle, {'--file': bundle['--file'], '--content-type': 'application/gzip',
                                  '--cache-control': 'public, max-age=31536000, immutable'})
        loader = json.loads((self.meta / publisher.DEFAULT_BUCKET / 'bootstrap.sh.json').read_text())
        self.assertEqual((loader['--content-type'], loader['--cache-control']), ('text/x-shellscript', 'no-cache'))

    def test_republishing_identical_content_writes_nothing(self):
        self.assertEqual(self.run_publish('--release-id', 'r1')[0], 0)
        self.calls.unlink()
        code, output = self.run_publish('--release-id', 'r1')
        self.assertEqual(code, 0, output)
        self.assertEqual(self.puts(), [])
        self.assertIn('unchanged releases/r1/runtime-bootstrap.tar.gz', output)

    def test_refuses_to_replace_a_published_release(self):
        conflict = self.store / publisher.DEFAULT_BUCKET / 'releases/r1/SHA256SUMS'
        conflict.parent.mkdir(parents=True)
        conflict.write_bytes(b'other\n')
        code, output = self.run_publish('--release-id', 'r1', '--activate', 'r1')
        self.assertEqual(code, 1)
        self.assertIn('immutable', output)
        self.assertEqual(conflict.read_bytes(), b'other\n')
        self.assertIsNone(self.remote('bootstrap.sh'))

    def test_activation_requires_a_complete_published_release(self):
        code, output = self.run_publish('--activate', 'r1')
        self.assertEqual(code, 1)
        self.assertIn('not completely published', output)
        self.assertIsNone(self.remote('bootstrap.sh'))

    def test_activation_moves_forward(self):
        self.assertEqual(self.run_publish('--all', '--activate', 'r1')[0], 0)
        code, output = self.run_publish('--activate', 'r2')
        self.assertEqual(code, 0, output)
        self.assertEqual(self.remote('bootstrap.sh'), self.local('r2', 'bootstrap.sh'))
        # Re-activating the active release is a no-op check.
        self.assertEqual(self.run_publish('--activate', 'r2')[0], 0)

    def test_refuses_to_activate_an_older_or_diverged_release(self):
        for commit in ('c1', 'c3'):
            shutil.rmtree(self.store, ignore_errors=True)
            self.set_commit('r1', commit)
            self.assertEqual(self.run_publish('--all', '--activate', 'r2')[0], 0, commit)
            code, output = self.run_publish('--activate', 'r1')
            self.assertEqual(code, 1, commit)
            self.assertIn('is not newer than the active release r2', output)
            self.assertIn('--rollback', output)
            self.assertEqual(self.remote('bootstrap.sh'), self.local('r2', 'bootstrap.sh'))

    def test_rollback_reactivates_an_older_release(self):
        self.assertEqual(self.run_publish('--all', '--activate', 'r2')[0], 0)
        self.assertEqual(self.remote('bootstrap.sh'), self.local('r2', 'bootstrap.sh'))
        code, output = self.run_publish('--activate', 'r1', '--rollback')
        self.assertEqual(code, 0, output)
        self.assertIn('(rollback)', output)
        self.assertEqual(self.remote('bootstrap.sh'), self.local('r1', 'bootstrap.sh'))
        self.assertIsNotNone(self.remote('releases/r2/runtime-bootstrap.tar.gz'))
        # Moving forward again needs no flag.
        self.assertEqual(self.run_publish('--activate', 'r2')[0], 0)

    def test_refuses_releases_it_cannot_order(self):
        for commit, message in (('a' * 40, 'fetch its history'), ('--output=x', 'invalid source_commit')):
            shutil.rmtree(self.store, ignore_errors=True)
            self.set_commit('r2', commit)
            self.assertEqual(self.run_publish('--all', '--activate', 'r1')[0], 0, commit)
            code, output = self.run_publish('--activate', 'r2')
            self.assertEqual(code, 1, commit)
            self.assertIn(message, output)
            self.assertIn('--rollback', output)
            self.assertEqual(self.remote('bootstrap.sh'), self.local('r1', 'bootstrap.sh'))

    def test_rollback_requires_activate(self):
        self.assertEqual(self.run_publish('--release-id', 'r1', '--rollback')[0], 2)

    def test_read_errors_are_not_mistaken_for_missing_objects(self):
        os.environ['FAKE_R2_FAIL'] = 'get:releases/r1/runtime-bootstrap.tar.gz'
        code, output = self.run_publish('--release-id', 'r1')
        self.assertEqual(code, 1)
        self.assertIn('Authentication error', output)
        self.assertEqual(self.puts(), [])

    def test_write_must_read_back_intact(self):
        os.environ['FAKE_R2_CORRUPT'] = 'releases/r1/runtime-bootstrap.tar.gz'
        code, output = self.run_publish('--release-id', 'r1', '--activate', 'r1')
        self.assertEqual(code, 1)
        self.assertIn('did not read back intact', output)
        self.assertIsNone(self.remote('bootstrap.sh'))

    def test_rejects_inconsistent_or_unexpected_local_releases(self):
        (self.source / 'releases/r1/SHA256SUMS').write_text('0' * 64 + '  runtime-bootstrap.tar.gz\n')
        (self.source / 'releases/r2/notes.txt').write_text('extra')
        for release_id, message in (('r1', 'inconsistent'), ('r2', 'must contain exactly'), ('../r1', 'safe path component'), ('missing', 'not found')):
            code, output = self.run_publish('--release-id', release_id)
            self.assertEqual(code, 1, release_id)
            self.assertIn(message, output, release_id)
        self.assertFalse(self.calls.exists())


if __name__ == '__main__':
    unittest.main()
