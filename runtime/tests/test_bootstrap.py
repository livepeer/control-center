"""Host-safe tests; PyYAML and kubectl enable optional manifest validation."""
import contextlib
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import sys
import unittest
from unittest import mock
import urllib.error
import urllib.request

SCRIPT = Path(__file__).resolve().parents[1] / 'bootstrap-livepeer.sh'
PROJECT = SCRIPT.parent
try:
    import yaml
except ImportError:
    yaml = None


@contextlib.contextmanager
def serve(handler):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def archive_bytes(entries):
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, kind, data in entries:
                entry = tarfile.TarInfo(name)
                entry.type, entry.size, entry.mode = kind, len(data), 0o644
                entry.linkname = '/etc/passwd' if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ''
                archive.addfile(entry, io.BytesIO(data))
    return raw.getvalue()


def bundle(content=b'resources: []\n'):
    return archive_bytes([('kustomization.yaml', tarfile.REGTYPE, content)])


class TempTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)



class ShellTests(TempTest):
    def test_managed_kubeconfig_compatibility_directory(self):
        install = self.root.resolve() / 'install'
        target = install / 'config/kubeconfig.yaml'
        target.parent.mkdir(parents=True)
        target.write_text('managed kubeconfig')
        directory = self.root / 'compatibility'
        directory.mkdir()
        link = directory / 'k3s.yaml'
        link.symlink_to(target)
        def accepted(path=directory):
            return self.shell('INSTALL_DIR="$1"; managed_kubeconfig_directory "$2"', str(install), str(path)).returncode == 0
        self.assertTrue(accepted())
        extra = directory / 'foreign-state'
        extra.write_text('foreign')
        self.assertFalse(accepted())
        extra.unlink()
        link.unlink()
        link.symlink_to(self.root / 'foreign-kubeconfig')
        self.assertFalse(accepted())
        link.unlink()
        link.write_text(str(target))
        self.assertFalse(accepted())
        link.unlink()
        link.symlink_to(target)
        alias = self.root / 'alias'
        alias.symlink_to(directory)
        self.assertFalse(accepted(alias))

    def test_resume_accepts_only_the_managed_kernel_flannel_socket(self):
        setup = """MANAGED=$1
systemctl() { [[ $2 == --quiet && $3 == livepeer-k3s.service && $ACTIVE == 1 ]]; }
ip() { printf 'vxlan id 1 local 10.204.0.3 dstport %s nolearning\\n' "$PORT"; }
ss() { printf 'udp UNCONN 0 0 0.0.0.0:8472 0.0.0.0:* %s\\n' "$PROCESS"; }
owned_pid() { return 1; }
ACTIVE=$2; PORT=$3; PROCESS=$4
check_ports
"""
        for managed, active, port, process, expected in [
            ('1', '1', '8472', '', 0),
            ('0', '1', '8472', '', 1),
            ('1', '0', '8472', '', 1),
            ('1', '1', '8473', '', 1),
            ('1', '1', '8472', 'users:((foreign,pid=123,fd=4))', 1),
        ]:
            result = self.shell(setup, managed, active, port, process)
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_resume_rejects_cluster_state_in_default_extraction_cache(self):
        directory = self.root / 'cache'
        directory.mkdir()
        (directory / 'data').mkdir()
        def accepted():
            return self.shell('managed_k3s_cache_directory "$1"', str(directory)).returncode == 0
        self.assertTrue(accepted())
        for name in ('agent', 'server'):
            extra = directory / name
            extra.mkdir()
            self.assertFalse(accepted())
            extra.rmdir()
        (directory / 'data').rmdir()
        (directory / 'data').symlink_to(self.root)
        self.assertFalse(accepted())

    def shell(self, commands, *args):
        # Any accidental host Python invocation fails, even on developer machines.
        setup = '''source "$1"; shift
python() { echo 'host Python is forbidden' >&2; exit 199; }
python3() { echo 'host Python is forbidden' >&2; exit 199; }
ENROLLMENT_TOKEN='header.payload.signature'
LIVEPEER_API_URL='http://127.0.0.1:41932'
LIVEPEER_ALLOW_DEVELOPMENT_HTTP=1
RUNTIME_IMAGE=registry.invalid/runtime@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
LIVEPEER_RUNTIME_IMAGE=$RUNTIME_IMAGE
curl() {
  local digest
  digest=$(printf '%s' "$(cat /etc/machine-id)" | sha256sum)
  printf '{"node_id":"lp-%s","token":"%s","config_url":"%s","epoch":"11111111-1111-4111-8111-111111111111","credential_version":1}' "${digest:0:16}" "${MOCK_SERVICE_TOKEN:-$(printf 'b%.0s' {1..64})}" "${MOCK_CONFIG_URL:-http://api.example/v1/nodes/lp-${digest:0:16}/config}"
  printf '\\n200'
}
'''
        return subprocess.run(['bash', '-c', setup + commands, 'test', str(SCRIPT), *args],
                              text=True, capture_output=True)

    def test_help_and_invalid_arguments(self):
        result = self.shell('usage')
        self.assertEqual(result.returncode, 0)
        self.assertIn('--check-only', result.stdout)
        self.assertNotIn('Python', result.stdout)
        for args in (['--install-dir'], ['--unknown'], ['--install-dir', '/'],
                     ['--install-dir', 'relative'], ['--install-dir', '/opt/a b'],
                     ['--install-dir', '/opt/../livepeer']):
            result = self.shell('parse_args "$@"', *args)
            self.assertNotEqual(result.returncode, 0, args)

    def test_check_only_never_authenticates_or_installs(self):
        result = self.shell('''
preflight() { echo eligibility; }
authenticate_node() { echo authenticated; exit 88; }
prepare_installation() { exit 89; }
main --check-only --install-dir "$1"
''', str(self.root / 'not-created'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'eligibility')
        self.assertFalse((self.root / 'not-created').exists())

    def test_preflight_failure_stops_before_authentication(self):
        result = self.shell('''
preflight() { echo rejected; return 42; }
authenticate_node() { echo authenticated; }
main --install-dir "$1"
''', str(self.root / 'not-created'))
        self.assertEqual(result.returncode, 42)
        self.assertNotIn('authenticated', result.stdout)
        self.assertFalse((self.root / 'not-created').exists())

    def test_status_does_not_enroll_or_install(self):
        result = self.shell('''
show_status() { echo status; }
preflight() { exit 88; }
authenticate_node() { exit 89; }
main --status --install-dir "$1"
''', str(self.root / 'not-created'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'status')
        self.assertFalse((self.root / 'not-created').exists())

    def test_main_stage_order_without_host_mutation(self):
        result = self.shell('''
preflight() { echo eligibility; }
authenticate_node() { echo authentication; }
lock_installation() { echo lock; }
check_existing_installation() { echo recheck; }
prepare_installation() { echo prepare; mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/state"; }
install_components() { echo install; }
stage_manifests() { echo manifests; }
write_host_configuration() { echo host; }
bootstrap_cluster() { echo cluster; }
smoke_test() { echo smoke; }
main --install-dir "$1"
''', str(self.root / 'installation'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[:10],
                         ['eligibility', 'lock', 'recheck', 'authentication', 'prepare', 'install',
                          'manifests', 'host', 'cluster', 'smoke'])

    def test_checksums_and_supported_versions(self):
        (self.root / 'binary').write_bytes(b'corrupt')
        (self.root / 'SHA256SUMS').write_text('0' * 64 + '  binary\n')
        result = self.shell('verify_sum 256 "$1/SHA256SUMS" binary "$1"', str(self.root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum failed', result.stderr)
        for version, good in [('v1.37.2+k3s1', True), ('v1.37.10+k3s1', True),
                              ('v1.38.0+k3s1', True), ('v1.37.2+k3s10', True),
                              ('v1.37.1+k3s1', False), ('v1.36.9+k3s1', False), ('unknown', False)]:
            result = self.shell('version_at_least "$1" "$K3S_VERSION"', version)
            self.assertEqual(result.returncode == 0, good, version)

    def test_enrollment_and_prepare_preserve_secrets_without_python(self):
        target = self.root / 'installation'
        enroll = '''INSTALL_DIR="$1"; chown() { :; }
authenticate_node; prepare_installation
'''
        result = self.shell(enroll, str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        (target / 'credentials/runner-bootstrap.secret').write_text('preserved-runner-secret')
        saved = {p: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
                 for p in (target / 'credentials').iterdir()}
        result = self.shell(enroll, str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex((target / 'credentials/node-id').read_text(), r'^lp-[a-f0-9]{16}$')
        self.assertRegex((target / 'credentials/service-token').read_text(), r'^[a-f0-9]{64}$')
        for path, original in saved.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), original)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((target / 'k3s').stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / 'state/install-dir').read_text().strip(), str(target))
        token = target / 'credentials/service-token'
        token.write_bytes(b'')
        result = self.shell('INSTALL_DIR="$1"; authenticate_node', str(target))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(token.read_bytes(), b'')
        token.unlink()
        result = self.shell('INSTALL_DIR="$1"; authenticate_node', str(target))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('restore', result.stderr)

    def test_interrupted_enrollment_reuses_saved_credentials_without_jwt(self):
        for keep_runner in (False, True):
            target = self.root / ('saved-runner' if keep_runner else 'no-runner')
            result = self.shell('''INSTALL_DIR="$1"
chown() { :; }
authenticate_node
prepare_installation
''', str(target))
            self.assertEqual(result.returncode, 0, result.stderr)
            credentials = target / 'credentials'
            saved = {name: (credentials / name).read_bytes() for name in ('node-id', 'service-token', 'config-url')}
            runner = (credentials / 'runner-bootstrap.secret').read_bytes()
            (target / 'state/enrolled').unlink()
            if not keep_runner:
                (credentials / 'runner-bootstrap.secret').unlink()
            result = self.shell('''INSTALL_DIR="$1"
ENROLLMENT_TOKEN=''
unset LIVEPEER_API_URL
curl() { exit 91; }
chown() { :; }
authenticate_node
prepare_installation
''', str(target))
            self.assertEqual(result.returncode, 0, result.stderr)
            for name, value in saved.items():
                self.assertEqual((credentials / name).read_bytes(), value)
            self.assertTrue((target / 'state/enrolled').exists())
            self.assertTrue((credentials / 'runner-bootstrap.secret').stat().st_size)
            if keep_runner:
                self.assertEqual((credentials / 'runner-bootstrap.secret').read_bytes(), runner)

    def test_loopback_config_is_rejected_before_installation(self):
        for host in ('localhost', 'LOCALHOST', 'localhost.', '127.0.0.1', '127.42.0.1'):
            result = self.shell('''INSTALL_DIR="$1"
MOCK_CONFIG_URL="$2"
authenticate_node
''', str(self.root / 'new'), 'http://' + host + ':41932/config')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('loopback', result.stderr)
            self.assertFalse((self.root / 'new').exists())

    def test_fresh_enrollment_requires_token_and_api(self):
        for setup, message in [("ENROLLMENT_TOKEN=''", '--token'),
                               ("unset LIVEPEER_API_URL", 'LIVEPEER_API_URL')]:
            result = self.shell('INSTALL_DIR="$1"; ' + setup + '; authenticate_node', str(self.root / 'new'))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
            self.assertFalse((self.root / 'new').exists())

    def test_failed_or_malformed_registration_never_writes_credentials(self):
        cases = [
            ("curl() { return 22; }", 'registration request failed'),
            ("curl() { printf '{}\\n200'; }", 'invalid enrollment response: node_id'),
            ("curl() { printf 'not-json\\n200'; }", 'invalid enrollment response: node_id'),
            ("MOCK_SERVICE_TOKEN=bad", 'invalid enrollment credentials'),
            ("MOCK_CONFIG_URL=file:///invalid", 'invalid configuration URL'),
        ]
        for setup, expected in cases:
            result = self.shell('INSTALL_DIR="$1"; ' + setup + '; authenticate_node', str(self.root / 'new'))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertFalse((self.root / 'new').exists())
            self.assertNotIn('header.payload.signature', result.stderr)


class EnrollmentHTTPTests(TempTest):
    shell = ShellTests.shell

    def test_callback_sends_identity_and_consumes_credentials_without_logging(self):
        received = {}
        class Registration(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                received['path'] = self.path
                received['authorization'] = self.headers.get('Authorization')
                received['body'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                fingerprint = received['body']['fingerprint']
                response = {'node_id': 'lp-' + fingerprint[:16], 'token': 'c' * 64,
                            'config_url': 'https://api.example/v1/nodes/lp-' + fingerprint[:16] + '/config',
                            'epoch': '11111111-1111-4111-8111-111111111111', 'credential_version': 1}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
        url = self.stack.enter_context(serve(Registration))
        result = self.shell('''INSTALL_DIR="$1"
LIVEPEER_API_URL="$2"
curl() { command curl "$@"; }
chown() { :; }
authenticate_node
prepare_installation
''', str(self.root / 'install'), url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received['path'], '/v1/nodes/register')
        self.assertEqual(received['authorization'], 'Bearer header.payload.signature')
        self.assertEqual(received['body']['install_dir'], str(self.root / 'install'))
        self.assertRegex(received['body']['fingerprint'], r'^[a-f0-9]{64}$')
        self.assertEqual((self.root / 'install/credentials/service-token').read_text(), 'c' * 64)
        self.assertNotIn('c' * 64, result.stdout + result.stderr)
        self.assertNotIn('header.payload.signature', result.stdout + result.stderr)

    def test_registration_errors_distinguish_credentials_from_conflicts(self):
        for status, expected in [(401, 'refresh the enrollment token'), (409, 'already registered'), (503, 'HTTP 200')]:
            class Rejection(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass
                def do_POST(self):
                    self.send_response(status)
                    self.end_headers()
                    self.wfile.write(b'private-error-body')
            with serve(Rejection) as url:
                result = self.shell('''INSTALL_DIR="$1"
LIVEPEER_API_URL="$2"
curl() { command curl "$@"; }
authenticate_node
''', str(self.root / 'new'), url)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertNotIn('private-error-body', result.stdout + result.stderr)
            self.assertFalse((self.root / 'new').exists())

    def test_redirect_never_receives_the_bearer_token(self):
        forwarded = []
        class Sink(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                forwarded.append(self.headers.get('Authorization'))
                self.send_response(200)
                self.end_headers()
        destination = self.stack.enter_context(serve(Sink))
        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                metadata = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                node_id = 'lp-' + metadata['fingerprint'][:16]
                self.send_response(307)
                self.send_header('Location', destination + '/capture')
                self.end_headers()
                # A redirect body may resemble success; status is authoritative.
                self.wfile.write(json.dumps({'node_id': node_id, 'token': 'c' * 64,
                                            'config_url': 'https://api.example/config'}).encode())
        source = self.stack.enter_context(serve(Redirect))
        result = self.shell('''INSTALL_DIR="$1"
LIVEPEER_API_URL="$2"
curl() { command curl "$@"; }
authenticate_node
''', str(self.root / 'new'), source)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(forwarded, [])
        self.assertFalse((self.root / 'new').exists())


class EligibilityTests(TempTest):
    shell = ShellTests.shell

    def test_cpu_memory_and_disk_checks(self):
        base = '''INSTALL_DIR="$1/not-created"
nproc() { echo 4; }
awk() { if [[ "$*" == */proc/meminfo* ]]; then echo 8000000; else command awk "$@"; fi; }
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted-on\\n/dev/test 99999999 0 20971520 0 /\\n'; }
'''
        for override, message in [('', None), ('nproc() { echo 1; }', 'CPUs'),
                                   ('awk() { echo 1000; }', 'RAM'),
                                   ("df() { printf 'header\\n/dev/test 100 99 1 99 /\\n'; }", 'free disk')]:
            result = self.shell(base + override + '\ncheck_resources', str(self.root))
            if message:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'not-created').exists())

    def test_network_overlap_and_managed_routes(self):
        for route, managed, good in [('default via 10.0.0.1 dev eth0', 0, True),
                                     ('10.0.0.0/8 dev eth0', 0, False),
                                     ('10.42.1.0/24 dev eth0', 0, False),
                                     ('local 10.43.0.1 dev lo table local', 0, False),
                                     ('10.44.0.0/16 dev eth0', 0, True),
                                     ('10.42.0.0/24 dev cni0', 1, True),
                                     ('10.42.0.0/24 dev cni0', 0, False)]:
            result = self.shell('MANAGED="$2"; ip() { echo "$ROUTE"; }; ROUTE="$1"; check_routes', route, str(managed))
            self.assertEqual(result.returncode == 0, good, (route, result.stderr))

    def test_port_conflicts_allow_only_managed_processes(self):
        for protocol, port, managed, pids, good in [
            ('tcp', 6443, 0, 'pid=123', False), ('udp', 8472, 0, 'pid=123', False),
            ('tcp', 8935, 0, 'pid=999', False), ('tcp', 8936, 0, 'pid=999', False),
            ('tcp', 20241, 0, 'pid=999', False),
            ('tcp', 6443, 1, 'pid=123', True), ('tcp', 6443, 1, 'pid=999', False),
            ('tcp', 6443, 1, 'pid=123,pid=999', False), ('tcp', 6443, 1, '', False),
            ('tcp', 8080, 0, 'pid=999', True)]:
            socket = f'{protocol} LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:* users:(({pids}))'
            result = self.shell('''MANAGED="$2"; SOCKET="$1"
ss() { echo "$SOCKET"; }
owned_pid() { [[ "$1" == 123 ]]; }
check_ports
''', socket, str(managed))
            self.assertEqual(result.returncode == 0, good, (socket, result.stderr))

    def test_unmanaged_directory_and_invalid_marker_rejected(self):
        (self.root / 'user-data').write_text('keep')
        result = self.shell('INSTALL_DIR="$1"; check_existing_installation', str(self.root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nonempty', result.stderr)
        (self.root / 'state').mkdir()
        (self.root / 'state/install-dir').write_text('/somewhere-else')
        result = self.shell('INSTALL_DIR="$1"; check_existing_installation', str(self.root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('incompatible', result.stderr)


class RecoveryTests(TempTest):
    shell = ShellTests.shell

    def test_interrupted_publication_resumes_for_absent_and_empty_root(self):
        for existing in (False, True):
            target = self.root / ('empty' if existing else 'absent')
            if existing:
                target.mkdir()
            failed = self.shell('''INSTALL_DIR="$1"
mv() { if [[ "${*: -1}" == "$INSTALL_DIR" ]]; then exit 71; fi; command mv "$@"; }
initialize_installation
''', str(target))
            self.assertEqual(failed.returncode, 71, failed.stderr)
            self.assertFalse(target.exists())
            result = self.shell('INSTALL_DIR="$1"; initialize_installation; managed_installation', str(target))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_directory_initializes_and_nonempty_directory_is_preserved(self):
        target = self.root / 'install'
        target.mkdir()
        result = self.shell('INSTALL_DIR="$1"; initialize_installation; managed_installation', str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        other = self.root / 'unowned'
        (other / 'credentials').mkdir(parents=True)
        (other / 'credentials/operator-data').write_text('keep')
        result = self.shell('INSTALL_DIR="$1"; initialize_installation', str(other))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((other / 'credentials/operator-data').read_text(), 'keep')
        self.assertFalse((other / 'state/install-dir').exists())

    def test_interruption_during_write_preserves_old_file(self):
        credential = self.root / 'secret'
        credential.write_text('original')
        result = self.shell('''
mv() { exit 72; }
printf 'replacement' | atomic_write "$1"
''', str(credential))
        self.assertEqual(result.returncode, 72)
        self.assertEqual(credential.read_text(), 'original')
        result = self.shell('write_once "$1" original', str(credential))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_damaged_cache_and_binary_are_repaired_without_partial_publication(self):
        source = self.root / 'upstream'
        source.write_text('#!/bin/sh\necho healthy\n')
        sums = self.root / 'checksums'
        sums.write_text(hashlib.sha256(source.read_bytes()).hexdigest() + '  asset\n')
        (self.root / 'asset').write_text('damaged cache')
        (self.root / 'binary').write_text('damaged installation')
        result = self.shell('''
download() { cp "$1" "$2"; }
verified_asset "$1/upstream" "$1/asset" 256 "$1/checksums"
atomic_binary "$1/asset" "$1/binary"
''', str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'asset').read_bytes(), source.read_bytes())
        self.assertEqual((self.root / 'binary').read_bytes(), source.read_bytes())
        self.assertTrue(os.access(self.root / 'binary', os.X_OK))
        (self.root / 'binary').chmod(0o644)
        inode = (self.root / 'binary').stat().st_ino
        result = self.shell('mv() { exit 73; }; atomic_binary "$1/asset" "$1/binary"', str(self.root))
        # Identical verified binaries are reused without replacing their inode.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'binary').stat().st_ino, inode)
        self.assertTrue(os.access(self.root / 'binary', os.X_OK))
        (self.root / 'asset').write_text('a new verified binary')
        old = (self.root / 'binary').read_bytes()
        result = self.shell('mv() { exit 73; }; atomic_binary "$1/asset" "$1/binary"', str(self.root))
        self.assertEqual(result.returncode, 73)
        self.assertEqual((self.root / 'binary').read_bytes(), old)

    def test_corrupt_checksum_cache_refreshes_and_bad_upstream_preserves_installation(self):
        version = 'v1.38.0+k3s1'
        payload = f'#!/bin/sh\necho "k3s version {version} (repaired)"\n'.encode()
        valid = (hashlib.sha256(payload).hexdigest() + '  k3s\n').encode()
        for case, metadata in [('healthy', valid), ('empty', b''), ('truncated', b'1234  k3s\n'),
                               ('ambiguous', valid * 2), ('mismatch', b'0' * 64 + b'  k3s\n'),
                               ('unavailable', None)]:
            with self.subTest(case=case):
                target = self.root / case
                cache = target / 'download/k3s' / version
                for directory in (cache, target / 'upstream', target / 'bin', target / 'state'):
                    directory.mkdir(parents=True)
                (cache / 'checksums.txt').write_bytes(b'broken cached metadata')
                (cache / 'k3s').write_bytes(b'broken cached payload')
                (target / 'upstream/k3s').write_bytes(payload)
                if metadata is not None:
                    (target / 'upstream/sha256sum-amd64.txt').write_bytes(metadata)
                binary = target / 'bin/k3s'
                binary.write_text(f'#!/bin/sh\necho "k3s version {version} (installed)"\n')
                binary.chmod(0o755)
                record = target / 'state/k3s-version'
                record.write_text(version + '\n')
                saved = {p: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
                         for p in (binary, record, cache / 'k3s')}
                result = self.shell('''INSTALL_DIR="$1"
curl() {
  local url="${@: -1}"
  while [[ "$1" != --output ]]; do shift; done
  printf '%s\\n' "${url##*/}" >> "$INSTALL_DIR/fetches"
  cp "$INSTALL_DIR/upstream/${url##*/}" "$2"
}
install_k3s
''', str(target))
                self.assertEqual((target / 'fetches').read_text().splitlines().count('sha256sum-amd64.txt'), 1)
                if case == 'healthy':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(binary.read_bytes(), payload)
                    self.assertEqual((cache / 'checksums.txt').read_bytes(), valid)
                    self.assertEqual(record.read_text(), version + '\n')
                    self.assertTrue(os.access(binary, os.X_OK))
                else:
                    self.assertNotEqual(result.returncode, 0)
                    for path, original in saved.items():
                        self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), original)
                    self.assertFalse((target / 'state/k3s-restart-required').exists())

    def test_gvisor_installer_replaces_partial_tree_and_reuses_complete_generation(self):
        upstream = self.root / 'upstream'
        upstream.mkdir()
        tree = self.root / 'tree'
        (tree / 'gvisor-bin').mkdir(parents=True)
        for name in ('runsc', 'containerd-shim-runsc-v1', 'gvisor-bin/helper'):
            (tree / name).write_text('#!/bin/sh\nexit 0\n')
            (tree / name).chmod(0o755)
        archive = upstream / 'gvisor-x86_64.tar.bz2'
        with tarfile.open(archive, 'w:bz2') as tar:
            for path in tree.iterdir():
                tar.add(path, arcname=path.name)
        (upstream / 'SHA512SUMS').write_text(hashlib.sha512(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
        (self.root / 'bin').mkdir()
        generations = []
        for fault in ('missing-helper', 'not-executable'):
            with self.subTest(fault=fault):
                damaged = self.root / fault
                shutil.copytree(tree, damaged)
                helper = damaged / 'gvisor-bin/helper'
                if fault == 'missing-helper':
                    helper.unlink()
                else:
                    helper.chmod(0o644)
                for name in ('runsc', 'containerd-shim-runsc-v1'):
                    link = self.root / 'bin' / name
                    link.unlink(missing_ok=True)
                    link.symlink_to(damaged / name)
                result = self.shell('''INSTALL_DIR="$1"
download() { cp "$INSTALL_DIR/upstream/${1##*/}" "$2"; }
install_gvisor
first=$(readlink -f "$INSTALL_DIR/bin/runsc")
install_gvisor
[[ "$first" == "$(readlink -f "$INSTALL_DIR/bin/runsc")" ]]
''', str(self.root))
                self.assertEqual(result.returncode, 0, result.stderr)
                installed = (self.root / 'bin/runsc').resolve().parent
                self.assertNotEqual(installed, damaged)
                self.assertTrue(os.access(installed / 'gvisor-bin/helper', os.X_OK))
                generations.extend((damaged, installed))
        self.assertTrue(all(path.exists() for path in generations))

    def test_k3s_repairs_to_recorded_version_instead_of_downgrading(self):
        (self.root / 'state').mkdir()
        (self.root / 'bin').mkdir()
        (self.root / 'state/k3s-version').write_text('v1.38.0+k3s1\n')
        (self.root / 'bin/k3s').write_text('damaged')
        expected = self.root / 'healthy'
        expected.write_text('#!/bin/sh\necho "k3s version v1.38.0+k3s1 (test)"\n')
        result = self.shell('''INSTALL_DIR="$1"
download() { printf 'checksums' > "$2"; }
verified_asset() { [[ "$1" == */v1.38.0%2Bk3s1/k3s ]] || exit 90; cp "$INSTALL_DIR/healthy" "$2"; }
install_k3s
"$INSTALL_DIR/bin/k3s" --version
''', str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('v1.38.0+k3s1', result.stdout)
        self.assertTrue((self.root / 'state/k3s-restart-required').exists())

    def test_upgrade_start_records_new_version_before_server_launch(self):
        binary = self.root / 'k3s'
        binary.write_text('#!/bin/sh\necho "k3s version v1.38.0+k3s1 (test)"\n')
        binary.chmod(0o755)
        record = self.root / 'version'
        record.write_text('v1.37.2+k3s1\n')
        result = subprocess.run(['bash', str(PROJECT / 'lib/record-version.sh'), str(binary),
                                 str(record), str(PROJECT / 'lib/recovery.sh')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record.read_text().strip(), 'v1.38.0+k3s1')


class FirewallTests(TempTest):
    def test_atomic_update_is_limited_to_owned_table(self):
        nft = self.root / 'nft'
        nft.write_text('#!/bin/sh\nif [ "$1" = list ]; then exit 0; fi\ncat > "$BATCH_OUTPUT"\n')
        nft.chmod(0o755)
        batch = self.root / 'batch'
        env = {**os.environ, 'BATCH_OUTPUT': str(batch)}
        result = subprocess.run(['bash', str(PROJECT / 'lib/firewall.sh'),
                                 str(PROJECT / 'config/firewall.nft'), str(nft)],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = batch.read_text()
        self.assertTrue(rules.startswith('delete table inet livepeer_bootstrap\n'))
        self.assertNotIn('flush ruleset', rules)
        self.assertIn('iifname "lo" accept', rules)
        self.assertIn('ip saddr 10.42.0.0/16 tcp dport 6443 accept', rules)
        self.assertIn('ct direction reply', rules)

    def test_missing_policy_does_not_change_firewall(self):
        nft = self.root / 'nft'
        nft.write_text('#!/bin/sh\ntouch "$TOUCHED"\n')
        nft.chmod(0o755)
        touched = self.root / 'touched'
        result = subprocess.run(['bash', str(PROJECT / 'lib/firewall.sh'), str(self.root / 'missing'), str(nft)],
                                capture_output=True, env={**os.environ, 'TOUCHED': str(touched)})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(touched.exists())


class StagingTests(TempTest):
    shell = ShellTests.shell

    def setUp(self):
        super().setUp()
        # Only filesystem staging runs, never installation or systemd commands.
        result = self.shell('''
INSTALL_DIR="$1"
chown() { :; }
authenticate_node
prepare_installation
stage_manifests
''', str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_paths_and_service_programs_are_staged_without_host_python(self):
        for path in (self.root / 'manifests').rglob('*.yaml'):
            self.assertNotRegex(path.read_text(), r'@[A-Z_]+@')
        self.assertFalse((self.root / 'desired').exists())
        self.assertNotIn((self.root / 'credentials/service-token').read_text(),
                         (self.root / 'manifests/bootstrap/deployments.yaml').read_text())

    def test_rerun_preserves_credentials_and_uses_hosted_config(self):
        token = (self.root / 'credentials/service-token').read_bytes()
        result = self.shell('''INSTALL_DIR="$1"
ENROLLMENT_TOKEN=''
unset LIVEPEER_API_URL
curl() { exit 91; }
authenticate_node
stage_manifests
''', str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'credentials/service-token').read_bytes(), token)
        deployment = (self.root / 'manifests/bootstrap/deployments.yaml').read_text()
        self.assertIn('http://api.example/v1/nodes/', deployment)
        self.assertNotIn('name: livepeer-config', deployment)

    def test_bootstrap_waits_for_workload_creation_before_rollout(self):
        flux = self.root / 'bin/flux'
        flux.write_text('#!/bin/sh\nprintf "kind: List\\nitems: []\\n"\n')
        flux.chmod(0o755)
        steps = self.root / 'cluster-steps'
        steps.unlink(missing_ok=True)
        result = self.shell('''INSTALL_DIR="$1"
install_machine_secret() { :; }
kube() {
  printf '%s\\n' "$*" >> "$INSTALL_DIR/cluster-steps"
  if [[ "$*" == 'get nodes -o name' ]]; then printf 'node/test-node'; fi
  if [[ "$*" == *'create secret generic'* ]]; then printf '{}'; fi
  if [[ "$*" == 'apply -f -' ]]; then cat >/dev/null; fi
}
bootstrap_cluster
''', str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = steps.read_text().splitlines()
        for namespace, name in (('system-upgrade', 'system-upgrade-controller'), ('livepeer', 'orchestrator')):
            creation = f'-n {namespace} wait --for=create deployment/{name} --timeout=300s'
            rollout = f'-n {namespace} rollout status deployment/{name} --timeout=300s'
            self.assertLess(calls.index(creation), calls.index(rollout))

    def test_failed_firewall_activation_stops_k3s(self):
        result = self.shell('''INSTALL_DIR="$1"
authenticate_node
atomic_symlink() { :; }
systemctl() {
  case "$*" in
    'start livepeer-firewall.service') return 1 ;;
    'stop livepeer-k3s.service') printf 'stopped' > "$INSTALL_DIR/stopped" ;;
  esac
}
write_host_configuration
''', str(self.root))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'stopped').read_text(), 'stopped')
        self.assertIn('firewall enforcement failed', result.stderr)

    @unittest.skipUnless(shutil.which('kubectl') and yaml, 'kubectl and PyYAML needed for manifest validation')
    def test_kustomize_uses_pinned_go_adapter_and_independent_management(self):
        result = subprocess.run(['kubectl', 'kustomize', str(self.root / 'manifests/bootstrap')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        resources = list(yaml.safe_load_all(result.stdout))
        deployment = next(r for r in resources if r['kind'] == 'Deployment')
        container = deployment['spec']['template']['spec']['containers'][0]
        self.assertEqual(container['command'], ['/usr/local/bin/livepeer-runtime', 'http-source'])
        self.assertRegex(container['image'], r'@sha256:[0-9a-f]{64}$')
        self.assertNotIn('python', str(deployment))
        management = next(r for r in resources if r['kind'] == 'Kustomization')
        self.assertFalse(management['spec']['wait'])
        self.assertNotIn('dependsOn', management['spec'])


if __name__ == '__main__':
    unittest.main()
