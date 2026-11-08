"""Portable protected-delivery tests; no Cloudflare account or host installation."""
import contextlib
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services'))
import control_client
import http_source
import tunnel_broker
import tunnel_launcher
from test_bootstrap import archive_bytes

NODE = 'lp-aaaaaaaaaaaaaaaa'
EPOCH = '11111111-1111-4111-8111-111111111111'
MACHINE_TOKEN = 'a' * 64


class ProtectedDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('openssl required for local verified-TLS fixture')
        cls.cert_dir = tempfile.TemporaryDirectory()
        root = Path(cls.cert_dir.name)
        (root / 'openssl.cnf').write_text('''[req]
prompt=no
distinguished_name=dn
x509_extensions=extensions
[dn]
CN=localhost
[extensions]
subjectAltName=IP:127.0.0.1,DNS:localhost
basicConstraints=critical,CA:TRUE
''')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-config', str(root / 'openssl.cnf')], check=True, capture_output=True)
        cls.cert = root / 'cert.pem'
        cls.key = root / 'key.pem'

    @classmethod
    def tearDownClass(cls):
        cls.cert_dir.cleanup()

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(mock.patch.dict(os.environ, {'SSL_CERT_FILE': str(self.cert)}))
        self.machine_file = self.root / 'machine'
        self.machine_file.write_text(MACHINE_TOKEN)
        self.grants = 0
        self.fail = False
        self.redirect = None
        self.live_enabled = False
        self.observed = []
        self.version = 1
        self.bundle = b''
        self.desired = {'node_id': NODE, 'epoch': EPOCH, 'credential_version': 1, 'generation': 1,
                        'tunnel_id': 'tunnel-uuid', 'credential_generation': 1,
                        'terminal': False, 'service_url': 'https://public.example.invalid', 'config_digest': 'b' * 64}
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                if self.headers.get('Authorization') != 'Bearer ' + MACHINE_TOKEN:
                    self.send_error(401)
                    return
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                test.observed.append((self.path, json.loads(body) if body else None))
                if test.redirect:
                    self.send_response(302)
                    self.send_header('Location', test.redirect)
                    self.end_headers()
                    return
                if test.fail:
                    self.send_response(503)
                    self.end_headers()
                    self.wfile.write(b'private-provider-failure-body')
                    return
                result = b'{}'
                if self.path.endswith('/config'):
                    result = test.bundle
                elif self.path.endswith('/tunnel/connector-token'):
                    test.grants += 1
                    result = json.dumps({'token': 'opaque-current-tunnel-token-' + str(test.version),
                                         'epoch': EPOCH, 'tunnel_id': 'tunnel-uuid', 'credential_generation': test.version}).encode()
                self.send_response(200)
                self.send_header('X-Livepeer-Epoch', test.desired['epoch'])
                self.send_header('X-Livepeer-Credential-Version', str(test.desired['credential_version']))
                if test.live_enabled:
                    self.send_header('X-Livepeer-Tunnels-Enabled', 'true')
                self.end_headers()
                self.wfile.write(result)

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.cert, self.key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(timeout=2)))
        self.url = f'https://127.0.0.1:{server.server_port}/v1/nodes/{NODE}/config'
        self.url_file = self.root / 'config-url'
        self.url_file.write_text(self.url)
        self.config = self.root / 'routing.json'
        self.save_desired()

    def save_desired(self):
        self.config.write_text(json.dumps(self.desired))
        self.bundle = archive_bytes([('kustomization.yaml', tarfile.REGTYPE, b'resources: []\n'),
                                     ('runtime.json', tarfile.REGTYPE, json.dumps(self.desired).encode())])

    def broker(self):
        broker = tunnel_broker.Broker(self.config, self.machine_file, self.url_file)
        path = self.root / 'broker' / 'token.sock'
        server = tunnel_broker.serve(broker, path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(timeout=2)))
        return broker, path

    def test_fresh_token_every_process_start_and_no_fallback(self):
        broker, sock = self.broker()
        path = self.root / 'volatile' / 'token'
        path.parent.mkdir()
        (path.parent / '.token-interrupted').write_text('interrupted-write')
        for version in (1, 2):
            self.version = version
            self.desired['credential_generation'] = version
            self.save_desired()
            expected = hashlib.sha256(('opaque-current-tunnel-token-' + str(version)).encode()).hexdigest()
            code = "import hashlib,pathlib,stat,sys; p=pathlib.Path(sys.argv[1]); assert stat.S_IMODE(p.stat().st_mode)==0o600; assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2]"
            self.assertEqual(tunnel_launcher.run_once(sock, path, [sys.executable, '-c', code, str(path), expected]), 0)
            self.assertFalse(path.exists())
            self.assertEqual(list(path.parent.iterdir()), [])
        self.assertEqual(self.grants, 2)
        self.assertEqual(broker.granted['credential_generation'], 2)
        path.write_text('stale-tunnel-token')
        self.fail = True
        with mock.patch.object(tunnel_launcher.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError):
                tunnel_launcher.run_once(sock, path)
            spawn.assert_not_called()
        self.assertFalse(path.exists())

    def test_redirects_and_arbitrary_endpoints_never_receive_credential(self):
        self.redirect = 'https://127.0.0.1:1/credential-capture'
        client = control_client.ControlClient(self.url, self.machine_file)
        with self.assertRaises(urllib.error.HTTPError) as error:
            client.request('tunnel/connector-token')
        self.assertEqual(error.exception.code, 302)
        self.assertEqual(len(self.observed), 1)
        with self.assertRaises(ValueError):
            client.request('https://other.example.invalid/steal')
        self.assertEqual(len(self.observed), 1)
        with self.assertRaises(ValueError):
            control_client.ControlClient(self.url.replace('https:', 'http:'), self.machine_file)

    def test_development_profile_cannot_enable_tunnels_over_https(self):
        self.live_enabled = True
        client = control_client.ControlClient(self.url, self.machine_file, allow_http=True)
        with self.assertRaises(ValueError):
            client.request('config')

    def test_broker_restart_restarts_connector_and_fetches_again(self):
        broker, sock = self.broker()
        token = self.root / 'volatile' / 'token'
        child = mock.Mock()

        def restarted(timeout=None):
            broker.instance = 'f' * 32
            broker.granted = None
            raise subprocess.TimeoutExpired('cloudflared', timeout)

        waits = iter((restarted, lambda timeout=None: 0))
        child.wait.side_effect = lambda timeout=None: next(waits)(timeout)
        with mock.patch.object(tunnel_launcher.subprocess, 'Popen', return_value=child):
            self.assertEqual(tunnel_launcher.run_once(sock, token), 75)
        child.terminate.assert_called_once()
        self.assertFalse(token.exists())
        self.assertIsNone(broker.granted)
        with mock.patch.object(tunnel_launcher.subprocess, 'Popen') as spawn:
            spawn.return_value.wait.return_value = 0
            self.assertEqual(tunnel_launcher.run_once(sock, token), 0)
        self.assertEqual(self.grants, 2)
        self.assertEqual(broker.granted['credential_generation'], 1)

    def test_unavailable_broker_preserves_running_connector(self):
        _, sock = self.broker()
        token = self.root / 'volatile' / 'token'
        original = tunnel_launcher.request
        def request(path, command):
            if command == b'identity\n':
                raise ConnectionError('broker unavailable')
            return original(path, command)
        with mock.patch.object(tunnel_launcher, 'request', side_effect=request), mock.patch.object(tunnel_launcher.subprocess, 'Popen') as spawn:
            spawn.return_value.wait.side_effect = [subprocess.TimeoutExpired('cloudflared', 5), 0]
            self.assertEqual(tunnel_launcher.run_once(sock, token), 0)
            spawn.return_value.terminate.assert_not_called()
        self.assertFalse(token.exists())

    def test_broker_rejects_stale_epoch_and_generation(self):
        broker, _ = self.broker()
        self.desired['epoch'] = '22222222-2222-4222-8222-222222222222'
        self.save_desired()
        with self.assertRaises(ValueError):
            broker.grant()
        self.desired['epoch'] = EPOCH
        self.desired['credential_generation'] = 2
        self.save_desired()
        with self.assertRaises(ValueError):
            broker.grant()

    def test_rollout_report_requires_running_pod_digest(self):
        fixture = self
        class Kube:
            pod_digest = 'outdated'
            def request(self, path):
                if '/kustomizations/' in path:
                    return {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
                            'lastAppliedRevision': 'sha256:' + 'a' * 64, 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                if '/pods?' in path:
                    return {'items': [{'metadata': {'annotations': {'livepeer.io/config-sha256': self.pod_digest}},
                                       'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}]}
                if '/deployments/' in path:
                    return {'metadata': {'generation': 1}, 'spec': {'template': {'metadata': {'annotations': {
                            'livepeer.io/config-sha256': fixture.desired['config_digest']}}}},
                            'status': {'observedGeneration': 1, 'updatedReplicas': 1, 'readyReplicas': 1, 'availableReplicas': 1}}
                raise AssertionError(path)
        class Origin:
            def open(self, url, **kwargs):
                response = io.BytesIO(json.dumps([{'address': fixture.desired['service_url']}]).encode())
                response.status = 200
                return response
        kube = Kube()
        adapter = http_source.Adapter(self.url, self.machine_file, self.root, 'http://artifacts.internal', kube)
        client = control_client.ControlClient(self.url, self.machine_file)
        with mock.patch.object(http_source.urllib.request, 'build_opener', return_value=Origin()):
            adapter.report(client, self.desired, 'sha256:' + 'a' * 64)
            self.assertFalse(self.observed[-1][1]['ready'])
            kube.pod_digest = self.desired['config_digest']
            adapter.report(client, self.desired, 'sha256:' + 'a' * 64)
            self.assertTrue(self.observed[-1][1]['ready'])
    def test_terminal_bundle_is_explicit_and_cannot_reactivate(self):
        class Kube:
            artifact = None

            def publish(self, artifact, *args):
                if artifact:
                    self.artifact = artifact

            def request(self, path, payload=None):
                if '/kustomizations/' in path:
                    return {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
                            'lastAppliedRevision': self.artifact['digest'], 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                if '/pods?' in path:
                    return {'items': []}
                raise urllib.error.HTTPError(path, 404, 'absent', {}, None)

        directory = self.root / 'artifacts'
        directory.mkdir()
        identity = self.root / 'identity.json'
        identity.write_text(json.dumps({'epoch': EPOCH, 'credential_version': '1'}))
        kube = Kube()
        adapter = http_source.Adapter(self.url, self.machine_file, directory, 'http://artifacts.internal', kube, identity_file=identity)
        def sync():
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return adapter.sync_once()
        self.assertTrue(sync())
        previous = kube.artifact.copy()
        self.fail = True
        self.assertFalse(sync())
        self.assertEqual(previous, kube.artifact)
        self.assertFalse(any(path.endswith('/removal-ack') for path, _ in self.observed))
        self.fail = False
        self.desired['terminal'] = True
        self.save_desired()
        self.assertTrue(sync())
        terminal = kube.artifact.copy()
        acknowledgements = [body for path, body in self.observed if path.endswith('/removal-ack')]
        self.assertEqual(acknowledgements[-1]['epoch'], EPOCH)
        self.assertEqual(acknowledgements[-1]['digest'], terminal['digest'].split(':')[1])
        self.desired['terminal'] = False
        self.save_desired()
        self.assertFalse(sync())
        self.assertEqual(kube.artifact, terminal)

        self.desired['epoch'] = '22222222-2222-4222-8222-222222222222'
        self.save_desired()
        self.assertFalse(sync())
        self.assertEqual(kube.artifact, terminal)

    def test_legacy_identity_can_fetch_only_version_zero(self):
        class Kube:
            def publish(self, *args):
                pass
        directory = self.root / 'artifacts'
        directory.mkdir()
        identity = self.root / 'identity.json'
        identity.write_text(json.dumps({'epoch': '', 'credential_version': '0'}))
        adapter = http_source.Adapter(self.url, self.machine_file, directory,
                                     'http://artifacts.internal', Kube(), identity_file=identity)
        self.desired['credential_version'] = 0
        self.save_desired()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(adapter.sync_once())
            self.desired['credential_version'] = 1
            self.save_desired()
            self.assertFalse(adapter.sync_once())
            self.desired['credential_version'] = 0
            self.desired['epoch'] = '22222222-2222-4222-8222-222222222222'
            self.save_desired()
            self.assertFalse(adapter.sync_once())

    def test_app_assignment_validation_preserves_artifact_and_watermark(self):
        class Kube:
            artifact = None
            def publish(self, artifact, *args):
                if artifact:
                    self.artifact = artifact
        directory = self.root / 'app-artifacts'
        directory.mkdir()
        kube = Kube()
        adapter = http_source.Adapter(self.url, self.machine_file, directory, 'http://artifacts.internal', kube)
        def make_archive(files):
            return archive_bytes([(name, tarfile.REGTYPE, data) for name, data in files.items()])
        def bundle(generation, entries=None):
            data = json.dumps({'schema_version': 1, 'node_id': NODE, 'epoch': EPOCH,
                               'apps_generation': generation, 'entries': entries or []}, separators=(',', ':'))
            digest = 'sha256:' + hashlib.sha256(data.encode()).hexdigest()
            self.desired.update(apps_generation=generation, apps_digest=digest)
            manifest = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
                'name': 'livepeer-app-assignments', 'namespace': 'livepeer',
                'annotations': {'livepeer.io/apps-sha256': digest}}, 'data': {'desired.json': data}}
            self.bundle = make_archive({'kustomization.yaml': b'resources: [app-assignments.json]\n',
                'runtime.json': json.dumps(self.desired).encode(), 'app-assignments.json': json.dumps(manifest).encode()})
        def sync():
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return adapter.sync_once()
        bundle(2)
        self.assertTrue(sync())
        previous, watermark = kube.artifact.copy(), (directory / 'enrollment.json').read_bytes()
        bundle(1)
        self.assertFalse(sync())
        self.assertEqual(kube.artifact, previous)
        self.assertEqual((directory / 'enrollment.json').read_bytes(), watermark)
        bundle(3)
        self.desired['apps_digest'] = 'sha256:' + '0' * 64
        # The body has mismatching Runtime metadata and manifest digest.
        with tarfile.open(fileobj=io.BytesIO(self.bundle), mode='r:gz') as archive:
            manifest = archive.extractfile('app-assignments.json').read()
        self.bundle = make_archive({'kustomization.yaml': b'resources: []\n',
            'runtime.json': json.dumps(self.desired).encode(), 'app-assignments.json': manifest})
        self.assertFalse(sync())
        self.assertEqual(kube.artifact, previous)
        self.assertEqual((directory / 'enrollment.json').read_bytes(), watermark)
        self.desired.pop('apps_generation'); self.desired.pop('apps_digest')
        self.save_desired()
        self.assertFalse(sync())
        bundle(3)
        self.assertTrue(sync())
        self.assertEqual(json.loads((directory / 'enrollment.json').read_bytes())['apps_generation'], 3)

    def test_app_status_client_path_is_scoped(self):
        client = control_client.ControlClient(self.url, self.machine_file)
        client.request('apps/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/status', {'phase': 'removed'})
        for endpoint in ['apps/../status', 'apps/x/status', 'apps/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/status/other']:
            with self.assertRaises(ValueError):
                client.request(endpoint, {})

    def test_app_only_update_keeps_confirmed_infrastructure_ready(self):
        old_metadata = dict(self.desired)
        new_metadata = dict(self.desired, apps_generation=1, apps_digest='sha256:' + 'c' * 64)
        def cached(metadata, node=b'unchanged node', routing=b'unchanged protection'):
            root = b'resources:\n- orchestrator.yaml\n- tunnel.yaml\n'
            files = [('orchestrator.yaml', tarfile.REGTYPE, node), ('tunnel.yaml', tarfile.REGTYPE, routing),
                     ('runtime.json', tarfile.REGTYPE, json.dumps(metadata).encode())]
            if metadata.get('apps_generation'):
                root += b'- app-assignments.json\n'
                files.append(('app-assignments.json', tarfile.REGTYPE, b'{}'))
            data = archive_bytes([('kustomization.yaml', tarfile.REGTYPE, root)] + files)
            digest = hashlib.sha256(data).hexdigest()
            (self.root / (digest + '.tar.gz')).write_bytes(data)
            return 'sha256:' + digest
        previous, current = cached(old_metadata), cached(new_metadata)
        fixture = self
        class Kube:
            def request(self, path):
                if '/kustomizations/' in path:
                    return {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1,
                        'lastAppliedRevision': previous, 'conditions': [{'type': 'Ready', 'status': 'False'}]}}
                if '/pods?' in path:
                    return {'items': [{'metadata': {'annotations': {'livepeer.io/config-sha256': fixture.desired['config_digest']}},
                                       'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}]}
                if '/deployments/' in path:
                    return {'metadata': {'generation': 1}, 'spec': {'template': {'metadata': {'annotations': {
                        'livepeer.io/config-sha256': fixture.desired['config_digest']}}}},
                        'status': {'observedGeneration': 1, 'updatedReplicas': 1, 'readyReplicas': 1, 'availableReplicas': 1}}
                raise AssertionError(path)
        class Origin:
            def open(self, url, **kwargs):
                response = io.BytesIO(json.dumps([{'address': fixture.desired['service_url']}]).encode())
                response.status = 200
                return response
        adapter = http_source.Adapter(self.url, self.machine_file, self.root, 'http://artifacts.internal', Kube())
        client = control_client.ControlClient(self.url, self.machine_file)
        with mock.patch.object(http_source.urllib.request, 'build_opener', return_value=Origin()):
            adapter.report(client, new_metadata, current)
            self.assertTrue(self.observed[-1][1]['ready'])
            self.assertEqual(self.observed[-1][1]['bundle_sha256'], previous.split(':')[1])
            for changed in [cached(new_metadata, node=b'changed node'),
                            cached(new_metadata, routing=b'changed protection')]:
                adapter.report(client, new_metadata, changed)
                self.assertFalse(self.observed[-1][1]['ready'])
            (self.root / (previous.split(':')[1] + '.tar.gz')).write_bytes(b'corrupt cache')
            adapter.report(client, new_metadata, current)
            self.assertFalse(self.observed[-1][1]['ready'])


if __name__ == '__main__':
    unittest.main()
