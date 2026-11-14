"""Host-safe upgrade tests: no real Docker commands or deployment access."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('upgrade_node', ROOT / 'tools/upgrade-node.py')
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
VERSION = 'v1.0.7'
COMMIT = 'a' * 40
NODE = upgrade.UPSTREAM + '@sha256:' + 'b' * 64
RUNTIME = 'registry.example/runtime@sha256:' + 'c' * 64
OLD = upgrade.PUBLIC + '@sha256:' + 'd' * 64
NEW = upgrade.PUBLIC + '@sha256:' + 'e' * 64


class Response:
    status = 200

    def __init__(self, data=b''):
        self.data = data

    def read(self, _limit=-1):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeDocker:
    def __init__(self, deploy):
        self.deploy, self.calls = deploy, []
        self.api_id = 'old-api'
        self.mounted = (deploy / 'config.toml').read_bytes()
        self.reported = None
        self.revision = COMMIT
        self.image_revision = COMMIT
        self.extra_mounts = {}
        self.on_recreate = None
        self.model = {'name': 'controlcenter', 'services': {'api': {'image': 'api:staging', 'volumes': [
            {'type': 'bind', 'source': str(deploy / 'config.toml'), 'target': '/etc/controlcenter/config.toml', 'read_only': True}]}}}
        self.api = {'Id': self.api_id, 'Image': 'sha256:api',
                    'Config': {'Entrypoint': ['controlcenter'],
                               'Cmd': ['serve', '--config', '/etc/controlcenter/config.toml'],
                               'Env': ['PATH=/bin'],
                               'Labels': {'com.docker.compose.project': 'controlcenter',
                                          'com.docker.compose.project.working_dir': str(deploy),
                                          'com.docker.compose.project.config_files': str(deploy / 'compose.yaml'),
                                          'com.docker.compose.config-hash': 'config-hash'}},
                    'Mounts': [{'Source': str(deploy / 'config.toml'), 'Destination': '/etc/controlcenter/config.toml', 'RW': False, 'Type': 'bind'}],
                    'State': {'Health': {'Status': 'healthy'}, 'StartedAt': self.started_at()}}
        self.built = {'Id': 'sha256:built', 'Os': 'linux', 'Architecture': 'amd64',
                      'Config': {'User': '65532:65532', 'Entrypoint': ['/usr/local/bin/livepeer'],
                                 'Labels': {'io.livepeer.node.image': NODE,
                                            'org.opencontainers.image.revision': COMMIT}}}

    def started_at(self):
        info = (self.deploy / 'config.toml').stat()
        return datetime.fromtimestamp(max(info.st_mtime, info.st_ctime) + 1, timezone.utc).isoformat()

    def __call__(self, *args, **kwargs):
        args = [str(arg) for arg in args]
        self.calls.append(args)
        if args[:4] == ['go', 'mod', 'edit', '-json']:
            return json.dumps({'Require': [{'Path': upgrade.MODULE, 'Version': VERSION}]})
        if args[:3] == ['git', 'status', '--porcelain']:
            return ''
        if args[:3] == ['git', 'rev-parse', 'HEAD'] or args[:2] == ['gh', 'api']:
            return COMMIT
        if args[:3] == ['docker', 'context', 'inspect']:
            return json.dumps([{'Name': 'default', 'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}])
        if args[:2] == ['docker', 'info']:
            return json.dumps({'OSType': 'linux', 'Architecture': 'x86_64'})
        if args[:4] == ['docker', 'buildx', 'imagetools', 'inspect']:
            ref = args[4]
            is_node = ref.startswith(upgrade.UPSTREAM)
            if args[-1] == '{{json .Manifest}}':
                return json.dumps({'digest': (NODE if is_node else RUNTIME).split('@')[1]})
            return json.dumps({'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': {
                'org.opencontainers.image.source': 'https://github.com/livepeer/node',
                'org.opencontainers.image.version': VERSION, 'org.opencontainers.image.revision': COMMIT}}})
        if args[:2] == ['docker', 'compose']:
            if args[-3:] == ['config', '--format', 'json']:
                return json.dumps(self.model)
            if args[-3:] == ['config', '--hash', 'api']:
                return 'api config-hash'
            if args[-3:-1] == ['ps', '--quiet']:
                return self.api_id if args[-1] == 'api' else args[-1]
            if 'up' in args:
                if self.on_recreate:
                    self.on_recreate()
                self.api_id += '-new'
                self.mounted = (self.deploy / 'config.toml').read_bytes()
                self.api['State']['StartedAt'] = self.started_at()
                return ''
        if args[:3] == ['docker', 'container', 'inspect']:
            if args[-1] == self.api_id:
                return json.dumps([{**self.api, 'Id': self.api_id}])
            if args[-1] == 'redeemer':
                return json.dumps([{'Id': 'redeemer', 'Image': 'sha256:redeemer', 'Config': {'Image': NODE}}])
            return json.dumps([{'Id': 'registry'}])
        if args[:3] == ['docker', 'image', 'inspect']:
            if args[-1] == 'api:staging':
                return json.dumps([{'Id': 'sha256:api', 'Config': {'Labels': {'org.opencontainers.image.revision': self.image_revision}}}])
            if args[-1] in (NODE, 'sha256:redeemer'):
                return json.dumps([{'Id': 'sha256:redeemer', 'Config': {'Labels': {
                    'org.opencontainers.image.revision': COMMIT, 'org.opencontainers.image.version': VERSION}}}])
            return json.dumps([self.built])
        if args[:2] == ['docker', 'exec']:
            if args[3] == 'sha256sum':
                data = self.mounted if args[-1] == '/etc/controlcenter/config.toml' else self.extra_mounts[args[-1]]
                return upgrade.sha(data) + '  ' + args[-1]
        if args[:3] == ['docker', 'buildx', 'build']:
            for value in args:
                if value.startswith('io.livepeer.node.inputs='):
                    self.built['Config']['Labels']['io.livepeer.node.inputs'] = value.split('=', 1)[1]
            return ''
        if args[:2] == ['docker', 'run']:
            return f'livepeer {VERSION} ({COMMIT})'
        if args[:2] in (['docker', 'pull'], ['docker', 'push']):
            return ''
        raise AssertionError('unexpected fake command: ' + repr(args))


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.deploy = self.root / 'deploy'
        self.deploy.mkdir()
        self.config = (f'# private settings\nRuntimeImage = "{RUNTIME}"\n'
                       f"RuntimeNodeImage = '{OLD}' # retain comment\nSecret = 'private-value'\n").encode()
        self.record = {'images': {'RuntimeImage': RUNTIME, 'RuntimeNodeImage': OLD},
                       'controlcenter_commit': 'runtime-build', 'source_note': 'old build note',
                       'node_commit': 'old-node', 'node_source_archive_sha256': 'old-archive',
                       'unrelated': {'retain': True}}
        (self.deploy / 'config.toml').write_bytes(self.config)
        (self.deploy / 'config.toml').chmod(0o640)
        (self.deploy / 'staging-images.json').write_bytes(upgrade.encoded(self.record))
        for name in (upgrade.FALLBACK, upgrade.RECIPE, upgrade.RECIPE + '.dockerignore'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('recipe')
        (self.root / upgrade.FALLBACK).write_text(f'image: ghcr.io/livepeer/node:{VERSION}@{NODE.split("@")[1]}\n')
        self.docker = FakeDocker(self.deploy)
        self.token_file = self.root / 'admin-token'
        self.token_file.write_text('private.admin.token')
        self.token_file.chmod(0o600)
        self.job = upgrade.Upgrade(self.root, self.deploy, runner=self.docker, token_file=self.token_file)
        def http(request, **_kwargs):
            if isinstance(request, upgrade.Request) and request.full_url.endswith('/api/admin/deployment'):
                value = self.docker.reported if self.docker.reported is not None else tomllib.loads(self.docker.mounted.decode()).get('RuntimeNodeImage', '')
                return Response(upgrade.encoded({'revision': self.docker.revision, 'runtime_node_image': value}))
            return Response()
        self.http_response = http
        self.http = patch.object(upgrade, 'urlopen', side_effect=http)
        self.http_mock = self.http.start()
        self.addCleanup(self.http.stop)
        self.local_http_mock = Mock(side_effect=http)
        opener = patch.object(upgrade, 'build_opener', return_value=SimpleNamespace(open=self.local_http_mock))
        self.opener_mock = opener.start()
        self.addCleanup(opener.stop)
        self.environment = patch.dict(os.environ, {'DOCKER_HOST': ''})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.job.preflight()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)

    def test_patch_preserves_unrelated_bytes_and_toml(self):
        for newline in (b'\n', b'\r\n'):
            data = self.config.replace(b'\n', newline)
            candidate = upgrade.patch_config(data, NEW)
            self.assertEqual(candidate, data.replace(("'" + OLD + "'").encode(), json.dumps(NEW).encode()))
        data = b"Secret = 'private-value'\n[other]\nRuntimeNodeImage = 'table-value'\n"
        result = upgrade.patch_config(data, NEW)
        self.assertTrue(result.endswith(data))
        self.assertEqual(tomllib.loads(result.decode())['other']['RuntimeNodeImage'], 'table-value')

    def test_unsupported_toml_cannot_change_private_values(self):
        for data in (b'RuntimeNodeImage = 123\n', b'"RuntimeNodeImage" = "old"\n',
                     b'RuntimeNodeImage = """old"""\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                upgrade.patch_config(data, NEW)
        with self.assertRaises(ValueError):
            upgrade.patch_config(self.config, 'node:latest')

    def test_source_rejects_unreleased_replaced_or_misaligned_versions(self):
        for version, replacement in (('v1.0.8-0.20260101000000-abcdef123456', False),
                                     ('v1.0.8', False), (VERSION, True)):
            value = {'Require': [{'Path': upgrade.MODULE, 'Version': version}]}
            if replacement:
                value['Replace'] = [{'Old': {'Path': upgrade.MODULE}}]
            with self.subTest(version=version, replacement=replacement), self.assertRaises(ValueError):
                upgrade.source_version(self.root, lambda *a, **kw: json.dumps(value))

    def test_atomic_write_preserves_mode_owner_and_rejects_changed_or_symlink_input(self):
        path = self.deploy / 'config.toml'
        snapshot = upgrade.Snapshot.read(path)
        snapshot.write(upgrade.patch_config(snapshot.data, NEW))
        actual = upgrade.Snapshot.read(path)
        self.assertEqual((actual.mode, actual.uid, actual.gid), (snapshot.mode, snapshot.uid, snapshot.gid))
        with self.assertRaises(ValueError):
            snapshot.write(b'overwrite')
        link = self.root / 'symlink'
        link.symlink_to(path)
        with self.assertRaises(OSError):
            upgrade.Snapshot.read(link)

    def test_activation_updates_only_node_records_and_recreates_only_api(self):
        result = self.job.activate(NEW, {'node_version': VERSION}, self.state)
        self.assertEqual(self.http_mock.call_args.args[0], 'http://127.0.0.1:43812/readyz')
        self.assertEqual(result['status'], 'api_loaded')
        self.assertEqual(tomllib.loads((self.deploy / 'config.toml').read_text())['RuntimeNodeImage'], NEW)
        record = json.loads((self.deploy / 'staging-images.json').read_bytes())
        self.assertEqual(record['controlcenter_commit'], 'runtime-build')
        self.assertEqual(record['source_note'], self.record['source_note'])
        self.assertEqual(record['unrelated'], self.record['unrelated'])
        self.assertEqual(record['legacy_build']['node_commit'], 'old-node')
        self.assertNotIn('node_source_archive_sha256', record)
        calls = [args for args in self.docker.calls if 'up' in args]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-len(self.job.recreate_args()):], self.job.recreate_args())
        directory = Path(result['recovery_directory'])
        self.assertEqual((directory / 'config.toml').read_bytes(), self.config)
        self.assertEqual((directory / 'config.toml').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((directory / 'receipt.json').read_bytes())['phase'], 'api_loaded')
        self.assertNotIn('private.admin.token', json.dumps(self.docker.calls))
        self.assertNotIn('private.admin.token', (directory / 'receipt.json').read_text())
        requests = [call.args[0] for call in self.local_http_mock.call_args_list]
        self.assertTrue(requests)
        self.assertTrue(all(request.get_header('Authorization') == 'Bearer private.admin.token' for request in requests))

    def test_loaded_target_rerun_does_not_recreate_api(self):
        provenance = {'node_version': VERSION}
        self.job.activate(NEW, provenance, self.state)
        self.job.preflight()
        self.docker.calls.clear()
        result = self.job.activate(NEW, provenance, self.state)
        self.assertEqual(result['status'], 'already_loaded')
        self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_stale_loaded_setting_blocks_activation(self):
        provenance = {'node_version': VERSION}
        self.job.activate(NEW, provenance, self.state)
        self.job.preflight()
        self.docker.reported = OLD
        with self.assertRaisesRegex(ValueError, 'has not loaded'):
            self.job.activate(NEW, provenance, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), upgrade.patch_config(self.config, NEW))

    def test_pending_atomic_or_in_place_config_edits_block_preflight(self):
        changed = self.config + b'Unrelated = true\n'
        (self.deploy / 'config.toml').write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'mounted config differs'):
            self.job.preflight()
        self.docker.mounted = changed  # In-place edits are visible through the bind mount.
        self.docker.api['State']['StartedAt'] = '2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'changed after API startup'):
            self.job.preflight()
        self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_provenance_only_update_keeps_single_quotes_and_does_not_restart(self):
        self.job.activate(NEW, {'old_metadata': True}, self.state)
        # Start a fixture with an already-loaded single-quoted target.
        data = self.config.replace(OLD.encode(), NEW.encode())
        (self.deploy / 'config.toml').write_bytes(data)
        self.docker = FakeDocker(self.deploy)
        self.job = upgrade.Upgrade(self.root, self.deploy, runner=self.docker, token_file=self.token_file)
        self.job.preflight()
        result = self.job.activate(NEW, {'corrected_metadata': True}, self.state)
        self.assertEqual(result['status'], 'already_loaded')
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), data)
        self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_secret_source_drift_is_detected_even_when_service_hash_matches(self):
        self.job.model['secrets'] = {'webhook': {'file': '/private/new-secret'}}
        self.job.model['services']['api']['secrets'] = [{'source': 'webhook'}]
        self.docker.api['Mounts'].append({'Destination': '/run/secrets/webhook', 'Source': '/private/old-secret', 'Type': 'bind', 'RW': False})
        with self.assertRaisesRegex(ValueError, 'sources changed'):
            self.job.check_api(self.docker.api)
        self.docker.api['Mounts'][-1]['Source'] = '/private/new-secret'
        self.job.check_api(self.docker.api)

    def test_pending_secret_contents_and_atomic_replacements_block_activation(self):
        path = self.root / 'webhook-secret'
        path.write_bytes(b'original-secret')
        self.job.model['secrets'] = {'webhook': {'file': str(path)}}
        self.job.model['services']['api']['secrets'] = [{'source': 'webhook', 'target': None}]
        target = '/run/secrets/webhook'
        self.docker.api['Mounts'].append({'Destination': target, 'Source': str(path), 'Type': 'bind', 'RW': False})
        self.docker.extra_mounts[target] = b'original-secret'
        self.job.check_api(self.docker.api)
        self.job.check_loaded_config(self.docker.api)
        path.write_bytes(b'pending-secret')
        started = max(path.stat().st_ctime, self.job.config.path.stat().st_ctime) + 10
        self.docker.api['State']['StartedAt'] = datetime.fromtimestamp(started, timezone.utc).isoformat()
        os.utime(path, (started + 10, started + 10))
        self.docker.extra_mounts[target] = b'pending-secret'  # In-place edit: matching mounted bytes.
        with self.assertRaisesRegex(ValueError, 'changed after API startup'):
            self.job.check_loaded_config(self.docker.api)
        # Even if timestamp comparison permits it, a replaced bind source must
        # still agree with what is mounted. Neither content nor hashes are logged.
        os.utime(path, (started - 1, started - 1))
        self.docker.extra_mounts[target] = b'original-secret'  # Atomic replacement: old mount remains.
        with self.assertRaisesRegex(ValueError, 'startup file differs'):
            self.job.check_loaded_config(self.docker.api)

    def test_partial_file_failure_restores_before_restart(self):
        original = upgrade.atomic_write
        def fail_record(path, *args, **kwargs):
            if path == self.job.record.path:
                raise OSError('injected failure')
            return original(path, *args, **kwargs)
        with patch.object(upgrade, 'atomic_write', side_effect=fail_record), self.assertRaises(OSError):
            self.job.activate(NEW, {}, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), self.config)
        self.assertEqual(json.loads((self.deploy / 'staging-images.json').read_bytes()), self.record)
        self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_restoration_conflict_preserves_edit_and_restores_other_file(self):
        original = upgrade.Snapshot.write
        changed_record = b'{"concurrent_edit":true}\n'
        def conflict(snapshot, data):
            if snapshot.path == self.job.record.path:
                snapshot.path.write_bytes(changed_record)
            return original(snapshot, data)
        with patch.object(upgrade.Snapshot, 'write', new=conflict), self.assertRaises(ValueError):
            self.job.activate(NEW, {}, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), self.config)
        self.assertEqual((self.deploy / 'staging-images.json').read_bytes(), changed_record)
        receipt = next(self.state.glob('*/receipt.json'))
        self.assertEqual(json.loads(receipt.read_bytes())['phase'], 'restore_incomplete')

    def test_startup_failure_does_not_automatically_restore_previous_target(self):
        def fail():
            raise subprocess.TimeoutExpired('compose', 240)
        self.docker.on_recreate = fail
        with self.assertRaises(subprocess.TimeoutExpired):
            self.job.activate(NEW, {}, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), upgrade.patch_config(self.config, NEW))
        receipt = next(self.state.glob('*/receipt.json'))
        self.assertEqual(json.loads(receipt.read_bytes())['phase'], 'api_start_requested')

    def test_concurrent_edit_is_not_overwritten(self):
        changed = self.config + b'AnotherSetting = true\n'
        (self.deploy / 'config.toml').write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'changed during'):
            self.job.activate(NEW, {}, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), changed)
        self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_api_drift_missing_readiness_field_and_overrides_block_activation(self):
        for edit in ('override', 'stack', 'entrypoint', 'unhealthy', 'image'):
            api = copy.deepcopy(self.docker.api)
            if edit == 'override':
                api['Config']['Env'].append('RUNTIME_NODE_IMAGE=' + NEW)
            elif edit == 'stack':
                api['Config']['Labels']['com.docker.compose.project.config_files'] += ',missing-overlay.yaml'
            elif edit == 'entrypoint':
                api['Config']['Cmd'].append('--runtime-node-image=' + NEW)
            elif edit == 'unhealthy':
                api['State']['Health']['Status'] = 'unhealthy'
            else:
                api['Image'] = 'sha256:other'
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.job.check_api(api)
        with patch.object(self.opener_mock.return_value, 'open', return_value=Response(b'{}')), self.assertRaisesRegex(ValueError, 'must expose'):
            self.job.deployment()

    def test_deployment_auth_and_installed_revision_are_required_before_publish(self):
        self.docker.revision = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'build revision differs'):
            self.job.preflight()
        self.docker.revision = COMMIT
        self.docker.image_revision = 'unknown'
        with self.assertRaisesRegex(ValueError, 'needs a baked COMMIT'):
            self.job.preflight()
        self.docker.image_revision = COMMIT
        self.token_file.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'must be private'):
            self.job.preflight()
        self.token_file.chmod(0o600)
        with patch.object(self.opener_mock.return_value, 'open', side_effect=HTTPError('url', 403, 'forbidden', {}, None)), \
                self.assertRaisesRegex(ValueError, 'administrator deployment check failed'):
            self.job.preflight()
        self.assertFalse(any('up' in args or args[:2] == ['docker', 'push'] for args in self.docker.calls))

    def test_deployment_request_cannot_use_proxy_redirect_or_unsafe_token(self):
        self.job.deployment()
        proxy, redirects = self.opener_mock.call_args.args
        self.assertEqual(proxy.proxies, {})
        self.assertIsNone(redirects.redirect_request(None, None, None, None, None, None))
        for token in ('private\nadmin.token', 'x' * 8193):
            self.token_file.write_text(token)
            with self.assertRaises(ValueError) as error:
                self.job.preflight()
            self.assertNotIn(token, str(error.exception))

    def test_auth_failure_before_mutation_and_after_start_preserves_boundary(self):
        with patch.object(self.opener_mock.return_value, 'open', side_effect=HTTPError('url', 401, 'expired', {}, None)), \
                self.assertRaises(ValueError):
            self.job.activate(NEW, {}, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), self.config)
        def fail_after_start(*args, **kwargs):
            if self.docker.api_id != 'old-api':
                raise HTTPError('url', 401, 'expired', {}, None)
            return self.http_response(*args, **kwargs)
        with patch.object(self.opener_mock.return_value, 'open', side_effect=fail_after_start), self.assertRaises(ValueError):
            self.job.activate(NEW, {}, self.state)
        self.assertEqual((self.deploy / 'config.toml').read_bytes(), upgrade.patch_config(self.config, NEW))
        receipt = next(self.state.glob('*/receipt.json'))
        self.assertEqual(json.loads(receipt.read_bytes())['phase'], 'api_start_requested')

    def test_onchain_redeemer_mismatch_blocks_without_touching_any_service(self):
        self.docker.model['services']['redeemer'] = {'image': OLD}
        self.job.model = self.docker.model
        with self.assertRaisesRegex(ValueError, 'not been applied'):
            self.job.check_redeemer()
        self.docker.model['services']['redeemer']['image'] = NODE
        self.job.check_redeemer()
        self.docker.model['services']['redeemer']['image'] = NEW
        self.docker.built['Config']['Labels']['io.livepeer.node.image'] = NODE
        self.docker.built['Config']['Labels']['org.opencontainers.image.version'] = VERSION
        # Matching custom upstream labels cannot prove an arbitrary wrapped image.
        current = {'Id': 'redeemer', 'Image': 'sha256:built', 'Config': {'Image': NEW}}
        with patch.object(self.job, 'container', return_value=current), self.assertRaisesRegex(ValueError, 'redeemer must use'):
            self.job.check_redeemer()
        self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_publish_uses_manifest_digest_and_reuses_verified_existing_build(self):
        manifest = {'config': {'digest': 'sha256:config'}, 'layers': [{'digest': 'sha256:layer'}]}
        for existing in (False, True):
            self.docker.calls.clear()
            self.docker.built['Config']['Labels']['io.livepeer.node.inputs'] = self.job.build_key
            entries = ([('sha256:' + 'e' * 64, manifest)] if existing else [None])
            entries += [('sha256:' + 'e' * 64, manifest)] * 2
            with self.subTest(existing=existing), patch.object(upgrade, 'registry_manifest', side_effect=entries), \
                    patch.object(self.job, 'image_file_hash', return_value='wrapper-hash'):
                image, record = self.job.publish()
            self.assertEqual(image, NEW)
            self.assertEqual(record['runtime_image'], RUNTIME)
            self.assertEqual(any(args[:2] == ['docker', 'push'] for args in self.docker.calls), not existing)
            self.assertFalse(any('up' in args for args in self.docker.calls))

    def test_conflicting_build_tag_and_wrong_wrapper_never_push(self):
        manifest = {'config': {'digest': 'sha256:config'}, 'layers': []}
        with patch.object(upgrade, 'registry_manifest', return_value=('sha256:' + 'e' * 64, manifest)), \
                self.assertRaisesRegex(ValueError, 'conflicting inputs'):
            self.job.publish()
        self.docker.calls.clear()
        with patch.object(upgrade, 'registry_manifest', return_value=None), \
                patch.object(self.job, 'image_file_hash', side_effect=['one', 'two']), \
                self.assertRaisesRegex(ValueError, 'Runtime wrapper'):
            self.job.publish()
        self.assertFalse(any(args[:2] == ['docker', 'push'] for args in self.docker.calls))

    def test_registry_missing_and_corrupt_manifest_are_distinct(self):
        with patch.object(upgrade, 'urlopen', side_effect=HTTPError('url', 404, 'missing', {}, None)):
            self.assertIsNone(upgrade.registry_manifest('http://localhost/v2/node', 'tag', missing_ok=True))
            with self.assertRaises(ValueError):
                upgrade.registry_manifest('http://localhost/v2/node', 'tag')
        response = Response()
        response.read = lambda _limit: b'{}'
        response.headers = {'Docker-Content-Digest': 'sha256:' + '0' * 64}
        with patch.object(upgrade, 'urlopen', return_value=response), self.assertRaisesRegex(ValueError, 'digest header'):
            upgrade.registry_manifest('http://localhost/v2/node', 'tag')

    def test_private_state_lock_refuses_unsafe_permissions(self):
        self.state.chmod(0o755)
        with self.assertRaises(ValueError), upgrade.locked_state(self.state):
            pass


if __name__ == '__main__':
    unittest.main()
