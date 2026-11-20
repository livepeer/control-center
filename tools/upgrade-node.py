#!/usr/bin/env python3
"""Publish and activate a managed Node image on a Linux amd64 host and fleet.

The default dry-run checks metadata only. --apply ends after it verifies the
installed API revision and loaded runtime_node_image via /api/admin/deployment;
fleet reconciliation may begin immediately. Supply an existing administrator
bearer token in a private --admin-token-file. The installed API needs that
protected endpoint and the same COMMIT in its binary and OCI revision label.
An onchain redeemer must separately use the verified upstream image. The config
timestamp gate may require a separate reload of pending or recovered edits before retry.
Private backups under --state-dir contain config secrets; retain them for recovery.
Requires Python 3.11+, Go, Git, gh, Docker Engine, Compose and Buildx.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import tomllib
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener, urlopen


ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/livepeer/node'
UPSTREAM = 'ghcr.io/livepeer/node'
PUBLIC = 'controlcenter-registry.livepeer.live/controlcenter/node'
UPLOAD = '127.0.0.1:63812/controlcenter/node'
# The API's public listener on the deployment host (PublicListen in config.toml).
API = 'http://127.0.0.1:43811'
PLATFORM = 'linux/amd64'
DIGEST = r'sha256:[0-9a-f]{64}'
IMAGE = rf'[a-zA-Z0-9][a-zA-Z0-9./:_-]*@{DIGEST}'
FALLBACK = 'api/internal/controlplane/machineconfig/templates/system/node/orchestrator.yaml'
RECIPE = 'runtime/services/Dockerfile.node'
INPUTS = ['go.mod', 'go.sum', FALLBACK, RECIPE, RECIPE + '.dockerignore', 'tools/upgrade-node.py']
ACCEPT = ', '.join(('application/vnd.oci.image.manifest.v1+json',
                    'application/vnd.docker.distribution.manifest.v2+json'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def run(*args, cwd=None, timeout=120):
    # Command output can contain private Compose values. Never echo it on error.
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, capture_output=True,
                            text=True, timeout=timeout)
    require(result.returncode == 0, f'{args[0]} {args[1]} failed (exit {result.returncode})')
    return result.stdout.strip()


def source_version(root, runner=run):
    module = json.loads(runner('go', 'mod', 'edit', '-json', cwd=root))
    require(not any(item['Old']['Path'] == MODULE for item in module.get('Replace') or []),
            'Node module replacements are unsupported')
    versions = [item['Version'] for item in module['Require'] if item['Path'] == MODULE]
    require(len(versions) == 1 and re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', versions[0]),
            'go.mod must select one released Node version; pseudo-versions are unsupported')
    fallback = re.findall(r'image: ghcr\.io/livepeer/node:([^\s@]+)@(' + DIGEST + ')',
                          (root / FALLBACK).read_text())
    require(len(fallback) == 1 and fallback[0][0] == versions[0],
            'fallback Node image release must match go.mod')
    return versions[0], fallback[0][1]


def patch_config(data, image):
    require(re.fullmatch(IMAGE, image), 'managed image must be digest-pinned')
    text = data.decode()
    before = tomllib.loads(text)
    if before.get('RuntimeNodeImage') == image:
        return data
    if 'RuntimeNodeImage' in before:
        pattern = r'''(?m)^([ \t]*RuntimeNodeImage[ \t]*=[ \t]*)("[^"\r\n]*"|'[^'\r\n]*')([ \t]*(?:#[^\r\n]*)?)(?=\r?$)'''
        text, count = re.subn(pattern, lambda m: m[1] + json.dumps(image) + m[3], text)
        require(count == 1 and isinstance(before['RuntimeNodeImage'], str),
                'RuntimeNodeImage must be one plain root-level string assignment')
    else:
        newline = '\r\n' if '\r\n' in text else '\n'
        text = 'RuntimeNodeImage = ' + json.dumps(image) + newline + text
    before['RuntimeNodeImage'] = image
    require(tomllib.loads(text) == before, 'config patch would change unrelated settings')
    return text.encode()


@dataclass
class Snapshot:
    path: Path
    data: bytes
    mode: int
    uid: int
    gid: int

    @classmethod
    def read(cls, path, limit=None):
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode), 'deployment input must be a regular file')
            data = stream.read() if limit is None else stream.read(limit + 1)
            require(limit is None or len(data) <= limit, 'deployment input exceeds its size limit')
            return cls(path, data, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)

    def unchanged(self):
        require(Snapshot.read(self.path) == self, 'deployment file changed during upgrade: ' + self.path.name)

    def write(self, data):
        self.unchanged()
        atomic_write(self.path, data, self.mode, self.uid, self.gid)


def atomic_write(path, data, mode=0o600, uid=None, gid=None):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            if uid is not None:
                os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            temporary.replace(path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def locked_state(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'state directory must be owned by this user with mode 0700')
    with os.fdopen(os.open(path / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def registry_manifest(base, reference, missing_ok=False):
    try:
        with urlopen(Request(base + '/manifests/' + reference, headers={'Accept': ACCEPT}), timeout=30) as response:
            data = response.read(4 * 1024 * 1024 + 1)
            require(len(data) <= 4 * 1024 * 1024, 'registry manifest is too large')
            digest = 'sha256:' + sha(data)
            require(response.headers.get('Docker-Content-Digest') == digest,
                    'registry manifest digest header does not match content')
            return digest, json.loads(data)
    except HTTPError as error:
        error.close()
        if missing_ok and error.code == 404:
            return None
        raise ValueError(f'registry manifest request failed (HTTP {error.code})') from None


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Upgrade:
    def __init__(self, root, deploy, files=None, env_file=None, runner=run, token_file=None):
        self.root, self.deploy, self.run = root.resolve(), deploy.resolve(), runner
        self.token_file = token_file
        self.files = [path.resolve() for path in files or [self.deploy / 'compose.yaml']]
        self.compose = ['docker', 'compose', '--project-directory', self.deploy]
        for path in self.files:
            self.compose += ['-f', path]
        if env_file is None:
            default_env_file = self.deploy / 'compose.env'
            env_file = default_env_file if default_env_file.exists() else Path(os.devnull)
        self.compose += ['--env-file', env_file.resolve()]

    def inspect(self, kind, reference):
        result = json.loads(self.run('docker', kind, 'inspect', reference))
        require(len(result) == 1, 'expected one Docker ' + kind)
        return result[0]

    def container(self, service):
        ids = self.run(*self.compose, 'ps', '--quiet', service).splitlines()
        require(len(ids) == 1, 'expected one running ' + service + ' container')
        return self.inspect('container', ids[0])

    def remote_image(self, reference):
        descriptor = json.loads(self.run('docker', 'buildx', 'imagetools', 'inspect',
                                         reference, '--format', '{{json .Manifest}}'))
        digest = descriptor.get('digest', '')
        require(re.fullmatch(DIGEST, digest), 'missing registry manifest digest')
        repository = reference.split('@')[0]
        if '@' not in reference:
            repository = reference.rsplit(':', 1)[0]
        child = digest
        if 'manifests' in descriptor:
            candidates = [entry['digest'] for entry in descriptor['manifests']
                          if entry.get('platform', {}).get('os') == 'linux'
                          and entry['platform'].get('architecture') == 'amd64']
            require(len(candidates) == 1, 'image must contain exactly one linux/amd64 manifest')
            child = candidates[0]
        config = json.loads(self.run('docker', 'buildx', 'imagetools', 'inspect',
                                     repository + '@' + child, '--format', '{{json .Image}}'))
        require(config.get('os') == 'linux' and config.get('architecture') == 'amd64',
                'image does not support linux/amd64')
        return repository + '@' + digest, repository + '@' + child, config

    def deployment(self):
        request = Request(API + '/api/admin/deployment',
                          headers={'Authorization': 'Bearer ' + self.token})
        try:
            with build_opener(ProxyHandler({}), RejectRedirects()).open(request, timeout=30) as response:
                data = response.read(16385)
                require(len(data) <= 16384, 'deployment response exceeds its size limit')
                result = json.loads(data)
        except HTTPError as error:
            error.close()
            raise ValueError(f'administrator deployment check failed (HTTP {error.code})') from None
        require(isinstance(result, dict) and set(result) == {'revision', 'runtime_node_image'}
                and isinstance(result.get('runtime_node_image'), str)
                and re.fullmatch(r'[0-9a-f]{40}', result.get('revision', '')),
                'API must expose loaded Node image and baked revision in /api/admin/deployment')
        require(result['revision'] == self.api_revision, 'API build revision differs from the intended installed image')
        return result['runtime_node_image']

    def mounted_hash(self, container, path='/etc/controlcenter/config.toml'):
        return self.run('docker', 'exec', container['Id'], 'sha256sum', '--', path).split()[0]

    def preflight(self):
        self.version, fallback_digest = source_version(self.root, self.run)
        require(self.token_file is not None, 'provide an existing administrator bearer token with --admin-token-file')
        token = Snapshot.read(self.token_file, limit=8192)
        require(token.mode & 0o077 == 0, 'administrator token file must be private (mode 0600)')
        self.token = token.data.decode().strip()
        require(re.fullmatch(r'[a-zA-Z0-9._-]+', self.token), 'invalid administrator token file')
        require(not self.run('git', 'status', '--porcelain', '--', *INPUTS, cwd=self.root),
                'commit upgrade build inputs before deployment')
        self.commit = self.run('git', 'rev-parse', 'HEAD', cwd=self.root)
        context = json.loads(self.run('docker', 'context', 'inspect'))
        require(len(context) == 1 and context[0].get('Name') == 'default'
                and context[0]['Endpoints']['docker']['Host'].startswith('unix://')
                and not os.environ.get('DOCKER_HOST'), 'use the deployment host local Docker context')
        info = json.loads(self.run('docker', 'info', '--format', '{{json .}}'))
        require(info.get('OSType') == 'linux' and info.get('Architecture') in ('x86_64', 'amd64'),
                'this script supports only a Linux amd64 deployment host/fleet')
        self.config = Snapshot.read(self.deploy / 'config.toml')
        self.record = Snapshot.read(self.deploy / 'staging-images.json')
        self.params = tomllib.loads(self.config.data.decode())
        self.images = json.loads(self.record.data)
        self.runtime = self.params.get('RuntimeImage', '')
        require(re.fullmatch(IMAGE, self.runtime), 'RuntimeImage must be digest-pinned')
        for key in ('RuntimeImage', 'RuntimeConnectorImage', 'RuntimeNodeImage'):
            require(self.images.get('images', {}).get(key, '') == self.params.get(key, ''),
                    'config and staging-images.json disagree on ' + key + '; resolve interrupted/manual changes first')
        self.model = json.loads(self.run(*self.compose, 'config', '--format', 'json'))
        self.api = self.container('api')
        self.check_api(self.api)
        self.check_loaded_config(self.api)
        runtime_ref, _, _ = self.remote_image(self.runtime)
        require(runtime_ref == self.runtime, 'Runtime manifest does not match the configured digest')
        self.upstream, self.upstream_child, upstream_config = self.remote_image(UPSTREAM + ':' + self.version)
        require(self.upstream == UPSTREAM + '@' + fallback_digest,
                'published release digest differs from the committed fallback pin')
        self.node_commit = self.run('gh', 'api', f'repos/livepeer/node/commits/refs/tags/{self.version}', '--jq', '.sha')
        require(re.fullmatch(r'[0-9a-f]{40}', self.node_commit), 'invalid upstream release commit')
        labels = upstream_config['config'].get('Labels') or {}
        require(labels.get('org.opencontainers.image.source') == 'https://github.com/livepeer/node'
                and labels.get('org.opencontainers.image.version') == self.version
                and labels.get('org.opencontainers.image.revision') == self.node_commit,
                'upstream image version/source/revision does not match the release')
        self.check_redeemer()
        self.container('registry')
        with urlopen('http://127.0.0.1:63812/v2/', timeout=10) as response:
            require(response.status == 200, 'loopback registry is unavailable')
        self.inputs = {'node_image': self.upstream, 'runtime_image': self.runtime,
                       'platform': PLATFORM, 'recipe_sha256': sha((self.root / RECIPE).read_bytes()),
                       'dockerignore_sha256': sha((self.root / (RECIPE + '.dockerignore')).read_bytes())}
        self.build_key = sha(encoded(self.inputs))
        self.tag = 'node-' + self.version + '-' + self.build_key
        return {'version': self.version, 'node_commit': self.node_commit, **self.inputs,
                'previous_image': self.params.get('RuntimeNodeImage', ''),
                'publish_tag': UPLOAD + ':' + self.tag}

    def check_api(self, container):
        labels = container['Config'].get('Labels') or {}
        require(labels.get('com.docker.compose.project') == self.model['name'], 'wrong Compose project')
        require(labels.get('com.docker.compose.project.working_dir') == str(self.deploy), 'wrong Compose directory')
        require(labels.get('com.docker.compose.project.config_files', '').split(',') == [str(p) for p in self.files],
                'selected Compose files differ from the running API stack')
        expected_hash = self.run(*self.compose, 'config', '--hash', 'api').split()
        require(len(expected_hash) == 2 and expected_hash[0] == 'api'
                and labels.get('com.docker.compose.config-hash') == expected_hash[1],
                'API Compose definition changed; deploy it separately first')
        spec = container['Config']
        require(spec.get('Cmd') == ['serve', '--config', '/etc/controlcenter/config.toml']
                and spec.get('Entrypoint') == ['controlcenter'], 'unsupported API entrypoint/config override')
        require(not any(value.split('=', 1)[0] in ('RUNTIME_NODE_IMAGE', 'RUNTIME_IMAGE', 'CONTROL_CENTER_CONFIG')
                        for value in spec.get('Env') or []), 'API environment overrides the deployment config')
        mounts = [m for m in container['Mounts'] if m['Destination'] == '/etc/controlcenter/config.toml']
        require(len(mounts) == 1 and mounts[0]['Source'] == str(self.config.path) and not mounts[0]['RW'],
                'API must mount deploy/config.toml read-only')
        expected_mounts = {}
        service = self.model['services']['api']
        for mount in service.get('volumes') or []:
            require(mount['type'] == 'bind', 'API upgrade supports only existing bind mounts')
            expected_mounts[mount['target']] = (mount['source'], not mount.get('read_only', False))
        for kind in ('secrets', 'configs'):
            for item in service.get(kind) or []:
                item = {'source': item} if isinstance(item, str) else item
                definition = self.model[kind][item['source']]
                require(isinstance(definition.get('file'), str), 'API upgrade requires file-backed secrets/configs')
                target = item.get('target') or item['source']
                if not target.startswith('/'):
                    target = ('/run/secrets/' if kind == 'secrets' else '/') + target
                expected_mounts[target] = (definition['file'], False)
        actual_mounts = {m['Destination']: (m['Source'], m['RW']) for m in container['Mounts']}
        require(all(m['Type'] == 'bind' for m in container['Mounts']) and actual_mounts == expected_mounts,
                'API mount/secret/config sources changed; deploy them separately first')
        self.api_mounts = expected_mounts
        expected = self.model['services']['api']['image']
        installed = self.inspect('image', expected)
        require(container['Image'] == installed['Id'],
                'configured API image differs from the running image')
        revision = (installed['Config'].get('Labels') or {}).get('org.opencontainers.image.revision', '')
        require(re.fullmatch(r'[0-9a-f]{40}', revision),
                'installed API image needs a baked COMMIT and matching OCI revision label')
        self.api_revision = revision
        require(container['State'].get('Health', {}).get('Status') == 'healthy', 'API is not healthy')

    def check_loaded_config(self, container):
        require(self.mounted_hash(container) == sha(self.config.data),
                'API mounted config differs from the host file; resolve pending config changes separately')
        started = datetime.fromisoformat(container['State']['StartedAt'].replace('Z', '+00:00')).timestamp()
        for target, (source, _) in self.api_mounts.items():
            path = Path(source)
            info = path.stat()
            # RPC directories hold immutable versions read on demand, rather
            # than one startup-loaded file. Do not recursively inspect them.
            if stat.S_ISREG(info.st_mode):
                require(max(info.st_mtime, info.st_ctime) <= started,
                        'API startup file changed after API startup; load pending changes separately first')
                require(self.mounted_hash(container, target) == sha(path.read_bytes()),
                        'API startup file differs from its host source; load pending changes separately first')
        require(self.deployment() == self.params.get('RuntimeNodeImage', ''),
                'API has not loaded the current RuntimeNodeImage; resolve it separately first')

    def check_redeemer(self):
        enabled = any(self.params.get(key) for key in ('OnchainSecretsDir', 'OnchainWebhookSecretFile', 'OnchainWebhookSecret'))
        service = self.model['services'].get('redeemer')
        if not enabled and not service:
            return
        require(service is not None, 'onchain deployment requires a redeemer service')
        image = service['image']
        require(re.fullmatch(IMAGE, image), 'LIVEPEER_REDEEMER_IMAGE must be digest-pinned')
        current = self.container('redeemer')
        selected = self.inspect('image', image)
        require(current['Config']['Image'] == image and current['Image'] == selected['Id'],
                'redeemer image setting has not been applied; upgrade the redeemer separately')
        labels = selected['Config'].get('Labels') or {}
        raw = (image.split('@')[-1] in (self.upstream.split('@')[-1], self.upstream_child.split('@')[-1])
               and labels.get('org.opencontainers.image.revision') == self.node_commit
               and labels.get('org.opencontainers.image.version') == self.version)
        require(raw, 'redeemer must use ' + self.upstream + '; upgrade it separately before API activation')

    def image_file_hash(self, image):
        with tempfile.TemporaryDirectory() as directory:
            container = self.run('docker', 'create', '--platform', PLATFORM, image)
            try:
                path = Path(directory) / 'wrapper'
                self.run('docker', 'cp', container + ':/usr/local/bin/livepeer-runtime', path)
                return sha(path.read_bytes())
            finally:
                self.run('docker', 'container', 'rm', container)

    def publish(self):
        base = 'http://127.0.0.1:63812/v2/controlcenter/node'
        existing = registry_manifest(base, self.tag, missing_ok=True)
        local_tag = UPLOAD + ':' + self.tag
        if existing:
            image = UPLOAD + '@' + existing[0]
            self.run('docker', 'pull', '--platform', PLATFORM, image, timeout=900)
        else:
            self.run('docker', 'buildx', 'build', '--builder', 'default', '--platform', PLATFORM,
                     '--load', '--provenance=false', '-f', self.root / RECIPE,
                     '--build-arg', 'NODE_IMAGE=' + self.upstream,
                     '--build-arg', 'RUNTIME_IMAGE=' + self.runtime,
                     '--label', 'io.livepeer.node.inputs=' + self.build_key,
                     '--label', 'io.livepeer.node.image=' + self.upstream,
                     '--label', 'org.opencontainers.image.source=https://github.com/livepeer/control-center',
                     '--label', 'org.opencontainers.image.revision=' + self.commit,
                     '-t', local_tag, self.root / 'runtime/services', timeout=1800)
            image = local_tag
        built = self.inspect('image', image)
        labels = built['Config'].get('Labels') or {}
        require(labels.get('io.livepeer.node.inputs') == self.build_key
                and labels.get('io.livepeer.node.image') == self.upstream
                and re.fullmatch(r'[0-9a-f]{40}', labels.get('org.opencontainers.image.revision', '')),
                'existing build tag has conflicting inputs')
        require(built.get('Os') == 'linux' and built.get('Architecture') == 'amd64'
                and built['Config'].get('User') == '65532:65532'
                and built['Config'].get('Entrypoint') == ['/usr/local/bin/livepeer'],
                'managed Node image platform/user/entrypoint is incorrect')
        self.run('docker', 'pull', '--platform', PLATFORM, self.upstream, timeout=900)
        for reference in (self.upstream, built['Id']):
            version = self.run('docker', 'run', '--rm', '--network', 'none', '--read-only',
                               '--cap-drop', 'ALL', '--platform', PLATFORM, reference, 'version')
            require(version == f'livepeer {self.version} ({self.node_commit})', 'Node binary version mismatch')
        self.run('docker', 'pull', '--platform', PLATFORM, self.runtime, timeout=900)
        require(self.image_file_hash(self.runtime) == self.image_file_hash(built['Id']),
                'managed image does not contain the selected Runtime wrapper')
        if not existing:
            self.run('docker', 'push', local_tag, timeout=900)
        digest, manifest = registry_manifest(base, self.tag)
        public_base = 'https://' + PUBLIC.replace('/controlcenter/node', '/v2/controlcenter/node')
        public_digest, public_manifest = registry_manifest(public_base, digest)
        require(public_digest == digest and public_manifest == manifest, 'public registry manifest mismatch')
        for blob in [manifest['config'], *manifest['layers']]:
            with urlopen(Request(public_base + '/blobs/' + blob['digest'], method='HEAD'), timeout=30) as response:
                require(response.status == 200, 'public image blob is unavailable anonymously')
        image = PUBLIC + '@' + digest
        self.run('docker', 'pull', '--platform', PLATFORM, image, timeout=900)
        require(self.inspect('image', image)['Id'] == built['Id'], 'published image differs from the validated build')
        return image, {**self.inputs, 'node_version': self.version, 'node_commit': self.node_commit,
                       'managed_image': image, 'build_key': self.build_key,
                       'controlcenter_commit': labels['org.opencontainers.image.revision']}

    def activate(self, image, provenance, state_dir):
        config = patch_config(self.config.data, image)
        record = json.loads(self.record.data)
        record['images']['RuntimeNodeImage'] = image
        legacy = {key: record.pop(key) for key in ('node_commit', 'node_source_archive_sha256') if key in record}
        if legacy:
            record['legacy_build'] = {**legacy, 'images': self.images['images']}
        record['node_build'] = provenance
        record_data = encoded(record)
        self.config.unchanged()
        self.record.unchanged()
        self.model = json.loads(self.run(*self.compose, 'config', '--format', 'json'))
        current = self.container('api')
        self.check_api(current)
        self.check_loaded_config(current)
        self.check_redeemer()
        loaded = self.config.data == config
        if loaded and json.loads(self.record.data) == record:
            return {'status': 'already_loaded', 'image': image}
        directory = Path(tempfile.mkdtemp(dir=state_dir, prefix='upgrade-'))
        atomic_write(directory / 'config.toml', self.config.data)
        atomic_write(directory / 'staging-images.json', self.record.data)
        receipt = {'phase': 'prepared', 'image': image, 'previous_image': self.params.get('RuntimeNodeImage', ''),
                   'config_sha256': sha(config), 'started_at': datetime.now(timezone.utc).isoformat(),
                   'files': {snap.path.name: {'mode': snap.mode, 'uid': snap.uid, 'gid': snap.gid}
                             for snap in (self.config, self.record)},
                   'api_recreate_command': [str(arg) for arg in self.compose] + self.recreate_args()}
        def phase(value):
            receipt['phase'] = value
            atomic_write(directory / 'receipt.json', encoded(receipt))
        changed = []
        restart_requested = False
        try:
            phase('prepared')
            for snapshot, data in ((self.config, config), (self.record, record_data)):
                if snapshot.data == data:
                    continue
                changed.append((Snapshot(snapshot.path, data, snapshot.mode, snapshot.uid, snapshot.gid), snapshot.data))
                snapshot.write(data)
            phase('files_written')
            if loaded:
                phase('api_loaded')
                return {'status': 'already_loaded', 'image': image, 'recovery_directory': str(directory)}
            # Startup workers can reconcile before readiness succeeds. Never
            # automatically restore a previous target beyond this boundary.
            phase('api_start_requested')
            restart_requested = True
            self.run(*self.compose, *self.recreate_args(), timeout=240)
            started = self.container('api')
            require(started['Id'] != current['Id'] and started['Image'] == current['Image'],
                    'API was not recreated with the existing image')
            self.check_api(started)
            require(self.mounted_hash(started) == sha(config) and self.deployment() == image,
                    'API did not load the new RuntimeNodeImage')
            with urlopen(API + '/readyz', timeout=10) as response:
                require(response.status == 200, 'API readiness failed')
            phase('api_loaded')
            return {'status': 'api_loaded', 'image': image, 'recovery_directory': str(directory)}
        except BaseException:
            print('Upgrade incomplete. Private backups and receipt: ' + str(directory), file=sys.stderr)
            if not restart_requested:
                conflicts = []
                for snapshot, old_data in reversed(changed):
                    try:
                        if Snapshot.read(snapshot.path).data != old_data:
                            snapshot.write(old_data)
                    except (OSError, ValueError):
                        conflicts.append(snapshot.path.name)
                if conflicts:
                    print('Restoration incomplete; preserved conflicting files: ' + ', '.join(conflicts), file=sys.stderr)
                try:
                    phase('restore_incomplete' if conflicts else 'restored_before_api_start')
                except OSError:
                    print('Could not update the recovery receipt.', file=sys.stderr)
            if restart_requested:
                print('API startup was requested; fleet reconciliation may have begun. Restore the saved files with their recorded ownership/modes and recreate only the API to select the previous target. This is a new rollout, not a fleet rollback.', file=sys.stderr)
            raise

    @staticmethod
    def recreate_args():
        return ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate',
                '--wait', '--wait-timeout', '180', 'api']


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true', help='publish, activate and recreate only the API')
    mode.add_argument('--dry-run', action='store_true', help='inspect and resolve metadata only (default)')
    mode.add_argument('--check-source', action='store_true', help='check go.mod and the fallback release, then exit')
    parser.add_argument('--deploy-dir', type=Path, default=ROOT / 'deploy')
    parser.add_argument('--compose-file', type=Path, action='append', help='existing Compose file, in original order; repeat for overlays')
    parser.add_argument('--env-file', type=Path,
                        help='Compose interpolation file (default: compose.env in --deploy-dir, if present)')
    parser.add_argument('--admin-token-file', type=Path, help='private file containing an existing administrator bearer token')
    parser.add_argument('--expected-version', help='require this go.mod version')
    parser.add_argument('--state-dir', type=Path, default=Path('/var/lib/controlcenter/node-upgrades'), help='private backup/lock directory')
    args = parser.parse_args()
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    for name in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(name, interrupted)
    try:
        version, _ = source_version(ROOT)
        require(not args.expected_version or version == args.expected_version, 'unexpected Node version in go.mod')
        if args.check_source:
            print(version)
            return
        upgrade = Upgrade(ROOT, args.deploy_dir, args.compose_file, args.env_file, token_file=args.admin_token_file)
        if not args.apply:
            print(json.dumps({'mode': 'dry_run', **upgrade.preflight()}, indent=2))
            return
        with locked_state(args.state_dir):
            print(json.dumps(upgrade.preflight(), indent=2), flush=True)
            image, provenance = upgrade.publish()
            print(json.dumps(upgrade.activate(image, provenance, args.state_dir), indent=2))
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        # TOML/JSON errors may quote private input. Keep diagnostics generic.
        message = str(error) if type(error) is ValueError else type(error).__name__
        parser.exit(1, 'error: ' + message + '\n')
    except KeyboardInterrupt:
        parser.exit(130, 'error: upgrade interrupted\n')


if __name__ == '__main__':
    main()
