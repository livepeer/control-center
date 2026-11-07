"""Poll the configuration API and publish a Flux ExternalArtifact."""
import argparse
import datetime
import hashlib
import http.server
import io
import json
import os
import pathlib
import re
import ssl
import sys
import threading
import time
import tarfile
import urllib.request
import urllib.error

from artifacts import MAX_ARCHIVE, atomic_write, validate_archive
from http_common import Handler
from control_client import ControlClient, NoRedirect, read_config

API_PATH = "/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/externalartifacts/livepeer-service"
FLUX_PATH = '/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations/'
DEPLOY_PATH = '/apis/apps/v1/namespaces/'


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


class KubeClient:
    def __init__(self):
        self.base = 'https://' + os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc') + ':' + os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS', '443')
        self.directory = pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.context = ssl.create_default_context(cafile=str(self.directory / 'ca.crt'))

    def request(self, path, payload=None):
        headers = {'Authorization': 'Bearer ' + (self.directory / 'token').read_text().strip()}
        if payload is not None:
            headers['Content-Type'] = 'application/merge-patch+json'
        req = urllib.request.Request(self.base + path,
                                     data=json.dumps(payload).encode() if payload is not None else None,
                                     headers=headers, method='PATCH' if payload is not None else 'GET')
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=self.context))
        with opener.open(req, timeout=20) as response:
            body = response.read((4 << 20) + 1)
            if len(body) > 4 << 20:
                raise ValueError('Kubernetes response exceeds limit')
            return json.loads(body)

    def publish(self, artifact, ready, reason, message):
        resource = self.request(API_PATH)
        old_conditions = resource.get('status', {}).get('conditions', [])
        old = next((c for c in old_conditions if c['type'] == 'Ready'), {})
        status = 'True' if ready else 'False'
        condition = {'type': 'Ready', 'status': status, 'reason': reason,
                     'message': message, 'observedGeneration': resource['metadata']['generation'],
                     'lastTransitionTime': old.get('lastTransitionTime', utcnow()) if old.get('status') == status else utcnow()}
        body = {'conditions': [condition], 'observedGeneration': resource['metadata']['generation']}
        if artifact is not None:
            body['artifact'] = artifact
        self.request(API_PATH + '/status', {'status': body})


class Adapter:
    def __init__(self, url, token_file, directory, artifact_url, kube, allow_http=False, identity_file=None):
        self.url, self.token_file = url, pathlib.Path(token_file)
        self.directory, self.artifact_url, self.kube = pathlib.Path(directory), artifact_url.rstrip('/'), kube
        self.last_digest = None
        self.approved_url = url
        self.allow_http = allow_http
        self.identity_file = pathlib.Path(identity_file) if identity_file else None

    def report(self, client, desired, digest):
        def applied(name):
            resource = self.kube.request(FLUX_PATH + name)
            status = resource.get('status', {})
            return (status.get('observedGeneration') == resource['metadata']['generation'] and
                    status.get('lastAppliedRevision') == digest and
                    any(c['type'] == 'Ready' and c['status'] == 'True' for c in status.get('conditions', [])))

        applied_bundle = applied('livepeer') and applied('livepeer-upgrade-plan')
        if desired['terminal']:
            pods = self.kube.request('/api/v1/namespaces/flux-system/pods?labelSelector=app%3Dlivepeer-tunnel')
            absent = not pods.get('items')
            try:
                self.kube.request(DEPLOY_PATH + 'flux-system/deployments/livepeer-tunnel')
                absent = False
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise
            if applied_bundle and absent:
                client.request('removal-ack', {'epoch': desired['epoch'], 'digest': digest.split(':')[1], 'connector_absent': True})
            return
        ready = False
        actual_digest = ''
        try:
            deployment = self.kube.request(DEPLOY_PATH + 'livepeer/deployments/orchestrator')
            status = deployment.get('status', {})
            actual_digest = deployment['spec']['template']['metadata'].get('annotations', {}).get('livepeer.io/config-sha256', '')
            ready = (applied_bundle and status.get('observedGeneration') == deployment['metadata']['generation'] and
                     status.get('updatedReplicas') == 1 and status.get('readyReplicas') == 1 and
                     status.get('availableReplicas') == 1 and actual_digest == desired['config_digest'])
            pods = self.kube.request('/api/v1/namespaces/livepeer/pods?labelSelector=app%3Dorchestrator')['items']
            running = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
            ready = ready and len(running) == 1
            if len(running) == 1:
                pod = running[0]
                actual_digest = pod['metadata'].get('annotations', {}).get('livepeer.io/config-sha256', '')
                ready = (ready and actual_digest == desired['config_digest'] and
                         any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', [])))
            else:
                actual_digest = ''
            if ready:
                opener = urllib.request.build_opener(NoRedirect())
                with opener.open('http://orchestrator.livepeer.svc.cluster.local:8936/readyz', timeout=2) as response:
                    ready = response.status == 200
                with opener.open('http://orchestrator.livepeer.svc.cluster.local:8935/discovery', timeout=2) as response:
                    entries = json.loads(response.read((1 << 20) + 1))
                ready = ready and len(entries) == 1 and entries[0]['address'] == desired['service_url']
        except Exception:
            ready = False
        client.request('status', {
            'epoch': desired['epoch'], 'credential_version': desired['credential_version'],
            'component': 'runtime', 'generation': desired['generation'],
            'bundle_sha256': digest.split(':')[1], 'config_digest': actual_digest,
            'ready': ready, 'https': self.url.startswith('https://'),
            'reason': 'ready' if ready else 'applying'})

    def sync_once(self):
        try:
            if self.url != self.approved_url:
                raise ValueError('configuration destination changed without installer refresh')
            client = ControlClient(self.url, self.token_file, self.allow_http)
            data, headers = client.request('config', limit=MAX_ARCHIVE)
            digest = validate_archive(data)
            desired = None
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                try:
                    member = archive.getmember('runtime.json')
                except KeyError:
                    member = None
                if member is not None:
                    if member.size > 16384:
                        raise ValueError('Runtime metadata exceeds limit')
                    desired = json.loads(archive.extractfile(member).read())
            if desired is not None:
                if desired['node_id'] != client.node_id or desired['epoch'] != headers.get('X-Livepeer-Epoch'):
                    raise ValueError('configuration epoch mismatch')
                if int(headers.get('X-Livepeer-Credential-Version', '-1')) != desired['credential_version']:
                    raise ValueError('configuration credential version mismatch')
                if self.identity_file:
                    expected = read_config(self.identity_file)
                    legacy = (expected['epoch'] == '' and int(expected['credential_version']) == 0 and
                              desired['credential_version'] == 0)
                    if not legacy and (expected['epoch'] != desired['epoch'] or int(expected['credential_version']) != desired['credential_version']):
                        raise ValueError('configuration does not match installed enrollment')
                watermark_path = self.directory / 'enrollment.json'
                if watermark_path.exists():
                    previous = read_config(watermark_path)
                    if previous['epoch'] != desired['epoch']:
                        raise ValueError('old enrollment artifact directory must be fenced during re-enrollment')
                    if previous['terminal'] and not desired['terminal']:
                        raise ValueError('terminal enrollment cannot reactivate')
                    if not desired['terminal'] and previous['generation'] > desired['generation']:
                        raise ValueError('stale configuration generation')
                atomic_write(watermark_path, json.dumps(desired).encode())
            elif not self.allow_http:
                raise ValueError('enrollment metadata required')
            filename = digest.split(':')[1] + '.tar.gz'
            path = self.directory / filename
            if not path.exists():
                atomic_write(path, data, 0o644)
            elif hashlib.sha256(path.read_bytes()).hexdigest() != digest.split(':')[1]:
                atomic_write(path, data, 0o644)
            timestamp = datetime.datetime.fromtimestamp(path.stat().st_mtime, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
            artifact = {'digest': digest, 'revision': digest, 'path': 'artifacts/' + filename,
                        'url': self.artifact_url + '/artifacts/' + filename,
                        'size': len(data), 'lastUpdateTime': timestamp}
            self.kube.publish(artifact, True, 'Succeeded', 'Stored desired configuration ' + digest)
            # Record each publication in access time; keep artifact metadata stable.
            os.utime(path, ns=(time.time_ns(), path.stat().st_mtime_ns))
            if digest != self.last_digest:
                print('Published ' + digest, flush=True)
            self.last_digest = digest
            if desired is not None:
                try:
                    self.report(client, desired, digest)
                except Exception:
                    print('Applied-state report unavailable', file=sys.stderr, flush=True)
            # Retain recent immutable revisions so an in-flight Flux download survives updates.
            paths = sorted(self.directory.glob('*.tar.gz'), key=lambda p: p.stat().st_atime, reverse=True)
            for old in paths[10:]:
                if old != path and time.time() - old.stat().st_atime > 3600:
                    old.unlink()
            return True
        except Exception as exc:
            # Do not log remote bodies/URLs, which may contain credentials.
            message = 'Configuration fetch or publication failed: ' + type(exc).__name__
            print(message, file=sys.stderr, flush=True)
            try:
                self.kube.publish(None, False, 'FetchFailed', message)
            except Exception as status_error:
                print('Status update failed: ' + type(status_error).__name__, file=sys.stderr, flush=True)
            return False


def handler_for(directory):
    class ArtifactHandler(Handler):
        def do_GET(self):
            if self.probe():
                return
            if not re.fullmatch(r'/artifacts/[a-f0-9]{64}\.tar\.gz', self.path):
                return self.reply(404, b'not found\n')
            path = pathlib.Path(directory, self.path.rsplit('/', 1)[-1])
            try:
                self.reply(200, path.read_bytes(), 'application/gzip')
            except FileNotFoundError:
                self.reply(404, b'not found\n')
    return ArtifactHandler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--artifact-url', required=True)
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--identity-file')
    parser.add_argument('--transport', choices=['https', 'development-http'], default='https')
    args = parser.parse_args()
    adapter = Adapter(args.url, args.token_file, args.directory, args.artifact_url, KubeClient(), args.transport == 'development-http', args.identity_file)

    def poll():
        while True:
            adapter.sync_once()
            time.sleep(60)

    threading.Thread(target=poll, daemon=True).start()
    http.server.ThreadingHTTPServer(('0.0.0.0', 8080), handler_for(args.directory)).serve_forever()
