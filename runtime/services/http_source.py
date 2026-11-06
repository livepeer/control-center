"""Poll the configuration API and publish a Flux ExternalArtifact."""
import argparse
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import re
import ssl
import sys
import threading
import time
import urllib.request

from artifacts import MAX_ARCHIVE, atomic_write, validate_archive
from http_common import Handler

API_PATH = "/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/externalartifacts/livepeer-service"


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
        with urllib.request.urlopen(req, context=self.context, timeout=20) as response:
            return json.load(response)

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
    def __init__(self, url, token_file, directory, artifact_url, kube):
        self.url, self.token_file = url, pathlib.Path(token_file)
        self.directory, self.artifact_url, self.kube = pathlib.Path(directory), artifact_url.rstrip('/'), kube
        self.last_digest = None

    def sync_once(self):
        try:
            request = urllib.request.Request(self.url, headers={
                'Authorization': 'Bearer ' + self.token_file.read_text(),
                'Accept': 'application/gzip'})
            # Never forward enrollment credentials across a redirect.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedirect())
            with opener.open(request, timeout=30) as response:
                data = response.read(MAX_ARCHIVE + 1)
            digest = validate_archive(data)
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
    args = parser.parse_args()
    adapter = Adapter(args.url, args.token_file, args.directory, args.artifact_url, KubeClient())

    def poll():
        while True:
            adapter.sync_once()
            time.sleep(60)

    threading.Thread(target=poll, daemon=True).start()
    http.server.ThreadingHTTPServer(('0.0.0.0', 8080), handler_for(args.directory)).serve_forever()
