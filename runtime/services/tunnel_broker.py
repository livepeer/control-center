"""Machine-authenticated token delivery over a same-Pod Unix socket."""
import argparse
import json
import os
import pathlib
import socketserver
import stat
import sys
import threading
import time
import urllib.request
import uuid

from control_client import ControlClient, read_config


class Broker:
    def __init__(self, config, token_file, config_url_file):
        self.config = config
        self.client = ControlClient(pathlib.Path(config_url_file).read_text(), token_file)
        self.granted = None
        self.instance = uuid.uuid4().hex
        self.lock = threading.Lock()

    def metadata(self):
        desired = read_config(self.config)
        if desired['node_id'] != self.client.node_id or desired.get('terminal'):
            raise ValueError('inactive or mismatched enrollment')
        return desired

    def grant(self):
        desired = self.metadata()
        body, _ = self.client.request('tunnel/connector-token')
        grant = json.loads(body)
        if (grant['epoch'] != desired['epoch'] or grant['tunnel_id'] != desired['tunnel_id'] or
                grant['credential_generation'] != desired['credential_generation']):
            raise ValueError('stale connector generation')
        with self.lock:
            self.granted = {key: grant[key] for key in ('epoch', 'credential_generation', 'tunnel_id')}
        grant['broker_instance'] = self.instance
        return grant

    def report_once(self):
        desired = self.metadata()
        ready = False
        version = 0
        try:
            with urllib.request.urlopen('http://127.0.0.1:20241/ready', timeout=2) as response:
                ready = response.status == 200
            with urllib.request.urlopen('http://127.0.0.1:20241/config', timeout=2) as response:
                body = response.read(262145)
                if len(body) > 262144:
                    raise ValueError('connector configuration exceeds limit')
                version = json.loads(body)['version']
        except Exception:
            ready = False
        with self.lock:
            generation = self.granted['credential_generation'] if self.granted else 0
        self.client.request('status', {
            'epoch': desired['epoch'], 'credential_version': desired['credential_version'],
            'component': 'connector', 'generation': desired['generation'],
            'token_generation': generation, 'provider_version': version,
            'ready': ready, 'https': True, 'reason': 'ready' if ready else 'offline'})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(broker, socket_path):
    path = pathlib.Path(socket_path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise ValueError('refusing to replace non-socket')
        path.unlink()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(25)
            command = self.rfile.readline(128)
            if command == b'identity\n':
                self.wfile.write(json.dumps({'broker_instance': broker.instance}).encode() + b'\n')
                return
            if command != b'token\n':
                return
            try:
                result = broker.grant()
            except Exception:
                result = {'error': 'connector credential unavailable'}
            self.wfile.write(json.dumps(result).encode() + b'\n')

    server = UnixServer(str(path), Handler)
    os.chmod(path, 0o600)
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--config-url-file', default='/credentials/config-url')
    parser.add_argument('--socket', required=True)
    args = parser.parse_args()
    broker = Broker(args.config, args.token_file, args.config_url_file)

    def report():
        while True:
            try:
                broker.report_once()
            except Exception:
                print('Connector status unavailable', file=sys.stderr, flush=True)
            time.sleep(20)

    threading.Thread(target=report, daemon=True).start()
    with serve(broker, args.socket) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
