"""Fetch a fresh token before each pinned cloudflared process; retain no disk copy."""
import argparse
import json
import os
import pathlib
import random
import signal
import socket
import subprocess
import sys
import tempfile
import time


def request(socket_path, command):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(25)
        sock.connect(str(socket_path))
        sock.sendall(command)
        with sock.makefile('rb') as stream:
            body = stream.readline(16385)
        if len(body) > 16384:
            raise ValueError('credential response exceeds limit')
        return json.loads(body)


def fetch(socket_path):
    grant = request(socket_path, b'token\n')
    token = grant.get('token', '')
    instance = grant.get('broker_instance', '')
    if (not isinstance(token, str) or not 20 <= len(token) <= 8192 or not token.isascii() or
            any(c.isspace() for c in token) or not isinstance(instance, str) or len(instance) != 32):
        raise ValueError('connector credential unavailable')
    return token, instance


def run_once(socket_path, token_path, command=None):
    path = pathlib.Path(token_path)
    if path.parent.is_symlink():
        raise ValueError('token directory cannot be a symlink')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.unlink(missing_ok=True)
    for stale in path.parent.glob('.token-*'):
        stale.unlink(missing_ok=True)
    token, instance = fetch(socket_path)  # Never reuse an earlier process's file.
    fd, temporary = tempfile.mkstemp(prefix='.token-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(token.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        child = subprocess.Popen(command or [
            '/usr/local/bin/cloudflared', 'tunnel', '--no-autoupdate',
            '--disable-path-normalization=false', '--metrics', '127.0.0.1:20241',
            'run', '--token-file', str(path)], env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent'})
        def stop(signum, frame):
            child.send_signal(signum)
        previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            while True:
                try:
                    return child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        current = request(socket_path, b'identity\n')['broker_instance']
                    except Exception:
                        continue  # An unavailable broker does not stop a running connector.
                    if current == instance:
                        continue
                    # A fresh broker cannot attest an earlier process's grant.
                    # Restart via Kubernetes, fetching anew before the next start.
                    child.terminate()
                    try:
                        child.wait(timeout=25)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                    return 75
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--token-path', required=True)
    args = parser.parse_args()
    attempt = 0
    while True:
        try:
            return run_once(args.socket, args.token_path)
        except Exception:
            # Do not print exception text, token bodies, or request URLs.
            print('Connector startup waiting for protected credential delivery', file=sys.stderr, flush=True)
            time.sleep(min(60, 2 ** min(attempt, 5)) + random.random())
            attempt += 1


if __name__ == '__main__':
    sys.exit(main())
