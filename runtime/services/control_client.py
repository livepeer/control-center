"""Bounded, origin-bound Control Center requests; never expose remote errors."""
import json
import pathlib
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ControlClient:
    def __init__(self, config_url, token_file, allow_http=False):
        u = urllib.parse.urlsplit(config_url)
        match = re.fullmatch(r'(.*)/v1/nodes/(lp-[a-f0-9]{16})/config', u.path)
        if (u.scheme not in (('https', 'http') if allow_http else ('https',)) or
                not u.hostname or u.username or u.password or u.query or u.fragment or not match):
            raise ValueError('verified HTTPS machine configuration URL required')
        self.config_url = config_url
        self.node_id = match[2]
        self.base = urllib.parse.urlunsplit((u.scheme, u.netloc, match[1] + '/v1/nodes/' + self.node_id, '', ''))
        self.token_file = pathlib.Path(token_file)
        self.allow_http = allow_http
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def request(self, endpoint, payload=None, limit=16384):
        if (endpoint not in ('config', 'status', 'removal-ack', 'tunnel/connector-token') and
                not re.fullmatch(r'apps/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/status', endpoint)):
            raise ValueError('unsupported machine endpoint')
        token = self.token_file.read_text()
        if not re.fullmatch('[a-f0-9]{64}', token):
            raise ValueError('invalid machine credential file')
        headers = {'Authorization': 'Bearer ' + token}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        method = 'GET' if endpoint == 'config' else 'POST'
        if method == 'POST' and data is None:
            data = b'{}'
        req = urllib.request.Request(self.base + '/' + endpoint, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            error.close()
            raise
        with response:
            if self.allow_http and response.headers.get('X-Livepeer-Tunnels-Enabled') == 'true':
                raise ValueError('development HTTP cannot use live provisioning')
            body = response.read(limit + 1)
            if len(body) > limit:
                raise ValueError('Control Center response exceeds limit')
            return body, response.headers


def read_config(path):
    data = pathlib.Path(path).read_bytes()
    if len(data) > 16384:
        raise ValueError('Runtime metadata exceeds limit')
    return json.loads(data)
