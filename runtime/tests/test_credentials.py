"""Credential transition ordering using shell fakes, without host installation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

LIBRARY = Path(__file__).resolve().parents[1] / 'lib/credentials.sh'


@unittest.skipUnless(shutil.which('jq'), 'jq required for credential transition fixtures')
class CredentialTransitions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('credentials', 'state', 'volumes/http-source'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / 'credentials/node-id').write_text('lp-' + 'a' * 16)
        (self.root / 'credentials/service-token').write_text('b' * 64)
        (self.root / 'credentials/runner-bootstrap.secret').write_text('runner-bootstrap')
        (self.root / 'credentials/config-url').write_text('http://legacy.example.invalid/v1/nodes/lp-' + 'a' * 16 + '/config')
        (self.root / 'state/k3s-version').write_text('v1.37.10+k3s1')

    def transition(self, fail=''):
        script = r'''
set -Eeuo pipefail
source "$1"
INSTALL_DIR=$2; export INSTALL_DIR
ENROLLMENT_TOKEN=header.payload.signature
LIVEPEER_API_URL=https://control.example.invalid
CREDENTIAL_TRANSITION=refresh
LIVEPEER_RUNTIME_IMAGE=registry.invalid/runtime@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
chown() { :; }
managed_installation() { return 0; }
die() { printf '%s\n' "$*" >&2; exit 1; }
atomic_write() { cat > "$1"; chmod 0600 "$1"; }
cat() {
  case "$*" in
    /etc/machine-id) printf 'machine' ;;
    /proc/sys/kernel/random/uuid) printf '11111111-1111-4111-8111-111111111111' ;;
    *) command cat "$@" ;;
  esac
}
sha256sum() { command cat >/dev/null; printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; }
kube() {
  printf 'kube %s\n' "$*" >> "$INSTALL_DIR/steps"
  if [[ "$FAIL_AT" == stop && "$*" == *'wait pod'* ]]; then return 1; fi
  if [[ "$*" == *'create secret generic livepeer-service-auth'* ]]; then
    [[ $(cat "$INSTALL_DIR/credentials/config-url") == https://* ]]
    [[ $(cat "$INSTALL_DIR/credentials/service-token") == cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ]]
    printf 'new-secret\n' >> "$INSTALL_DIR/steps"
  fi
  if [[ "$*" == 'apply -f -' ]]; then command cat >/dev/null; fi
}
stage_manifests() { printf 'https-code\n' >> "$INSTALL_DIR/steps"; }
curl() {
  printf 'refresh\n' >> "$INSTALL_DIR/steps"
  local previous='' arg
  for arg in "$@"; do
    if [[ "$previous" == --data-binary ]]; then printf '%s\n' "$arg" >> "$INSTALL_DIR/requests"; fi
    previous=$arg
  done
  [[ "$FAIL_AT" != request ]] || return 1
  printf '{"node_id":"lp-aaaaaaaaaaaaaaaa","token":"%s","epoch":"22222222-2222-4222-8222-222222222222","credential_version":"1","config_url":"https://control.example.invalid/v1/nodes/lp-aaaaaaaaaaaaaaaa/config"}\n200' \
    cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
}
transition_credentials
'''
        return subprocess.run(['bash', '-c', script, 'fixture', str(LIBRARY), str(self.root)],
                              env={**os.environ, 'FAIL_AT': fail}, text=True, capture_output=True)

    def test_interrupted_request_resumes_same_operation_after_consumers_stop(self):
        result = self.transition('request')
        self.assertNotEqual(result.returncode, 0)
        marker = self.root / 'state/credential-transition.json'
        operation = marker.read_bytes()
        self.assertEqual((self.root / 'credentials/service-token').read_text(), 'b' * 64)
        self.assertNotIn('new-secret', (self.root / 'steps').read_text())
        result = self.transition()
        self.assertEqual(result.returncode, 0, result.stderr)
        requests = [json.loads(x) for x in (self.root / 'requests').read_text().splitlines()]
        self.assertEqual(requests[0], requests[1])
        self.assertEqual(requests[0]['operation_id'], json.loads(operation)['operation'])
        self.assertEqual((self.root / 'state/k3s-version').read_text(), 'v1.37.10+k3s1')
        self.assertFalse(marker.exists())
        steps = (self.root / 'steps').read_text().splitlines()
        secret = steps.index('new-secret')
        self.assertLess(max(i for i, x in enumerate(steps[:secret]) if 'wait pod' in x), secret)
        self.assertLess(steps.index('https-code'), steps.index('refresh'))
        self.assertGreater(next(i for i, x in enumerate(steps) if 'rollout status' in x), secret)
        self.assertTrue(any('create secret generic livepeer-runner-bootstrap' in x for x in steps[:next(i for i,x in enumerate(steps) if 'rollout status' in x)]))

    def test_unconfirmed_consumer_termination_prevents_refresh(self):
        result = self.transition('stop')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'requests').exists())
        self.assertEqual((self.root / 'credentials/service-token').read_text(), 'b' * 64)
        self.assertTrue((self.root / 'state/credential-transition.json').exists())


if __name__ == '__main__':
    unittest.main()
