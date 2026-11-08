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

    def transition(self, fail='', mode='refresh', race=False):
        script = r'''
set -Eeuo pipefail
source "$1"
INSTALL_DIR=$2; export INSTALL_DIR
ENROLLMENT_TOKEN=header.payload.signature
LIVEPEER_API_URL=https://control.example.invalid
CREDENTIAL_TRANSITION=$TEST_MODE
LIVEPEER_RUNTIME_IMAGE=registry.invalid/runtime@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
chown() { :; }
managed_installation() { return 0; }
die() { printf '%s\n' "$*" >&2; exit 1; }
atomic_write() { cat > "$1.tmp"; chmod 0600 "$1.tmp"; mv "$1.tmp" "$1"; }
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
  if [[ "$*" == *'get deployment/kustomize-controller'* ]]; then printf '1'; fi
  if [[ "$FAIL_AT" == stop && "$*" == *'wait pod'* ]]; then return 1; fi
  if [[ "$FAIL_AT" == new-transfer && "$*" == *'wait externalartifact/livepeer-service'* ]]; then
    printf '%s\n' '{"stage":"handoff","epoch":"22222222-2222-4222-8222-222222222222"}' > "$INSTALL_DIR/volumes/http-source/system-layout.json"
    return 1
  fi
  if [[ "$*" == *'create secret generic livepeer-service-auth'* ]]; then
    [[ $(cat "$INSTALL_DIR/credentials/config-url") == https://* ]]
    [[ $(cat "$INSTALL_DIR/credentials/service-token") == cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ]]
    printf 'new-secret\n' >> "$INSTALL_DIR/steps"
  fi
  if [[ "$*" == 'apply -f -' ]]; then command cat >/dev/null; fi
}
stage_manifests() { printf 'https-code\n' >> "$INSTALL_DIR/steps"; }
curl() {
  local previous='' arg headers=''
  for arg in "$@"; do
    if [[ "$previous" == --dump-header ]]; then headers=$arg; fi
    previous=$arg
  done
  if [[ -n "$headers" ]]; then
    if [[ "$TEST_LAYOUT_RACE" == 1 ]]; then printf '%s\n' '{"stage":"handoff","epoch":"old-epoch"}' > "$INSTALL_DIR/volumes/http-source/system-layout.json"; fi
    printf 'HTTP/1.1 200 OK\r\nX-Livepeer-Terminal: true\r\nX-Livepeer-App-Cleanup-Ready: true\r\n' > "$headers"
    printf '200'
    return 0
  fi
  printf 'refresh\n' >> "$INSTALL_DIR/steps"
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
                              env={**os.environ, 'FAIL_AT': fail, 'TEST_MODE': mode,
                                   'TEST_LAYOUT_RACE': '1' if race else '0'}, text=True, capture_output=True)

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
        writer_stop = next(i for i, x in enumerate(steps) if 'scale deployment/kustomize-controller --replicas=0' in x)
        writer_gone = next(i for i, x in enumerate(steps) if 'wait pod -l app=kustomize-controller' in x)
        self.assertLess(writer_stop, writer_gone)
        self.assertLess(writer_gone, steps.index('refresh'))
        self.assertGreater(next(i for i, x in enumerate(steps) if 'scale deployment/kustomize-controller --replicas=1' in x), secret)
        self.assertLess(steps.index('https-code'), steps.index('refresh'))
        self.assertGreater(next(i for i, x in enumerate(steps) if 'rollout status' in x), secret)
        self.assertTrue(any('create secret generic livepeer-runner-bootstrap' in x for x in steps[:next(i for i,x in enumerate(steps) if 'rollout status' in x)]))

    def test_unconfirmed_consumer_termination_prevents_refresh(self):
        result = self.transition('stop')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'requests').exists())
        self.assertEqual((self.root / 'credentials/service-token').read_text(), 'b' * 64)
        self.assertTrue((self.root / 'state/credential-transition.json').exists())

    def test_reenrollment_rechecks_transfer_after_stopping_publishers(self):
        result = self.transition(mode='reenroll', race=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'requests').exists())
        self.assertEqual((self.root / 'credentials/service-token').read_text(), 'b' * 64)
        self.assertFalse((self.root / 'state/credential-transition.json').exists())

        steps = (self.root / 'steps').read_text()
        self.assertIn('scale deployment/livepeer-http-source --replicas=1', steps)
        self.assertIn('scale deployment/kustomize-controller --replicas=1', steps)
        # A resumed transition must perform the same stopped-publisher check.
        (self.root / 'state/credential-transition.json').write_text(json.dumps({
            'mode': 'reenroll', 'api': 'https://control.example.invalid',
            'operation': '11111111-1111-4111-8111-111111111111', 'expected': 0,
            'previous_epoch': 'legacy', 'cleanup_verified': True,
            'runtime_transition_format': 3, 'flux_replicas': 1,
        }))
        result = self.transition(mode='reenroll')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'requests').exists())
        self.assertFalse((self.root / 'state/credential-transition.json').exists())

    def test_new_enrollment_transfer_can_resume_but_unrelated_epoch_cannot(self):
        result = self.transition('new-transfer', mode='reenroll')
        self.assertNotEqual(result.returncode, 0)
        marker = self.root / 'state/credential-transition.json'
        transition = json.loads(marker.read_text())
        self.assertEqual(transition['issued_epoch'], '22222222-2222-4222-8222-222222222222')
        self.assertTrue(transition['layout_verified'])
        layout = self.root / 'volumes/http-source/system-layout.json'
        layout.write_text(json.dumps({'stage': 'handoff', 'epoch': '33333333-3333-4333-8333-333333333333'}))
        before = (self.root / 'requests').read_bytes()
        result = self.transition(mode='reenroll')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'requests').read_bytes(), before)
        layout.write_text(json.dumps({'stage': 'handoff', 'epoch': transition['issued_epoch']}))
        result = self.transition(mode='reenroll')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
