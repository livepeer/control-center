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
        for name in ('credentials', 'state', 'config', 'volumes/http-source'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / 'credentials/node-id').write_text('a' * 26)
        (self.root / 'credentials/fingerprint').write_text('a' * 64)
        (self.root / 'credentials/service-token').write_text('b' * 64)
        (self.root / 'credentials/runner-bootstrap.secret').write_text('runner-bootstrap')
        (self.root / 'credentials/config-url').write_text('https://control.example.invalid/v1/nodes/' + 'a' * 26 + '/config')
        (self.root / 'credentials/identity.json').write_text(json.dumps({'node_id': 'a' * 26, 'credential_version': 1}))
        (self.root / 'state/k3s-version').write_text('v1.37.10+k3s1')

    def transition(self, fail='', mode='refresh', node='c' * 26, nodes='node/worker', api='https://control.example.invalid'):
        script = r'''
set -Eeuo pipefail
source "$1"
INSTALL_DIR=$2; export INSTALL_DIR
if [[ -n $TEST_API ]]; then LIVEPEER_API_URL=$TEST_API; else unset LIVEPEER_API_URL; fi
CREDENTIAL_TRANSITION=$TEST_MODE
SECRET_PUBLIC=$(command cat "$INSTALL_DIR/fake-public-key" 2>/dev/null || printf public-fixture)
replace_secrets_key() { SECRET_PUBLIC=replacement-fixture; printf '%s' "$SECRET_PUBLIC" > "$INSTALL_DIR/fake-public-key"; printf 'key-rotated\n' >> "$INSTALL_DIR/steps"; }
secrets_key_proof() { printf signature-fixture; }
registration_key_proof() { command cat >/dev/null; printf registration-proof-sentinel; }
jq() { printf '%s\0' "$@" >> "$INSTALL_DIR/process-args"; command jq "$@"; }
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
  if [[ "$*" == 'get nodes -o name' ]]; then printf '%s' "$TEST_NODES"; fi
  if [[ "$*" == *'get deployment/kustomize-controller'* ]]; then printf '1'; fi
  if [[ "$FAIL_AT" == stop && "$*" == *'wait pod'* ]]; then return 1; fi
  if [[ "$FAIL_AT" == artifact && "$*" == *'wait externalartifact/livepeer-service'* ]]; then return 1; fi
  if [[ "$*" == *'create secret generic livepeer-service-auth'* ]]; then
    [[ -z "$ENROLLMENT_TOKEN" ]]
    [[ $(cat "$INSTALL_DIR/credentials/config-url") == https://* ]]
    [[ $(cat "$INSTALL_DIR/credentials/service-token") == cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ]]
    printf 'new-secret\n' >> "$INSTALL_DIR/steps"
  fi
  if [[ "$*" == 'apply -f -' ]]; then command cat >/dev/null; fi
}
stage_manifests() { printf 'https-code\n' >> "$INSTALL_DIR/steps"; }
curl() {
  printf '%s\0' "$@" >> "$INSTALL_DIR/process-args"
  local previous='' arg headers=''
  for arg in "$@"; do
    if [[ "$previous" == --dump-header ]]; then headers=$arg; fi
    previous=$arg
  done
  if [[ -n "$headers" ]]; then
    printf 'HTTP/1.1 200 OK\r\nX-Livepeer-Terminal: true\r\nX-Livepeer-App-Cleanup-Ready: true\r\n' > "$headers"
    printf '200'
    return 0
  fi
  printf 'refresh\n' >> "$INSTALL_DIR/steps"
  for arg in "$@"; do
    if [[ "$previous" == --data-binary ]]; then
      if [[ "$arg" == @* ]]; then command cat "${arg#@}" >> "$INSTALL_DIR/requests"; printf '\n' >> "$INSTALL_DIR/requests"
      else printf '%s\n' "$arg" >> "$INSTALL_DIR/requests"; fi
    fi
    previous=$arg
  done
  [[ "$FAIL_AT" != request ]] || return 1
  printf '{"node_id":"%s","token":"%s","credential_version":1,"config_url":"%s/v1/nodes/%s/config"}\n200' \
    "$TEST_NODE" cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc "${TEST_API:-https://controlcenter-api.livepeer.live}" "$TEST_NODE"
}
transition_credentials
'''
        return subprocess.run(['bash', '-c', script, 'fixture', str(LIBRARY.parent.parent / 'bootstrap-livepeer.sh'), str(self.root)],
                              env={**os.environ, 'LIVEPEER_ENROLLMENT_TOKEN': 'header.payload.signature',
                                   'FAIL_AT': fail, 'TEST_MODE': mode, 'TEST_NODE': ('a' * 26 if mode == 'refresh' else node), 'TEST_NODES': nodes, 'TEST_API': api or ''},
                              text=True, capture_output=True)

    def test_custom_origin_omission_fails_before_state_or_consumers_change(self):
        result = self.transition(api=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('LIVEPEER_API_URL', result.stderr)
        self.assertFalse((self.root / 'state/credential-transition.json').exists())
        self.assertFalse((self.root / 'steps').exists())
        self.assertEqual((self.root / 'credentials/service-token').read_text(), 'b' * 64)
        # The correct explicit endpoint still works, including HTTP-to-HTTPS refresh.
        (self.root / 'credentials/config-url').write_text('http://control.example.invalid/v1/nodes/' + 'a' * 26 + '/config')
        result = self.transition()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_standard_origin_refresh_can_omit_api_override(self):
        (self.root / 'credentials/config-url').write_text('https://controlcenter-api.livepeer.live/v1/nodes/' + 'a' * 26 + '/config')
        result = self.transition(api=None)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_identity_requires_base32_node_and_positive_numeric_version(self):
        for identity, valid in [
            ({'node_id': 'a' * 26, 'credential_version': 1}, True),
            ({'node_id': 'a' * 36, 'credential_version': 1}, False),
            ({'node_id': 'a' * 26, 'credential_version': '1'}, False),
            ({'node_id': 'a' * 26, 'credential_version': 0}, False),
            ({'node_id': 'a' * 26, 'credential_version': 1.5}, False),
        ]:
            result = subprocess.run(['bash', '-c', 'source "$1"; read_identity "$2"',
                                     'fixture', str(LIBRARY), json.dumps(identity)], capture_output=True)
            self.assertEqual(result.returncode == 0, valid, identity)

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
        self.assertLess(steps.index('refresh'), steps.index('https-code'))
        self.assertGreater(next(i for i, x in enumerate(steps) if 'rollout status' in x), secret)
        self.assertTrue(any('create secret generic livepeer-runner-bootstrap' in x for x in steps[:next(i for i,x in enumerate(steps) if 'rollout status' in x)]))

    def test_management_proof_is_in_body_and_never_process_arguments(self):
        for mode in ('refresh', 'reenroll'):
            with self.subTest(mode=mode):
                result = self.transition(mode=mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                request = json.loads((self.root / 'requests').read_text().splitlines()[-1])
                self.assertIn(request['management_proof'], ('b' * 64, 'c' * 64))
                if mode == 'reenroll':
                    self.assertEqual(request['public_key'], 'replacement-fixture')
                    self.assertEqual(request['signature'], 'registration-proof-sentinel')
                    self.assertNotIn(b'registration-proof-sentinel', (self.root / 'process-args').read_bytes())
                arguments = (self.root / 'process-args').read_bytes()
                self.assertNotIn(b'b' * 64, arguments)
                self.assertNotIn(b'c' * 64, arguments)

    def test_unconfirmed_consumer_termination_prevents_refresh(self):
        result = self.transition('stop')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'requests').exists())
        self.assertEqual((self.root / 'credentials/service-token').read_text(), 'b' * 64)
        self.assertTrue((self.root / 'state/credential-transition.json').exists())

    def test_reenrollment_resume_preserves_prior_owner_state(self):
        state = self.root / 'volumes/app-reconciler/state'
        state.mkdir(parents=True)
        (state / 'journal').write_text('previous owner')
        secrets=state.parent/'secrets';secrets.mkdir()
        for name in ('managed','key.pem','certificate.pem'): (secrets/name).write_text('old enrollment')
        (self.root/'k3s/server').mkdir(parents=True)
        (self.root/'config/k3s.yaml').write_text('data-dir: fixture\n')
        result = self.transition('artifact', mode='reenroll')
        self.assertNotEqual(result.returncode, 0)
        archived = state.parent / 'state.aaaaaaaaaaaaaaaaaaaaaaaaaa/journal'
        self.assertEqual(archived.read_text(), 'previous owner')
        self.assertTrue((self.root / 'state/credential-transition.json').exists())
        self.assertFalse((secrets/'managed').exists())
        self.assertNotIn('secrets-encryption: true',(self.root/'config/k3s.yaml').read_text())
        result = self.transition(mode='reenroll')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(archived.read_text(), 'previous owner')
        self.assertFalse((self.root / 'state/credential-transition.json').exists())
        self.assertTrue((state.parent / 'reenrolled-cccccccccccccccccccccccccc').exists())

    def test_reenrollment_changes_key_once_and_retries_with_its_proof(self):
        self.assertNotEqual(self.transition('request', mode='reenroll').returncode, 0)
        self.assertEqual(self.transition(mode='reenroll').returncode, 0)
        requests = [json.loads(x) for x in (self.root / 'requests').read_text().splitlines()]
        self.assertEqual(requests[0]['public_key'], 'replacement-fixture')
        self.assertEqual(requests[0]['public_key'], requests[1]['public_key'])
        self.assertEqual((self.root / 'steps').read_text().count('key-rotated'), 1)

    def test_reenrollment_resume_rejects_a_different_issued_identity(self):
        self.assertNotEqual(self.transition('artifact', mode='reenroll').returncode, 0)
        identity = (self.root / 'credentials/identity.json').read_bytes()
        result = self.transition(mode='reenroll', node='d' * 26)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('different identity', result.stderr)
        self.assertEqual((self.root / 'credentials/identity.json').read_bytes(), identity)
        self.assertTrue((self.root / 'state/credential-transition.json').exists())

    def test_reenrollment_stops_prior_node_before_issuing_credentials(self):
        result = self.transition(mode='reenroll')
        self.assertEqual(result.returncode, 0, result.stderr)
        steps = (self.root / 'steps').read_text().splitlines()
        self.assertIn('livepeer.io/node-id=' + 'c' * 26, (self.root / 'config/k3s.yaml').read_text())
        relabel = steps.index('kube label node/worker livepeer.io/node-id=' + 'c' * 26 + ' --overwrite')
        self.assertLess(relabel, steps.index('https-code'))
        stopped = next(i for i, x in enumerate(steps) if 'wait pod -l app=orchestrator' in x)
        self.assertLess(stopped, steps.index('refresh'))

    def test_reenrollment_rejects_empty_or_multinode_clusters_before_issuance(self):
        for nodes in ('', 'node/one\nnode/two'):
            result = self.transition(mode='reenroll', nodes=nodes)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('exactly one', result.stderr)
            self.assertFalse((self.root / 'requests').exists())
            self.assertEqual((self.root / 'credentials/node-id').read_text(), 'a' * 26)

    def test_refresh_keeps_node_for_authoritative_managed_drain(self):
        result = self.transition()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('scale deployment/orchestrator', (self.root / 'steps').read_text())


if __name__ == '__main__':
    unittest.main()
