"""Enrollment protocol tests; never installs K3s or contacts a real API."""
import base64
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'bootstrap-livepeer.sh'

@unittest.skipUnless(sys.platform.startswith('linux'), 'bootstrap uses Linux host tools')
class SecretEnrollment(unittest.TestCase):
    def test_reset_replaces_key_once_and_interrupted_setup_reuses_it(self):
        grant = 'header.' + base64.urlsafe_b64encode(json.dumps({'exp': int(time.time()) + 3600}).encode()).decode().rstrip('=') + '.signature'
        with tempfile.TemporaryDirectory() as root:
            script = r'''source "$1"
INSTALL_DIR=$2
prepare_secrets_enrollment
target="$INSTALL_DIR/credentials/secrets"
printf '%s' "$TEST_SETUP" > "$target/setup"
printf management-sentinel > "$INSTALL_DIR/credentials/service-token"
mkdir -p "$INSTALL_DIR/bin"
printf '#!/bin/sh\nprintf "Encryption Status: Enabled\\nCurrent Rotation Stage: start\\n"\n' > "$INSTALL_DIR/bin/k3s"
chmod 700 "$INSTALL_DIR/bin/k3s"
NODE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaa
openssl genpkey -algorithm ED25519 -out "$INSTALL_DIR/service-key.pem" 2>/dev/null
kube() { :; }
chown() { :; }
curl() {
  printf '%s\0' "$@" >> "$INSTALL_DIR/process-args"
  local count=0
  if [[ -f "$INSTALL_DIR/count" ]]; then count=$(cat "$INSTALL_DIR/count"); fi
  count=$((count+1)); printf '%s' "$count" > "$INSTALL_DIR/count"
  if (( count==1 )); then printf '{"code":"identity_reset_required"}\n409'; return; fi
  if (( count==2 )); then return 1; fi
  local service_public reply proof signature headers digest authorization body
  while (($#)); do if [[ "$1" == --dump-header ]]; then headers=$2; shift; fi; shift; done
  service_public=$(openssl pkey -in "$INSTALL_DIR/service-key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)
  reply=$(jq -nc --arg node "$NODE_ID" --arg service "$service_public" '{node_id:$node,owner_id:"11111111-1111-4111-8111-111111111111",generation:1,service:{origin:"https://controlcenter-secrets.livepeer.live",public_key:$service}}')
  digest=$(printf '%s' "$request" | sha256sum)
  proof=$(jq -nc --arg body "${digest%% *}" '["POST","/v1/machines/enroll",$body]')
  digest=$(printf '%s' "$proof" | sha256sum)
  authorization=$(printf 'Bearer %s' "$setup_token" | sha256sum)
  body=$(printf '%s' "$reply" | sha256sum)
  proof=$(jq -nc --arg origin "$endpoint" --arg request "${digest%% *}" --arg authorization "${authorization%% *}" --arg body "${body%% *}" '["lpcc-secrets-response-v1",$origin,$request,$authorization,200,$body]')
  printf '%s' "$proof" > "$INSTALL_DIR/receipt-proof"
  signature=$(openssl pkeyutl -sign -rawin -inkey "$INSTALL_DIR/service-key.pem" -in "$INSTALL_DIR/receipt-proof" | base64 -w0)
  printf 'X-Livepeer-Service-Signature: %s\r\n' "$signature" > "$headers"
  printf '%s\n200' "$reply"
}
before=$(sha256sum "$target/key.pem")
enroll_secrets
replacement=$(sha256sum "$target/key.pem")
[[ "$before" != "$replacement" && -f "$target/setup" ]]
enroll_secrets
[[ "$replacement" == "$(sha256sum "$target/key.pem")" && ! -f "$target/setup" ]]
cmp "$target/key.pem" "$INSTALL_DIR/volumes/app-reconciler/secrets/key.pem"
[[ $(jq -r '.node_id' "$INSTALL_DIR/volumes/app-reconciler/secrets/identity.json") == "$NODE_ID" ]]
[[ $(stat -c %a "$target/key.pem") == 600 ]]
pin=$(cat "$target/service.json")
printf '%s' "$TEST_SETUP" > "$target/setup"
openssl genpkey -algorithm ED25519 -out "$INSTALL_DIR/service-key.pem" 2>/dev/null
enroll_secrets
[[ $(cat "$target/service.json") == "$pin" && -f "$target/setup" ]]
'''
            result = subprocess.run(['bash', '-c', script, 'fixture', str(SCRIPT), root],
                                    env={**os.environ, 'TEST_SETUP': grant}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(grant, result.stdout + result.stderr)
            self.assertNotIn(b'management-sentinel', (Path(root) / 'process-args').read_bytes())

    def test_expiry_cleanup_needs_no_enrollment_rerun(self):
        cleanup=SCRIPT.parent/'lib/expire-secrets-setup.sh'
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'setup'
            for remaining in (3600,-1):
                grant='header.'+base64.urlsafe_b64encode(json.dumps({'exp':int(time.time())+remaining}).encode()).decode().rstrip('=')+'.signature'
                path.write_text(grant);path.chmod(0o600)
                result=subprocess.run(['bash',str(cleanup),str(path)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(path.exists(),remaining>0)
                self.assertNotIn(grant,result.stdout+result.stderr)

    def test_combined_envelope_is_split_before_registration_and_retry_keeps_key(self):
        grant = 'header.' + base64.urlsafe_b64encode(json.dumps({'exp':int(time.time())+3600}).encode()).decode().rstrip('=') + '.signature'
        envelope = 'lpcc1.' + base64.urlsafe_b64encode(json.dumps({'version':1,'control':'control.jwt.signature','setup':grant}).encode()).decode().rstrip('=')
        with tempfile.TemporaryDirectory() as root:
            install = Path(root)/'installation'
            script = '''source "$1"
INSTALL_DIR=$2
install_setup_cleanup() { :; }
ENROLLMENT_TOKEN=$3
prepare_secrets_enrollment
[[ "$ENROLLMENT_TOKEN" == control.jwt.signature ]]
[[ -s "$INSTALL_DIR/credentials/secrets/setup" ]]
first=$(sha256sum "$INSTALL_DIR/credentials/secrets/key.pem")
proof=$(secrets_key_proof '')
printf '%s' '{"fingerprint":"fingerprint","hostname":"host","install_dir":"/opt/livepeer","k3s_version":"v1.37.2+k3s1"}' | registration_key_proof > "$INSTALL_DIR/signature.b64"
openssl pkey -in "$INSTALL_DIR/credentials/secrets/key.pem" -pubout -out "$INSTALL_DIR/public.pem" 2>/dev/null
[[ ${#SECRET_PUBLIC} == 44 && ${#proof} == 88 ]]
ENROLLMENT_TOKEN=''
prepare_secrets_enrollment
[[ "$first" == "$(sha256sum "$INSTALL_DIR/credentials/secrets/key.pem")" ]]
[[ $(stat -c %a "$INSTALL_DIR/credentials/secrets/setup") == 600 ]]
'''
            result=subprocess.run(['bash','-c',script,'test',str(SCRIPT),str(install),envelope],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn(grant,result.stdout+result.stderr)
            self.assertEqual((install/'credentials/secrets/setup').read_text(),grant)
            statement=json.dumps(['lpcc-registration-v1',hashlib.sha256(b'control.jwt.signature').hexdigest(),'fingerprint','host','/opt/livepeer','v1.37.2+k3s1',False,base64.b64encode(subprocess.check_output(['openssl','pkey','-pubin','-in',str(install/'public.pem'),'-outform','DER'],stderr=subprocess.DEVNULL)[-32:]).decode()],separators=(',',':')).encode()
            (install/'statement').write_bytes(statement)
            (install/'signature').write_bytes(base64.b64decode((install/'signature.b64').read_bytes()))
            verified=subprocess.run(['openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(install/'public.pem'),'-in',str(install/'statement'),'-sigfile',str(install/'signature')],capture_output=True)
            self.assertEqual(verified.returncode,0,verified.stderr)

class EnrollmentReplies(unittest.TestCase):
    def test_only_authenticated_replies_can_change_saved_credentials(self):
        grant = 'header.' + base64.urlsafe_b64encode(json.dumps({'exp': int(time.time()) + 3600}).encode()).decode().rstrip('=') + '.signature'
        for mode, replaced, removed in [('missing409', False, False), ('missing401', False, False), ('forged409', False, False), ('replay409', False, False), ('signed409', True, False), ('signed401', False, True), ('initial200', False, True), ('initial-forged200', False, False), ('changed200', False, False)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'credentials/secrets'
                target.mkdir(parents=True)
                (root / 'credentials/service-token').write_text('management-fixture')
                (target / 'key.pem').write_text('original-key')
                (target / 'setup').write_text(grant)
                (target / 'url').write_text('https://secrets.example')
                (target / 'new-cluster').touch()
                service_key = root / 'service.pem'
                subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(service_key)], check=True, capture_output=True)
                public = subprocess.check_output(['openssl', 'pkey', '-in', str(service_key), '-pubout', '-outform', 'DER'], stderr=subprocess.DEVNULL)[-32:]
                pin = json.dumps({'origin': 'https://secrets.example', 'public_key': base64.b64encode(public).decode()})
                # Exercise both persisted-pin locations, including interrupted setup.
                saved = target / 'service.json'
                if mode == 'forged409':
                    saved = root / 'volumes/app-reconciler/secrets/identity.json'
                    saved.parent.mkdir(parents=True)
                    saved.write_text(json.dumps({'service': json.loads(pin)}))
                elif not mode.startswith('initial'):
                    saved.write_text(pin)
                saved_bytes = saved.read_bytes() if saved.exists() else None
                (root / 'trust.json').write_text(pin)
                (root / 'bin').mkdir()
                k3s = root / 'bin/k3s'
                k3s.write_text('#!/bin/sh\nprintf "Encryption Status: Enabled\\n"\n')
                k3s.chmod(0o700)
                signer = root / 'reply.py'
                signer.write_text(r'''
import base64, hashlib, json, os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1]); mode = sys.argv[3]
count = root / 'calls'; n = int(count.read_text()) + 1 if count.exists() else 1; count.write_text(str(n))
request = sys.stdin.read()
status = 200 if mode.endswith('200') else 401 if mode.endswith('401') else 409 if n == 1 else 503
identity = {'node_id': json.loads(request)['node_id'], 'owner_id': '11111111-1111-4111-8111-111111111111', 'generation': 1, 'service': json.loads((root / 'trust.json').read_text())}
if mode == 'changed200': identity['service']['public_key'] = base64.b64encode(bytes(32)).decode()
body = json.dumps(identity if status == 200 else {'code': 'identity_reset_required' if status == 409 else 'grant_refused' if status == 401 else 'unavailable'}, separators=(',', ':')) + '\n'
hash = lambda value: hashlib.sha256(value.encode()).hexdigest()
compact = lambda value: json.dumps(value, separators=(',', ':'))
signed_request = request + ' ' if mode == 'replay409' else request
proof = compact(['lpcc-secrets-response-v1', 'https://secrets.example', hash(compact(['POST', '/v1/machines/enroll', hash(signed_request)])), hash('Bearer ' + os.environ['TEST_SETUP']), status, hash(body)])
(root / 'proof').write_text(proof)
signature = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(root / 'service.pem'), '-in', str(root / 'proof')])
if mode in ('forged409', 'initial-forged200'): signature = bytes([signature[0] ^ 1]) + signature[1:]
pathlib.Path(sys.argv[2]).write_text('HTTP/1.1 %d OK\r\n' % status + ('' if mode.startswith('missing') else 'X-Livepeer-Service-Signature: ' + base64.b64encode(signature).decode() + '\r\n') + '\r\n')
sys.stdout.write(body + '\n' + str(status))
''')
                script = r'''set -Eeuo pipefail
source "$1"
INSTALL_DIR=$2
NODE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaa
log() { printf '%s\n' "$*" >&2; }
die() { log "$*"; exit 1; }
atomic_write() { cat > "$1"; }
kube() { :; }
chown() { :; }
SECRET_PUBLIC=runtime-public-fixture
secrets_key_proof() { printf proof-fixture; }
replace_secrets_key() { printf replacement-key > "$INSTALL_DIR/credentials/secrets/key.pem"; SECRET_PUBLIC=replacement-public; }
if ! command -v sha256sum >/dev/null; then sha256sum() { shasum -a 256; }; fi
curl() {
  local headers=''
  while (($#)); do if [[ "$1" == --dump-header ]]; then headers=$2; shift; fi; shift; done
  printf '%s' "$request" | "$TEST_PYTHON" "$INSTALL_DIR/reply.py" "$INSTALL_DIR" "$headers" "$TEST_MODE"
}
enroll_secrets
'''
                result = subprocess.run(['bash', '-c', script, 'fixture', str(SCRIPT.parent / 'lib/credentials.sh'), str(root)], env={**os.environ, 'TEST_SETUP': grant, 'TEST_MODE': mode, 'TEST_PYTHON': sys.executable}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1 if mode == 'changed200' else 0, result.stderr)
                if mode == 'changed200':
                    self.assertIn('secrets service identity changed', result.stderr)
                self.assertEqual((target / 'key.pem').read_text(), 'replacement-key' if replaced else 'original-key')
                self.assertEqual((target / 'setup').exists(), not removed)
                if saved_bytes is not None:
                    self.assertEqual(saved.read_bytes(), saved_bytes)
                elif mode == 'initial200':
                    self.assertEqual(json.loads(saved.read_text()), json.loads(pin))
                else:
                    self.assertFalse(saved.exists())
                self.assertEqual(int((root / 'calls').read_text()), 2 if replaced else 1)
                self.assertNotIn(grant, result.stdout + result.stderr)
