"""Linux enrollment protocol tests; never starts K3s or contacts a real API."""
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
  local service_public reply proof signature
  service_public=$(openssl pkey -in "$INSTALL_DIR/service-key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)
  reply=$(jq -nc --arg node "$NODE_ID" --arg public "$SECRET_PUBLIC" --arg nonce "$(jq -r '.nonce' <<< "$request")" --arg service "$service_public" '{node_id:$node,owner_id:"11111111-1111-4111-8111-111111111111",generation:1,public_key:$public,nonce:$nonce,service:{origin:"https://controlcenter-secrets.livepeer.live",public_key:$service}}')
  proof=$(jq -c '["lpcc-secrets-enrollment-v1",.service.origin,.service.public_key,.node_id,.owner_id,.generation,.public_key,.nonce]' <<< "$reply")
  printf '%s' "$proof" > "$INSTALL_DIR/receipt-proof"
  signature=$(openssl pkeyutl -sign -rawin -inkey "$INSTALL_DIR/service-key.pem" -in "$INSTALL_DIR/receipt-proof" | base64 -w0)
  jq -c --arg signature "$signature" '. + {receipt_signature:$signature}' <<< "$reply"
  printf '\n200'
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
if (enroll_secrets); then exit 1; fi
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
