# Discovery authentication rollout

Build and retain the Stage 1 release before deploying Stage 2. Operators migrate
existing resources separately from deployment; application startup does not
convert them.

## Stage 1: Ed25519 and ingress

New installations enable bundled Traefik as ClusterIP, retaining disabled
ServiceLB. Cloudflared forwards API, discovery and app requests to private
entrypoints 8080, 8081 and 8082 respectively. Its API/discovery Host override
remains `orchestrator.livepeer.svc.cluster.local:8935`; application Host values
remain unchanged. Traefik forwards these values unchanged. API/app isolation
also applies at ingress.

`livepeer-runtime ingress-auth` runs a persistent HTTP server. Traefik calls
`GET /authorize` using ForwardAuth; successful verification returns 204,
invalid/missing bearer credentials return 401, and service failure denies access.
`GET /readyz` is private. Only public verification keys and the intended node ID
are mounted. Neither signing nor verification calls the secrets service.

Generate and retain an independent Ed25519 key outside the deployment:

```sh
openssl genpkey -algorithm ED25519 -out jwt-signing-key.pem
chmod 0600 jwt-signing-key.pem
```

Mount it read-only, readable by the API identity (UID 65532), and configure
`JWTSigningPrivateKeyFile`. `JWTSigningKeyID` defaults to `1`.
`JWTVerificationPublicKeysFile` optionally names a JSON object mapping key IDs
to standard-base64 32-byte Ed25519 public keys. The current public key is
included automatically. Private material never enters machine artifacts.

Enrollment grants, orchestrator claims, invitations and discovery use EdDSA.
Old HMAC tokens are invalid immediately. Supabase sessions, the independent
secrets service's tokens and machine credential authentication are unchanged.
Discovery tokens have issuer `livepeer-control-center`, audience
`livepeer-discovery`, scope `discovery:read`, node ID subject, issued-at and
expiration. Their lifetime is five minutes with 30 seconds of clock tolerance.
Only the exact configured HTTPS discovery source receives its credentials;
redirects remain disabled. Stage 1 sends both Access credentials and a bearer.

### Existing-resource migration: approved maintenance window

Prepare release images, mounted signing configuration, and an ownership-scoped
inventory of existing tunnels and Access resources. Stop Control Center
reconciliation before changing existing infrastructure. Outside deployment:

1. Install the new bootstrap Traefik configuration before enabling Traefik and
   restarting K3s. Apply the new management observation RBAC and explicitly
   upgrade the bootstrap-owned `flux-system/livepeer-http-source` Deployment to
   the Stage 1 Runtime image, preserving its installed credentials and state.
   Control Center's `RuntimeImage` does not upgrade this Deployment.
2. Apply the release's generated ingress routes, public-key ConfigMap and
   `ingress-auth` Deployment. Also update the existing `livepeer-tunnel`
   NetworkPolicy in `flux-system` and `orchestrator-private` NetworkPolicy in
   `livepeer` to permit cloudflared → Traefik → Node. Coordinate their existing
   Flux owners so reconciliation cannot restore the old policies during cutover.
   Verify private routing, Host preservation and auth after both policies apply.
3. Switch existing tunnel origin destinations to the corresponding private
   entrypoints. Keep Cloudflare Access and Host rewrites intact.
4. Update the routing ledger under the existing revision/lease contract:
   `ingress_version=1`, applied rules/digest and provider version must describe
   the actual provider configuration. Invalidate old readiness/source evidence.
5. Start Stage 1 with the new key configuration and resume reconciliation.

If an existing tunnel lacks ingress version 1, the application retains the last
published artifact rather than converting it. Preserve tunnel UUIDs, DNS records, certificates,
enrollments and connector credentials throughout the external procedure.

Accept Stage 1 only after real external checks prove that Access plus a valid
bearer succeeds, and Access plus missing, invalid, expired or wrong-machine
bearers fails. Check API/app isolation and actual Host values. Readiness evidence
is bound to the ingress digest and source generation; changed inputs require
new evidence. Public-key distribution has a separate Flux inventory/digest and
does not change Node's drain/replacement digest.
Require a fresh Runtime report with `ingress_ready=true` and the expected
`ingress_config_digest` before accepting Stage 1.

If preparation fails, keep the old origins and Access protection. After the
signing cutover, restoring an old binary also requires its old configuration;
invalidated HMAC tokens are not restored by the new release.

## Stage 2: retire Access separately

Require accepted Stage 1 evidence. Before the first Stage 2 process starts,
refresh the ownership-scoped inventory of Access provider identifiers from the
routing ledger and credential table. Startup automatically applies SQL migration
013, which drops the credential table. Ciphertext is unnecessary for provider
deletion.

Deploy the Stage 2 release with `CloudflareEnabled=false` while leaving discovery
enabled. Outside deployment,
remove Access audience enforcement from existing tunnel configurations,
delete ownership-proven Access policies/applications/service tokens, confirm
provider absence, and remove their ledger entries.

Verify bearer-only success, missing/invalid bearer rejection, isolation and Host
preservation; then re-enable tunnel reconciliation. Brief discovery poll
failures use the existing retained-inventory policy and its existing limits.
Existing connectors can keep serving during provider cleanup. Restarting or
replacing one while reconciliation is disabled interrupts that machine's API
and app ingress until token delivery is re-enabled. Keeping the Stage 1
`RuntimeConnectorImage` digest avoids a planned connector replacement during
this window. Removal of obsolete Node header filters uses the existing
session-drain gate; public-key updates remain independent of Node rollout.
Keep external cleanup
restartable using a private operation record; do not discard unconfirmed work.

Do not run a Stage 1 reconciler during cleanup; it would restore protection. Deleting Access credentials is irreversible;
rollback requires explicitly reprovisioning protection rather than restarting
the old release with deleted resources.

## Subsequent key rotation

Distribute the next public key while signing with the current key. Confirm the
new ingress digest is applied, then switch the private key and signing ID.
Retain the previous public key for at least 24 hours after its last issuance,
covering invitations as well as shorter-lived tokens. Remove it in another
public-key rollout. Restarting `ingress-auth` never requires secret-service access.
