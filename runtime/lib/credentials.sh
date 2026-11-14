#!/usr/bin/env bash
# Explicit, resumable machine-credential transitions. Never changes K3s versions.

control_transport() {
  if [[ ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} == 1 ]]; then printf 'development-http'; else printf 'https'; fi
}

api_url() {
  local api=${LIVEPEER_API_URL:-https://controlcenter-api.livepeer.live}
  api=${api%/}
  [[ "$api" =~ ^https?://[a-zA-Z0-9_.:-]+(/[a-zA-Z0-9_.-]+)*$ ]] || die 'invalid LIVEPEER_API_URL: expected an API base URL'
  printf '%s' "$api"
}

runtime_image() {
  RUNTIME_IMAGE=''
  if [[ ${LIVEPEER_RUNTIME_IMAGE+x} ]]; then
    RUNTIME_IMAGE=$LIVEPEER_RUNTIME_IMAGE
  elif [[ -f "$INSTALL_DIR/state/runtime-image" ]]; then
    RUNTIME_IMAGE=$(cat "$INSTALL_DIR/state/runtime-image")
  elif [[ -n ${SCRIPT_DIR:-} && -f "$SCRIPT_DIR/release-runtime-image" ]]; then
    RUNTIME_IMAGE=$(cat "$SCRIPT_DIR/release-runtime-image")
  fi
  [[ "$RUNTIME_IMAGE" =~ ^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$ ]] || die 'set LIVEPEER_RUNTIME_IMAGE to a built Go Runtime image pinned by digest'
}

verify_retired_apps() {
  local headers code token
  headers=$(mktemp "$INSTALL_DIR/state/cleanup-headers.XXXXXX")
  token=$(cat "$INSTALL_DIR/credentials/service-token")
  code=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' \
    --dump-header "$headers" --output /dev/null --write-out '%{http_code}' \
    --config <(printf 'header = "Authorization: Bearer %s"\n' "$token") \
    "$1/v1/nodes/$NODE_ID/config") || { rm -f -- "$headers"; die 'cannot verify prior app cleanup; keep the existing enrollment running'; }
  if [[ "$code" != 200 ]] ||
      ! tr -d '\r' < "$headers" | grep -Eiq '^X-Livepeer-Terminal: true$' ||
      ! tr -d '\r' < "$headers" | grep -Eiq '^X-Livepeer-App-Cleanup-Ready: true$'; then
    rm -f -- "$headers"
    die 'finish app and registration cleanup for the retired enrollment before re-enrolling this installation'
  fi
  rm -- "$headers"
}

read_identity() {
  local identity="$1"
  IDENTITY_NODE_ID=$(jq -er '.node_id | select(type == "string")' <<< "$identity") || return 1
  CREDENTIAL_VERSION=$(jq -er '.credential_version | select(type == "number" and . >= 1 and . == floor)' <<< "$identity") || return 1
  [[ "$IDENTITY_NODE_ID" =~ ^[a-z2-7]{26}$ && "$CREDENTIAL_VERSION" =~ ^[1-9][0-9]*$ ]]
}

save_identity() {
  local identity
  identity=$(jq -nc --arg node_id "$IDENTITY_NODE_ID" --argjson version "$CREDENTIAL_VERSION" '{node_id:$node_id,credential_version:$version}')
  if [[ -f "$INSTALL_DIR/credentials/identity.json" && $(cat "$INSTALL_DIR/credentials/identity.json") == "$identity" ]]; then return; fi
  printf '%s\n' "$identity" | atomic_write "$INSTALL_DIR/credentials/identity.json"
}

install_machine_secret() {
  kube -n flux-system create secret generic livepeer-service-auth \
    --from-file="token=$INSTALL_DIR/credentials/service-token" \
    --from-file="config-url=$INSTALL_DIR/credentials/config-url" \
    --from-file="identity.json=$INSTALL_DIR/credentials/identity.json" \
    --from-file="runtime-key.pem=$INSTALL_DIR/credentials/secrets/key.pem" \
    --dry-run=client -o yaml | kube apply -f -
  kube -n flux-system create secret generic livepeer-runner-bootstrap \
    --from-file="secret=$INSTALL_DIR/credentials/runner-bootstrap.secret" \
    --dry-run=client -o yaml | kube apply -f -
}

stop_credential_consumers() {
  local replicas
  if ! jq -e '.flux_replicas != null' "$INSTALL_DIR/state/credential-transition.json" >/dev/null; then
    replicas=$(kube -n flux-system get deployment/kustomize-controller -o jsonpath='{.spec.replicas}')
    [[ "$replicas" =~ ^[0-9]+$ ]] || die 'cannot establish the Flux writer replica count'
    jq --argjson replicas "$replicas" '. + {flux_replicas:$replicas}' "$INSTALL_DIR/state/credential-transition.json" | \
      atomic_write "$INSTALL_DIR/state/credential-transition.json"
  fi
  # Suspending a Kustomization does not stop an in-flight apply. Terminate the
  # writer before stopping consumers so no sibling or app path can recreate one.
  kube -n flux-system scale deployment/kustomize-controller --replicas=0
  kube -n flux-system wait pod -l app=kustomize-controller --for=delete --timeout=120s
  kube -n flux-system scale deployment/livepeer-http-source --replicas=0
  if kube -n flux-system get deployment/livepeer-app-reconciler >/dev/null 2>&1; then
    kube -n flux-system scale deployment/livepeer-app-reconciler --replicas=0
  fi
  kube -n flux-system delete deployment/livepeer-tunnel --ignore-not-found --wait=true
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    # Old app cleanup is already confirmed; stop its Node before issuing credentials.
    if kube -n livepeer get deployment/orchestrator >/dev/null 2>&1; then
      kube -n livepeer scale deployment/orchestrator --replicas=0
    fi
    kube -n livepeer wait pod -l app=orchestrator --for=delete --timeout=120s
  fi
  # Replica count alone does not prove old HTTP-speaking processes terminated.
  kube -n flux-system wait pod -l app=livepeer-http-source --for=delete --timeout=120s
  kube -n flux-system wait pod -l app=livepeer-app-reconciler --for=delete --timeout=120s
  kube -n flux-system wait pod -l app=livepeer-tunnel --for=delete --timeout=120s
}

transition_credentials() {
  local api fingerprint operation expected response status request metadata previous_node issued_node apps replicas cluster_node
  managed_installation || die 'credential transition requires an initialized installation'
  [[ -s "$INSTALL_DIR/credentials/runner-bootstrap.secret" ]] || die 'restore the runner bootstrap credential before changing credentials'
  runtime_image
  [[ -n "$ENROLLMENT_TOKEN" ]] || die 'credential transition requires LIVEPEER_ENROLLMENT_TOKEN with a fresh owner enrollment JWT'
  [[ "$ENROLLMENT_TOKEN" =~ ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ ]] || die 'invalid enrollment JWT'
  api=$(api_url)
  [[ "$api" == https://* ]] || die 'set LIVEPEER_API_URL to the verified HTTPS API'
  NODE_ID=$(cat "$INSTALL_DIR/credentials/node-id")
  [[ "$NODE_ID" =~ ^[a-z2-7]{26}$ ]] || die 'invalid saved machine ID'
  if [[ -z ${LIVEPEER_API_URL:-} ]]; then
    [[ -s "$INSTALL_DIR/credentials/config-url" && $(< "$INSTALL_DIR/credentials/config-url") == "$api/v1/nodes/$NODE_ID/config" ]] ||
      die 'set LIVEPEER_API_URL to the original verified HTTPS API before changing credentials'
  fi
  fingerprint=$(printf '%s' "$(cat /etc/machine-id)" | sha256sum); fingerprint=${fingerprint:0:64}
  [[ $(cat "$INSTALL_DIR/credentials/fingerprint") == "$fingerprint" ]] || die 'installation fingerprint changed'
  if [[ -f "$INSTALL_DIR/state/credential-transition.json" ]]; then
    metadata=$(cat "$INSTALL_DIR/state/credential-transition.json")
    [[ $(jq -r '.mode' <<< "$metadata") == "$CREDENTIAL_TRANSITION" ]] || die 'resume the existing credential transition mode'
    [[ $(jq -r '.api' <<< "$metadata") == "$api" ]] || die 'resume with the original HTTPS API'
  else
    if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then verify_retired_apps "$api"; fi
    operation=$(cat /proc/sys/kernel/random/uuid)
    [[ -s "$INSTALL_DIR/credentials/identity.json" ]] || die 'restore the enrollment identity before changing credentials'
    read_identity "$(cat "$INSTALL_DIR/credentials/identity.json")" || die 'invalid saved enrollment identity'
    expected=$CREDENTIAL_VERSION
    previous_node=$IDENTITY_NODE_ID
    jq -nc --arg mode "$CREDENTIAL_TRANSITION" --arg api "$api" --arg operation "$operation" --argjson expected "$expected" --arg previous_node "$previous_node" \
      '{mode:$mode,api:$api,operation:$operation,expected:$expected,previous_node:$previous_node,cleanup_verified:($mode=="reenroll")}' | atomic_write "$INSTALL_DIR/state/credential-transition.json"
    metadata=$(cat "$INSTALL_DIR/state/credential-transition.json")
  fi
  previous_node=$(jq -er '.previous_node' <<< "$metadata")
  [[ "$previous_node" =~ ^[a-z2-7]{26}$ ]] || die 'invalid previous enrollment identity'
  jq -e '.expected | type == "number" and . >= 1' <<< "$metadata" >/dev/null || die 'invalid credential transition version'
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    cluster_node=$(kube get nodes -o name)
    [[ "$cluster_node" == node/* && "$cluster_node" != *$'\n'* ]] || die 're-enrollment requires exactly one Kubernetes node'
    if ! jq -e '.secrets_key_rotated == true' "$INSTALL_DIR/state/credential-transition.json" >/dev/null; then
      replace_secrets_key
      jq '. + {secrets_key_rotated:true}' "$INSTALL_DIR/state/credential-transition.json" | atomic_write "$INSTALL_DIR/state/credential-transition.json"
    fi
  fi
  stop_credential_consumers
  install -d -m 0700 "$INSTALL_DIR/volumes/app-reconciler"
  chown 65532:65532 "$INSTALL_DIR/volumes/app-reconciler"
  install -d -m 0700 "$INSTALL_DIR/volumes/management-sockets" \
    "$INSTALL_DIR/volumes/management-sockets/connector" "$INSTALL_DIR/volumes/management-sockets/apps" "$INSTALL_DIR/volumes/management-sockets/orchestrator"
  chown 65532:65532 "$INSTALL_DIR/volumes/management-sockets" \
    "$INSTALL_DIR/volumes/management-sockets/connector" "$INSTALL_DIR/volumes/management-sockets/apps" "$INSTALL_DIR/volumes/management-sockets/orchestrator"
  printf '%s\n' "$RUNTIME_IMAGE" | atomic_write "$INSTALL_DIR/state/runtime-image"
  LIVEPEER_ALLOW_DEVELOPMENT_HTTP=0
  CONFIG_URL="$api/v1/nodes/$NODE_ID/config"
  if [[ "$CREDENTIAL_TRANSITION" == refresh ]]; then
    request=$(jq -nc --rawfile management_proof "$INSTALL_DIR/credentials/service-token" --arg fingerprint "$fingerprint" --arg install_dir "$INSTALL_DIR" \
      --arg operation_id "$(jq -r '.operation' <<< "$metadata")" --argjson expected "$(jq -r '.expected' <<< "$metadata")" \
      '{management_proof:$management_proof,fingerprint:$fingerprint,install_dir:$install_dir,operation_id:$operation_id,expected_credential_version:$expected}')
    response=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' \
      --write-out '\n%{http_code}' --request POST --header 'Content-Type: application/json' \
      --config <(printf 'header = "Authorization: Bearer %s"\n' "$ENROLLMENT_TOKEN") \
      --data-binary @<(printf '%s' "$request") "$api/v1/nodes/$NODE_ID/credentials/refresh") || die 'HTTPS credential refresh failed; transition remains suspended'
  else
    request=$(jq -nc --arg fingerprint "$fingerprint" --arg hostname "$(hostname)" --arg install_dir "$INSTALL_DIR" \
      --arg version "$(cat "$INSTALL_DIR/state/k3s-version")" '{fingerprint:$fingerprint,hostname:$hostname,install_dir:$install_dir,k3s_version:$version}')
    request=$(jq -c --arg public "$SECRET_PUBLIC" --rawfile signature <(registration_key_proof <<< "$request") '.+{public_key:$public,signature:$signature}' <<< "$request")
    response=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' \
      --write-out '\n%{http_code}' --request POST --header 'Content-Type: application/json' \
      --config <(printf 'header = "Authorization: Bearer %s"\n' "$ENROLLMENT_TOKEN") \
      --data-binary @<(printf '%s' "$request") "$api/v1/nodes/register") || die 'HTTPS re-enrollment failed; transition remains suspended'
  fi
  ENROLLMENT_TOKEN=''
  status=${response##*$'\n'}; [[ "$status" == 200 ]] || die 'credential transition did not return HTTP 200; resume with the same operation'
  response=${response%$'\n'*}
  if [[ "$CREDENTIAL_TRANSITION" == refresh ]]; then
    [[ $(jq -r '.node_id' <<< "$response") == "$NODE_ID" ]] || die 'credential refresh returned a different node'
  else
    NODE_ID=$(jq -er '.node_id | select(type == "string")' <<< "$response")
    [[ "$NODE_ID" =~ ^[a-z2-7]{26}$ && "$NODE_ID" != "$previous_node" ]] || die 're-enrollment did not issue a fresh node'
    CONFIG_URL="$api/v1/nodes/$NODE_ID/config"
  fi
  [[ $(jq -r '.config_url' <<< "$response") == "$CONFIG_URL" ]] || die 'credential destination changed'
  SERVICE_TOKEN=$(jq -er '.token' <<< "$response")
  read_identity "$response" || die 'invalid refreshed machine identity'
  [[ "$SERVICE_TOKEN" =~ ^[a-f0-9]{64}$ ]] || die 'invalid refreshed machine credential'
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    issued_node=$(jq -r '.issued_node // empty' "$INSTALL_DIR/state/credential-transition.json")
    [[ -z "$issued_node" || "$issued_node" == "$IDENTITY_NODE_ID" ]] || die 're-enrollment returned a different identity; restore the prior transition'
    if [[ -z "$issued_node" ]]; then
      jq --arg node_id "$IDENTITY_NODE_ID" '. + {issued_node:$node_id}' "$INSTALL_DIR/state/credential-transition.json" | atomic_write "$INSTALL_DIR/state/credential-transition.json"
    fi
  fi
  printf '%s' "$SERVICE_TOKEN" | atomic_write "$INSTALL_DIR/credentials/service-token"
  printf '%s' "$CONFIG_URL" | atomic_write "$INSTALL_DIR/credentials/config-url"
  [[ "$IDENTITY_NODE_ID" == "$NODE_ID" ]] || die 'credential identity does not match the node'
  printf '%s' "$NODE_ID" | atomic_write "$INSTALL_DIR/credentials/node-id"
  save_identity
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    render_template "$SCRIPT_DIR/config/k3s.yaml" "$INSTALL_DIR/config/k3s.yaml"
    kube label "$cluster_node" "livepeer.io/node-id=$NODE_ID" --overwrite
  fi
  stage_manifests
  install_machine_secret
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    [[ $(jq -r '.cleanup_verified' <<< "$metadata") == true ]] || die 'prior app cleanup was not verified; restore the prior credential transition before re-enrolling'
    if [[ ! -f "$INSTALL_DIR/volumes/app-reconciler/reenrolled-$IDENTITY_NODE_ID" ]]; then
      if [[ -d "$INSTALL_DIR/volumes/app-reconciler/state" ]]; then
        mv -- "$INSTALL_DIR/volumes/app-reconciler/state" "$INSTALL_DIR/volumes/app-reconciler/state.$previous_node"
        sync -- "$INSTALL_DIR/volumes/app-reconciler"
      fi
      rm -f -- "$INSTALL_DIR/volumes/app-reconciler/secrets/identity.json" "$INSTALL_DIR/volumes/app-reconciler/secrets/key.pem" "$INSTALL_DIR/volumes/app-reconciler/secrets/managed"
      printf '1\n' | atomic_write "$INSTALL_DIR/volumes/app-reconciler/reenrolled-$IDENTITY_NODE_ID"
    fi
    # Fence the retired node's cached artifact and watermark while Flux is suspended.
    rm -f -- "$INSTALL_DIR/volumes/http-source/enrollment.json"
    kube -n flux-system patch externalartifact livepeer-service --subresource=status --type merge -p '{"status":{"artifact":null,"conditions":[]}}'
    apps=$(kube -n flux-system get externalartifact livepeer-apps --ignore-not-found -o name)
    if [[ -n "$apps" ]]; then kube -n flux-system patch externalartifact livepeer-apps --subresource=status --type merge -p '{"status":{"artifact":null,"conditions":[]}}'; fi
  fi
  kube apply -k "$INSTALL_DIR/manifests/bootstrap"
  kube -n flux-system rollout status deployment/livepeer-http-source --timeout=180s
  kube -n flux-system wait externalartifact/livepeer-service --for=condition=Ready --timeout=180s
  replicas=$(jq -er '.flux_replicas' "$INSTALL_DIR/state/credential-transition.json")
  kube -n flux-system scale deployment/kustomize-controller --replicas="$replicas"
  if (( replicas > 0 )); then
    kube -n flux-system rollout status deployment/kustomize-controller --timeout=180s
    kube -n flux-system wait kustomization/livepeer --for=condition=Ready --timeout=300s
  fi
  rm -- "$INSTALL_DIR/state/credential-transition.json"
  ENROLLMENT_TOKEN=''
}

# Split locally. The API receives only its JWT; the setup JWT never enters the
# management credential Secret or a generated manifest.
prepare_secrets_enrollment() {
  local encoded document
  unset SETUP_TOKEN
  SETUP_TOKEN=''
  if [[ "$ENROLLMENT_TOKEN" == lpcc1.* ]]; then
    encoded=${ENROLLMENT_TOKEN#lpcc1.}; encoded=${encoded//-/+}; encoded=${encoded//_/\/}
    while (( ${#encoded} % 4 )); do encoded+='='; done
    document=$(printf '%s' "$encoded" | base64 --decode) || die 'invalid enrollment envelope'
    jq -e '.version == 1 and (.control|type=="string") and (.setup|type=="string")' <<< "$document" >/dev/null || die 'invalid enrollment envelope'
    ENROLLMENT_TOKEN=$(jq -er '.control' <<< "$document")
    SETUP_TOKEN=$(jq -er '.setup' <<< "$document")
    [[ "$ENROLLMENT_TOKEN" =~ ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ && "$SETUP_TOKEN" =~ ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ ]] || die 'invalid enrollment grants'
  fi
  [[ -z "$ENROLLMENT_TOKEN" || "$ENROLLMENT_TOKEN" =~ ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ ]] || die 'invalid enrollment token format'
  command -v openssl >/dev/null || die 'install openssl before enrollment'
  initialize_installation
  install -d -m 0700 "$INSTALL_DIR/credentials/secrets"
  if [[ ! -f "$INSTALL_DIR/credentials/secrets/key.pem" ]]; then replace_secrets_key; fi
  SECRET_PUBLIC=$(openssl pkey -in "$INSTALL_DIR/credentials/secrets/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)
  if [[ -n "$SETUP_TOKEN" ]]; then install_setup_cleanup; printf '%s' "$SETUP_TOKEN" | atomic_write "$INSTALL_DIR/credentials/secrets/setup"; fi
  if [[ -n ${LIVEPEER_SECRETS_URL:-} ]]; then printf '%s' "$LIVEPEER_SECRETS_URL" | atomic_write "$INSTALL_DIR/credentials/secrets/url"
  elif [[ ! -f "$INSTALL_DIR/credentials/secrets/url" ]]; then printf '%s' 'https://controlcenter-secrets.livepeer.live' | atomic_write "$INSTALL_DIR/credentials/secrets/url"; fi
  SETUP_TOKEN=''
}

install_setup_cleanup() {
  install -d -m 0755 "$INSTALL_DIR/bin" "$INSTALL_DIR/systemd"
  atomic_binary "$SCRIPT_DIR/lib/expire-secrets-setup.sh" "$INSTALL_DIR/bin/livepeer-expire-secrets-setup"
  atomic_write "$INSTALL_DIR/systemd/livepeer-secrets-expiry.service" 0644 <<EOF
[Unit]
Description=Expire pending Livepeer secrets setup credential
[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/bin/livepeer-expire-secrets-setup $INSTALL_DIR/credentials/secrets/setup
EOF
  atomic_write "$INSTALL_DIR/systemd/livepeer-secrets-expiry.timer" 0644 <<'EOF'
[Unit]
Description=Check pending Livepeer secrets setup expiry
[Timer]
OnBootSec=1s
OnUnitActiveSec=30s
AccuracySec=1s
[Install]
WantedBy=timers.target
EOF
  atomic_symlink "$INSTALL_DIR/systemd/livepeer-secrets-expiry.service" /etc/systemd/system/livepeer-secrets-expiry.service
  atomic_symlink "$INSTALL_DIR/systemd/livepeer-secrets-expiry.timer" /etc/systemd/system/livepeer-secrets-expiry.timer
  systemctl daemon-reload
  systemctl enable --now livepeer-secrets-expiry.timer
}

replace_secrets_key() {
  local temporary
  temporary=$(mktemp "$INSTALL_DIR/credentials/secrets/key.XXXXXX")
  openssl genpkey -algorithm ED25519 -out "$temporary" 2>/dev/null
  atomic_write "$INSTALL_DIR/credentials/secrets/key.pem" < "$temporary"
  rm -f -- "$temporary"
  SECRET_PUBLIC=$(openssl pkey -in "$INSTALL_DIR/credentials/secrets/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)
}

sign_secrets_proof() {
  local temporary signature
  temporary=$(mktemp "$INSTALL_DIR/credentials/secrets/proof.XXXXXX")
  cat > "$temporary"
  signature=$(openssl pkeyutl -sign -rawin -inkey "$INSTALL_DIR/credentials/secrets/key.pem" -in "$temporary" 2>/dev/null | base64 -w0)
  rm -f -- "$temporary"
  printf '%s' "$signature"
}

registration_key_proof() {
  local grant_digest statement
  grant_digest=$(printf '%s' "$ENROLLMENT_TOKEN" | sha256sum); grant_digest=${grant_digest:0:64}
  statement=$(jq -c --arg grant "$grant_digest" --arg public "$SECRET_PUBLIC" '["lpcc-registration-v1",$grant,.fingerprint,.hostname,.install_dir,.k3s_version,(.development_http // false),$public]')
  printf '%s' "$statement" | sign_secrets_proof
}

secrets_key_proof() {
  printf 'lpcc-secrets-enroll-v1\n%s\n%s' "$1" "$SECRET_PUBLIC" | sign_secrets_proof
}

enroll_secrets() {
  local target="$INSTALL_DIR/credentials/secrets" response status request endpoint public setup_token attempt nonce anchor candidate headers signature replaced=0
  [[ -f "$target/setup" ]] || return 0
  local payload exp padded
  payload=$(cut -d. -f2 "$target/setup")
  padded=${payload//-/+}; padded=${padded//_/\/}
  while (( ${#padded} % 4 )); do padded+='='; done
  exp=$(printf '%s' "$padded" | base64 --decode 2>/dev/null | jq -er '.exp | numbers') || exp=0
  if (( exp <= $(date +%s) )); then rm -f -- "$target/setup"; log 'Secrets setup grant expired; generate a fresh enrollment command.'; return 0; fi
  # Encryption readiness is established from K3s, never from a page-load grant.
  local encryption_status
  encryption_status=$("$INSTALL_DIR/bin/k3s" secrets-encrypt status --data-dir "$INSTALL_DIR/k3s" 2>/dev/null) || encryption_status=''
  if ! grep -q 'Encryption Status: Enabled' <<< "$encryption_status"; then
    log 'Secrets enrollment pending: K3s secrets encryption is not enabled.'
    return 0
  fi
  endpoint=$(cat "$target/url")
  [[ "$endpoint" =~ ^https://[a-zA-Z0-9_.:-]+$ ]] || die 'invalid secrets service HTTPS origin'
  anchor=$(secrets_service_pin)
  if [[ -n "$anchor" && $(jq -r '.origin' <<< "$anchor") != "$endpoint" ]]; then die 'secrets service origin differs from the installed trust anchor'; fi
  setup_token=$(cat "$target/setup")
  for attempt in {1..12}; do
    nonce=$(openssl rand -hex 32)
    request=$(jq -nc --arg node "$NODE_ID" --arg public "$SECRET_PUBLIC" --arg nonce "$nonce" --rawfile signature <(secrets_key_proof "$NODE_ID") --rawfile management "$INSTALL_DIR/credentials/service-token" '{node_id:$node,public_key:$public,nonce:$nonce,signature:$signature,management_token:$management,encryption_ready:true}')
    headers=$(mktemp "$target/headers.XXXXXX")
    response=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 --dump-header "$headers" --proto '=https' --request POST --header 'Content-Type: application/json' --config <(printf 'header = "Authorization: Bearer %s"\n' "$setup_token") --data-binary @<(printf '%s' "$request") --write-out '\n%{http_code}' "$endpoint/v1/machines/enroll") || { rm -f -- "$headers"; log 'Secrets enrollment pending: service unavailable.'; return 0; }
    status=${response##*$'\n'}; response=${response%$'\n'*}
    signature=$(awk 'tolower($1)=="x-livepeer-service-signature:" {sub(/\r$/, "", $2); signature=$2} END {print signature}' "$headers")
    rm -f -- "$headers"
    if [[ "$status" == 200 ]]; then
      candidate=$(jq -cS '.service | {origin,public_key}' <<< "$response")
      if [[ -z "$anchor" ]]; then anchor=$candidate; fi
    fi
    if [[ -n "$anchor" ]] && ! verify_secrets_response "$anchor" "$request" "$setup_token" "$status" "$response" "$signature"; then
      log 'Secrets enrollment pending: service signature unavailable or invalid.'; return 0
    fi
    if [[ "$status" == 409 && "$replaced" == 0 ]] && [[ $(jq -r '.code // empty' <<< "$response") == identity_reset_required ]]; then
      # A pinned reply was verified; first enrollment still trusts HTTPS.
      # Save the replacement before registration so interruptions reuse it.
      replace_secrets_key
      replaced=1
      continue
    fi
    # Capability reports may arrive after management Pods become ready.
    if [[ "$status" == 503 && "$attempt" -lt 12 ]]; then sleep 5; continue; fi
    break
  done
  if [[ "$status" == 401 ]]; then rm -f -- "$target/setup"; log 'Secrets setup grant expired or revoked; generate a fresh enrollment command.'; return 0; fi
  if [[ "$status" != 200 ]]; then log 'Secrets enrollment pending; no secret values have been installed.'; return 0; fi
  [[ $(jq -r '.node_id' <<< "$response") == "$NODE_ID" ]] || die 'secrets identity mismatch'
  jq -e '(.owner_id | type == "string" and length > 0) and (.generation | type == "number" and . >= 1 and . == floor)' <<< "$response" >/dev/null || die 'invalid secrets identity'
  jq -e --arg origin "$endpoint" '.origin == $origin and (.public_key | type == "string")' <<< "$candidate" >/dev/null || die 'invalid secrets service identity'
  [[ "$candidate" == "$anchor" ]] || die 'secrets service identity changed; restore the trusted service key before retrying'
  printf '%s' "$anchor" | atomic_write "$target/service.json"
  public="$INSTALL_DIR/volumes/app-reconciler/secrets"
  install -d -m 0700 "$public"
  atomic_write "$public/key.pem" < "$target/key.pem"
  printf '%s' "$response" | atomic_write "$public/identity.json"
  atomic_write "$public/url" < "$target/url"
  kube label namespace livepeer-apps livepeer.io/managed-secrets=true --overwrite
  printf '1' | atomic_write "$public/managed"
  chown -R 65532:65532 "$public"
  # An owner-authorized key reset must also update the onchain request signer.
  install_machine_secret
  rm -f -- "$target/setup"
}

secrets_service_pin() {
  local target="$INSTALL_DIR/credentials/secrets"
  if [[ -s "$target/service.json" ]]; then jq -cS . "$target/service.json"
  fi
}

verify_secrets_response() {
  local digest authorization body proof
  digest=$(printf '%s' "$2" | sha256sum)
  proof=$(jq -nc --arg body "${digest%% *}" '["POST","/v1/machines/enroll",$body]')
  digest=$(printf '%s' "$proof" | sha256sum)
  authorization=$(printf 'Bearer %s' "$3" | sha256sum)
  body=$(printf '%s' "$5" | sha256sum)
  proof=$(jq -nc --arg origin "$(jq -r '.origin' <<< "$1")" --arg request "${digest%% *}" --arg authorization "${authorization%% *}" --argjson status "$4" --arg body "${body%% *}" '["lpcc-secrets-response-v1",$origin,$request,$authorization,$status,$body]')
  verify_secrets_signature "$(jq -r '.public_key' <<< "$1")" "$6" "$proof"
}

verify_secrets_signature() {
  local temporary result=0
  temporary=$(mktemp -d "$INSTALL_DIR/credentials/secrets/signature.XXXXXX")
  { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; printf '%s' "$1" | base64 --decode; } > "$temporary/public.der"
  printf '%s' "$2" | base64 --decode > "$temporary/signature"
  printf '%s' "$3" > "$temporary/proof"
  openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$temporary/public.der" -in "$temporary/proof" -sigfile "$temporary/signature" >/dev/null 2>&1 || result=1
  rm -rf -- "$temporary"
  return "$result"
}
