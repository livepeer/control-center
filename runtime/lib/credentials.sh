#!/usr/bin/env bash
# Explicit, resumable machine-credential transitions. Never changes K3s versions.

control_transport() {
  if [[ ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} == 1 ]]; then printf 'development-http'; else printf 'https'; fi
}

save_identity() {
  local identity
  identity=$(jq -nc --arg epoch "$ENROLLMENT_EPOCH" --arg version "$CREDENTIAL_VERSION" '{epoch:$epoch,credential_version:$version}')
  if [[ -f "$INSTALL_DIR/credentials/identity.json" && $(cat "$INSTALL_DIR/credentials/identity.json") == "$identity" ]]; then return; fi
  printf '%s\n' "$identity" | atomic_write "$INSTALL_DIR/credentials/identity.json"
}

install_machine_secret() {
  kube -n flux-system create secret generic livepeer-service-auth \
    --from-file="token=$INSTALL_DIR/credentials/service-token" \
    --from-file="config-url=$INSTALL_DIR/credentials/config-url" \
    --from-file="identity.json=$INSTALL_DIR/credentials/identity.json" \
    --dry-run=client -o yaml | kube apply -f -
}

stop_credential_consumers() {
  kube -n flux-system patch kustomization livepeer --type merge -p '{"spec":{"suspend":true}}'
  kube -n flux-system scale deployment/livepeer-http-source --replicas=0
  kube -n flux-system delete deployment/livepeer-tunnel --ignore-not-found --wait=true
  # Replica count alone does not prove old HTTP-speaking processes terminated.
  kube -n flux-system wait pod -l app=livepeer-http-source --for=delete --timeout=120s
  kube -n flux-system wait pod -l app=livepeer-tunnel --for=delete --timeout=120s
}

transition_credentials() {
  local api fingerprint operation expected response status request metadata
  managed_installation || die 'credential transition requires an initialized installation'
  [[ -n "$ENROLLMENT_TOKEN" ]] || die 'credential transition requires a fresh owner enrollment JWT'
  [[ "$ENROLLMENT_TOKEN" =~ ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ ]] || die 'invalid enrollment JWT'
  api=${LIVEPEER_API_URL:-}; api=${api%/}
  [[ "$api" =~ ^https://[a-zA-Z0-9_.:-]+(/[a-zA-Z0-9_.-]+)*$ ]] || die 'set LIVEPEER_API_URL to the verified HTTPS API'
  NODE_ID=$(cat "$INSTALL_DIR/credentials/node-id")
  [[ "$NODE_ID" =~ ^lp-[a-f0-9]{16}$ ]] || die 'invalid saved machine ID'
  fingerprint=$(printf '%s' "$(cat /etc/machine-id)" | sha256sum); fingerprint=${fingerprint:0:64}
  [[ "$NODE_ID" == "lp-${fingerprint:0:16}" ]] || die 'installation fingerprint changed'
  if [[ -f "$INSTALL_DIR/state/credential-transition.json" ]]; then
    metadata=$(cat "$INSTALL_DIR/state/credential-transition.json")
    [[ $(jq -r '.mode' <<< "$metadata") == "$CREDENTIAL_TRANSITION" ]] || die 'resume the existing credential transition mode'
    [[ $(jq -r '.api' <<< "$metadata") == "$api" ]] || die 'resume with the original HTTPS API'
  else
    operation=$(cat /proc/sys/kernel/random/uuid)
    expected=0
    if [[ -f "$INSTALL_DIR/credentials/identity.json" ]]; then expected=$(jq -er '.credential_version | tonumber' "$INSTALL_DIR/credentials/identity.json"); fi
    jq -nc --arg mode "$CREDENTIAL_TRANSITION" --arg api "$api" --arg operation "$operation" --argjson expected "$expected" \
      '{mode:$mode,api:$api,operation:$operation,expected:$expected}' | atomic_write "$INSTALL_DIR/state/credential-transition.json"
    metadata=$(cat "$INSTALL_DIR/state/credential-transition.json")
  fi
  stop_credential_consumers
  LIVEPEER_ALLOW_DEVELOPMENT_HTTP=0
  CONFIG_URL="$api/v1/nodes/$NODE_ID/config"
  # Publish HTTPS-enforcing source files and settings before releasing credentials.
  # The Deployment remains scaled to zero until the complete new manifest applies.
  stage_manifests
  if [[ "$CREDENTIAL_TRANSITION" == refresh ]]; then
    request=$(jq -nc --arg fingerprint "$fingerprint" --arg install_dir "$INSTALL_DIR" \
      --arg operation_id "$(jq -r '.operation' <<< "$metadata")" --argjson expected "$(jq -r '.expected' <<< "$metadata")" \
      '{fingerprint:$fingerprint,install_dir:$install_dir,operation_id:$operation_id,expected_credential_version:$expected}')
    response=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' \
      --write-out '\n%{http_code}' --request POST --header 'Content-Type: application/json' \
      --config <(printf 'header = "Authorization: Bearer %s"\n' "$ENROLLMENT_TOKEN") \
      --data-binary "$request" "$api/v1/nodes/$NODE_ID/credentials/refresh") || die 'HTTPS credential refresh failed; transition remains suspended'
  else
    request=$(jq -nc --arg fingerprint "$fingerprint" --arg hostname "$(hostname)" --arg install_dir "$INSTALL_DIR" \
      --arg version "$(cat "$INSTALL_DIR/state/k3s-version")" '{fingerprint:$fingerprint,hostname:$hostname,install_dir:$install_dir,k3s_version:$version}')
    response=$(curl -q --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' \
      --write-out '\n%{http_code}' --request POST --header 'Content-Type: application/json' \
      --config <(printf 'header = "Authorization: Bearer %s"\n' "$ENROLLMENT_TOKEN") \
      --data-binary "$request" "$api/v1/nodes/register") || die 'HTTPS re-enrollment failed; transition remains suspended'
  fi
  status=${response##*$'\n'}; [[ "$status" == 200 ]] || die 'credential transition did not return HTTP 200; resume with the same operation'
  response=${response%$'\n'*}
  [[ $(jq -r '.node_id' <<< "$response") == "$NODE_ID" ]] || die 'credential transition returned a different machine'
  [[ $(jq -r '.config_url' <<< "$response") == "$CONFIG_URL" ]] || die 'credential destination changed'
  SERVICE_TOKEN=$(jq -er '.token' <<< "$response"); ENROLLMENT_EPOCH=$(jq -er '.epoch' <<< "$response"); CREDENTIAL_VERSION=$(jq -er '.credential_version' <<< "$response")
  [[ "$SERVICE_TOKEN" =~ ^[a-f0-9]{64}$ && "$ENROLLMENT_EPOCH" =~ ^[a-f0-9-]{36}$ && "$CREDENTIAL_VERSION" =~ ^[1-9][0-9]*$ ]] || die 'invalid refreshed machine credential'
  printf '%s' "$SERVICE_TOKEN" | atomic_write "$INSTALL_DIR/credentials/service-token"
  printf '%s' "$CONFIG_URL" | atomic_write "$INSTALL_DIR/credentials/config-url"
  save_identity
  install_machine_secret
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    # Fence the previous epoch's cached artifact and watermark while Flux is suspended.
    rm -f -- "$INSTALL_DIR/volumes/http-source/enrollment.json"
    kube -n flux-system patch externalartifact livepeer-service --subresource=status --type merge -p '{"status":{"artifact":null,"conditions":[]}}'
  fi
  kube apply -k "$INSTALL_DIR/manifests/bootstrap"
  kube -n flux-system rollout status deployment/livepeer-http-source --timeout=180s
  kube -n flux-system wait externalartifact/livepeer-service --for=condition=Ready --timeout=180s
  kube -n flux-system patch kustomization livepeer --type merge -p '{"spec":{"suspend":false}}'
  kube -n flux-system wait kustomization/livepeer --for=condition=Ready --timeout=300s
  rm -- "$INSTALL_DIR/state/credential-transition.json"
  ENROLLMENT_TOKEN=''
}
