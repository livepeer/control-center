#!/usr/bin/env bash
# Explicit, resumable machine-credential transitions. Never changes K3s versions.

control_transport() {
  if [[ ${LIVEPEER_ALLOW_DEVELOPMENT_HTTP:-0} == 1 ]]; then printf 'development-http'; else printf 'https'; fi
}

runtime_image() {
  RUNTIME_IMAGE=${LIVEPEER_RUNTIME_IMAGE:-}
  if [[ -z "$RUNTIME_IMAGE" && -f "$INSTALL_DIR/state/runtime-image" ]]; then RUNTIME_IMAGE=$(cat "$INSTALL_DIR/state/runtime-image"); fi
  [[ "$RUNTIME_IMAGE" =~ ^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$ ]] || die 'set LIVEPEER_RUNTIME_IMAGE to a built Go Runtime image pinned by digest'
}

verify_retired_apps() {
  local headers code token
  if [[ -f "$INSTALL_DIR/volumes/http-source/system-layout.json" ]]; then
    [[ $(jq -r '.stage' "$INSTALL_DIR/volumes/http-source/system-layout.json") == complete ]] || die 'finish the Runtime inventory transfer before re-enrolling; keep the existing enrollment running'
  fi
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
  kube -n flux-system create secret generic livepeer-runner-bootstrap \
    --from-file="secret=$INSTALL_DIR/credentials/runner-bootstrap.secret" \
    --dry-run=client -o yaml | kube apply -f -
}

stop_credential_consumers() {
  local replicas
  if ! jq -e '.flux_replicas != null' "$INSTALL_DIR/state/credential-transition.json" >/dev/null; then
    replicas=$(kube -n flux-system get deployment/kustomize-controller -o jsonpath='{.spec.replicas}')
    [[ "$replicas" =~ ^[0-9]+$ ]] || die 'cannot establish the Flux writer replica count'
    jq --argjson replicas "$replicas" '. + {flux_replicas:$replicas,resume_legacy_root:(.runtime_transition_format != 3)}' "$INSTALL_DIR/state/credential-transition.json" | \
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
  # Replica count alone does not prove old HTTP-speaking processes terminated.
  kube -n flux-system wait pod -l app=livepeer-http-source --for=delete --timeout=120s
  kube -n flux-system wait pod -l app=livepeer-app-reconciler --for=delete --timeout=120s
  kube -n flux-system wait pod -l app=livepeer-tunnel --for=delete --timeout=120s
}

transition_credentials() {
  local api fingerprint operation expected response status request metadata previous_epoch apps replicas layout_epoch issued_epoch installed_epoch
  managed_installation || die 'credential transition requires an initialized installation'
  [[ -s "$INSTALL_DIR/credentials/runner-bootstrap.secret" ]] || die 'restore the runner bootstrap credential before changing credentials'
  runtime_image
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
    if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then verify_retired_apps "$api"; fi
    operation=$(cat /proc/sys/kernel/random/uuid)
    expected=0
    previous_epoch=legacy
    if [[ -f "$INSTALL_DIR/credentials/identity.json" ]]; then expected=$(jq -er '.credential_version | tonumber' "$INSTALL_DIR/credentials/identity.json"); fi
    if [[ -f "$INSTALL_DIR/credentials/identity.json" ]]; then previous_epoch=$(jq -er '.epoch' "$INSTALL_DIR/credentials/identity.json"); fi
    jq -nc --arg mode "$CREDENTIAL_TRANSITION" --arg api "$api" --arg operation "$operation" --argjson expected "$expected" --arg previous_epoch "$previous_epoch" \
      '{mode:$mode,api:$api,operation:$operation,expected:$expected,previous_epoch:$previous_epoch,cleanup_verified:($mode=="reenroll"),runtime_transition_format:3}' | atomic_write "$INSTALL_DIR/state/credential-transition.json"
    metadata=$(cat "$INSTALL_DIR/state/credential-transition.json")
  fi
  stop_credential_consumers
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    # Recheck after publisher termination, including on resume: the old agent
    # could have started a transfer while the cleanup preflight was in flight.
    if [[ -f "$INSTALL_DIR/volumes/http-source/system-layout.json" && $(jq -r '.stage' "$INSTALL_DIR/volumes/http-source/system-layout.json") != complete ]]; then
      layout_epoch=$(jq -r '.epoch' "$INSTALL_DIR/volumes/http-source/system-layout.json")
      issued_epoch=$(jq -r '.issued_epoch // empty' "$INSTALL_DIR/state/credential-transition.json")
      installed_epoch=''
      if [[ -f "$INSTALL_DIR/credentials/identity.json" ]]; then installed_epoch=$(jq -r '.epoch' "$INSTALL_DIR/credentials/identity.json"); fi
      if [[ $(jq -r '.layout_verified // false' "$INSTALL_DIR/state/credential-transition.json") == true && -n "$issued_epoch" && "$layout_epoch" == "$issued_epoch" && "$installed_epoch" == "$issued_epoch" ]]; then
        : # Resume the successfully installed new enrollment's own transfer.
      elif [[ $(jq -r '.layout_verified // false' "$INSTALL_DIR/state/credential-transition.json") != true ]]; then
        kube -n flux-system scale deployment/livepeer-http-source --replicas=1
        replicas=$(jq -er '.flux_replicas' "$INSTALL_DIR/state/credential-transition.json")
        kube -n flux-system scale deployment/kustomize-controller --replicas="$replicas"
        rm -- "$INSTALL_DIR/state/credential-transition.json"
        die 'Runtime inventory transfer began during preflight; the old enrollment was resumed; finish its transfer and retry re-enrollment'
      else
        die 'unfinished Runtime inventory transfer after the enrollment fence; restore the prior transition before continuing'
      fi
    fi
    jq '. + {layout_verified:true}' "$INSTALL_DIR/state/credential-transition.json" | atomic_write "$INSTALL_DIR/state/credential-transition.json"
  fi
  install -d -m 0700 "$INSTALL_DIR/volumes/app-reconciler"
  chown 65532:65532 "$INSTALL_DIR/volumes/app-reconciler"
  install -d -m 0700 "$INSTALL_DIR/volumes/management-sockets" \
    "$INSTALL_DIR/volumes/management-sockets/connector" "$INSTALL_DIR/volumes/management-sockets/apps"
  chown 65532:65532 "$INSTALL_DIR/volumes/management-sockets" \
    "$INSTALL_DIR/volumes/management-sockets/connector" "$INSTALL_DIR/volumes/management-sockets/apps"
  printf '%s\n' "$RUNTIME_IMAGE" | atomic_write "$INSTALL_DIR/state/runtime-image"
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
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    jq --arg epoch "$ENROLLMENT_EPOCH" '. + {issued_epoch:$epoch}' "$INSTALL_DIR/state/credential-transition.json" | atomic_write "$INSTALL_DIR/state/credential-transition.json"
  fi
  printf '%s' "$SERVICE_TOKEN" | atomic_write "$INSTALL_DIR/credentials/service-token"
  printf '%s' "$CONFIG_URL" | atomic_write "$INSTALL_DIR/credentials/config-url"
  save_identity
  install_machine_secret
  if [[ "$CREDENTIAL_TRANSITION" == reenroll ]]; then
    [[ $(jq -r '.cleanup_verified' <<< "$metadata") == true ]] || die 'prior app cleanup was not verified; restore the prior credential transition before re-enrolling'
    if [[ ! -f "$INSTALL_DIR/volumes/app-reconciler/reenrolled-$ENROLLMENT_EPOCH" ]]; then
      previous_epoch=$(jq -er '.previous_epoch' <<< "$metadata")
      [[ "$previous_epoch" == legacy || "$previous_epoch" =~ ^[a-f0-9-]{36}$ ]] || die 'invalid previous enrollment identity'
      if [[ -d "$INSTALL_DIR/volumes/app-reconciler/state" ]]; then
        mv -- "$INSTALL_DIR/volumes/app-reconciler/state" "$INSTALL_DIR/volumes/app-reconciler/state.$previous_epoch"
        sync -- "$INSTALL_DIR/volumes/app-reconciler"
      fi
      printf '1\n' | atomic_write "$INSTALL_DIR/volumes/app-reconciler/reenrolled-$ENROLLMENT_EPOCH"
    fi
    # Fence the previous epoch's cached artifact and watermark while Flux is suspended.
    rm -f -- "$INSTALL_DIR/volumes/http-source/enrollment.json"
    kube -n flux-system patch externalartifact livepeer-service --subresource=status --type merge -p '{"status":{"artifact":null,"conditions":[]}}'
    apps=$(kube -n flux-system get externalartifact livepeer-apps --ignore-not-found -o name)
    if [[ -n "$apps" ]]; then kube -n flux-system patch externalartifact livepeer-apps --subresource=status --type merge -p '{"status":{"artifact":null,"conditions":[]}}'; fi
  fi
  kube apply -k "$INSTALL_DIR/manifests/bootstrap"
  kube -n flux-system rollout status deployment/livepeer-http-source --timeout=180s
  kube -n flux-system wait externalartifact/livepeer-service --for=condition=Ready --timeout=180s
  replicas=$(jq -er '.flux_replicas' "$INSTALL_DIR/state/credential-transition.json")
  if [[ $(jq -r '.resume_legacy_root' "$INSTALL_DIR/state/credential-transition.json") == true ]]; then
    kube -n flux-system patch kustomization livepeer --type merge -p '{"spec":{"suspend":false}}'
  fi
  kube -n flux-system scale deployment/kustomize-controller --replicas="$replicas"
  if (( replicas > 0 )); then
    kube -n flux-system rollout status deployment/kustomize-controller --timeout=180s
    kube -n flux-system wait kustomization/livepeer --for=condition=Ready --timeout=300s
  fi
  rm -- "$INSTALL_DIR/state/credential-transition.json"
  ENROLLMENT_TOKEN=''
}
