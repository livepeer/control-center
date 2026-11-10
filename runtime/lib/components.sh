#!/usr/bin/env bash
# Install from verified release content. Presence alone is never an integrity check.

download() {
  local url="$1" target="$2" temporary
  [[ ! -f "$target" || ${3:-} == --refresh ]] || return 0
  temporary=$(mktemp "${target}.download.XXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --retry 4 --connect-timeout 20 --max-time 600 --output "$temporary" "$url"
  sync -- "$temporary"
  mv -fT -- "$temporary" "$target"
}

verify_sum() {
  local algorithm="$1" sum_file="$2" name="$3" directory="$4" expected
  expected=$(awk -v name="$name" '$2 == name || $2 == "*" name {print $1}' "$sum_file")
  [[ "$expected" =~ ^[a-fA-F0-9]+$ && ${#expected} -eq $(( algorithm / 4 )) ]] || die "missing or ambiguous checksum for $name"
  if ! (cd "$directory" && printf '%s  %s\n' "$expected" "$name" | "sha${algorithm}sum" --check --status); then
    log "checksum failed for $name"
    return 1
  fi
}

verified_asset() {
  local url="$1" target="$2" algorithm="$3" sums="$4" temporary
  if [[ -f "$target" ]] && verify_sum "$algorithm" "$sums" "${target##*/}" "${target%/*}"; then return; fi
  temporary=$(mktemp -d "${target}.verify.XXXXXX")
  download "$url" "$temporary/${target##*/}"
  verify_sum "$algorithm" "$sums" "${target##*/}" "$temporary" || die "upstream checksum mismatch for ${target##*/}; existing state preserved"
  mv -fT -- "$temporary/${target##*/}" "$target"
  rmdir "$temporary"
  sync -- "${target%/*}"
}

install_k3s() {
  local version="$K3S_VERSION" recorded='' reported='' release cache
  if [[ -f "$INSTALL_DIR/state/k3s-version" ]]; then
    recorded=$(cat "$INSTALL_DIR/state/k3s-version")
    version_at_least "$recorded" "$version" || die 'invalid or unsupported saved K3s version'
    version="$recorded"
  fi
  if [[ -x "$INSTALL_DIR/bin/k3s" ]]; then
    reported=$("$INSTALL_DIR/bin/k3s" --version 2>/dev/null | awk 'NR == 1 {print $3}') || reported=''
    if version_at_least "$reported" "$version"; then version="$reported"; fi
  fi
  if [[ -z "$recorded" && -z "$reported" && -d "$INSTALL_DIR/k3s/server" ]]; then
    die 'cannot establish the installed K3s version; restore state/k3s-version from a known backup before repair (no downgrade attempted)'
  fi
  if [[ -n "$reported" ]] && ! version_at_least "$reported" "$K3S_VERSION"; then
    die 'existing K3s is older than the minimum supported release or unrecognized; upgrade explicitly'
  fi
  cache="$INSTALL_DIR/download/k3s/$version"
  install -d -m 0700 "$cache"
  release="https://github.com/k3s-io/k3s/releases/download/${version//+/%2B}"
  download "$release/sha256sum-amd64.txt" "$cache/checksums.txt" --refresh
  verified_asset "$release/k3s" "$cache/k3s" 256 "$cache/checksums.txt"
  # Record the release before committing its binary so a missing/damaged binary
  # can be restored to that version, including after a system-upgrade job.
  printf '%s\n' "$version" | atomic_write "$INSTALL_DIR/state/k3s-version"
  if ! cmp -s "$cache/k3s" "$INSTALL_DIR/bin/k3s"; then
    printf '1\n' | atomic_write "$INSTALL_DIR/state/k3s-restart-required"
  fi
  atomic_binary "$cache/k3s" "$INSTALL_DIR/bin/k3s"
}

gvisor_matches() {
  local expected="$1" installed="$2" executable
  diff -qr --no-dereference "$expected" "$installed" >/dev/null || return 1
  while IFS= read -r -d '' executable; do
    [[ -x "$installed/${executable#"$expected/"}" ]] || return 1
  done < <(find "$expected" -type f -perm /111 -print0)
}

install_gvisor() {
  local release cache staged installed=''
  release="https://github.com/google/gvisor/releases/download/$GVISOR_VERSION"
  cache="$INSTALL_DIR/download/gvisor/$GVISOR_VERSION"
  install -d -m 0700 "$cache"
  download "$release/SHA512SUMS" "$cache/checksums.txt" --refresh
  verified_asset "$release/gvisor-x86_64.tar.bz2" "$cache/gvisor-x86_64.tar.bz2" 512 "$cache/checksums.txt"
  install -d -m 0755 "$INSTALL_DIR/runtimes/gvisor"
  staged=$(mktemp -d "$INSTALL_DIR/runtimes/gvisor/$GVISOR_VERSION.XXXXXX")
  tar -xjf "$cache/gvisor-x86_64.tar.bz2" -C "$staged" --no-same-owner
  [[ -x "$staged/runsc" && -x "$staged/containerd-shim-runsc-v1" ]] || die 'gVisor release lacks executable runtime or shim'
  if [[ -L "$INSTALL_DIR/bin/runsc" ]]; then installed=$(dirname "$(readlink -f "$INSTALL_DIR/bin/runsc")"); fi
  if [[ -n "$installed" && -x "$installed/runsc" && -x "$installed/containerd-shim-runsc-v1" ]] &&
      gvisor_matches "$staged" "$installed"; then
    rm -rf -- "$staged"
    staged="$installed"
  fi
  # Keep old generations for running sandboxes. Publish only a completely extracted tree.
  chmod 0755 "$staged"
  sync -- "$staged"
  atomic_symlink "$staged/runsc" "$INSTALL_DIR/bin/runsc"
  atomic_symlink "$staged/containerd-shim-runsc-v1" "$INSTALL_DIR/bin/containerd-shim-runsc-v1"
}

install_flux() {
  local release cache staged
  release="https://github.com/fluxcd/flux2/releases/download/$FLUX_VERSION"
  cache="$INSTALL_DIR/download/flux/$FLUX_VERSION"
  install -d -m 0700 "$cache"
  download "$release/flux_${FLUX_VERSION#v}_checksums.txt" "$cache/checksums.txt" --refresh
  verified_asset "$release/flux_${FLUX_VERSION#v}_linux_amd64.tar.gz" "$cache/flux_${FLUX_VERSION#v}_linux_amd64.tar.gz" 256 "$cache/checksums.txt"
  staged=$(mktemp -d "$cache/extract.XXXXXX")
  tar -xzf "$cache/flux_${FLUX_VERSION#v}_linux_amd64.tar.gz" -C "$staged" flux --no-same-owner
  atomic_binary "$staged/flux" "$INSTALL_DIR/bin/flux"
  rm -rf -- "$staged"
}

install_components() {
  install_k3s
  install_gvisor
  install_flux
  "$INSTALL_DIR/bin/k3s" check-config > "$INSTALL_DIR/logs/k3s-check-config.log" 2>&1 || {
    cat "$INSTALL_DIR/logs/k3s-check-config.log" >&2
    die 'K3s kernel configuration check failed'
  }
}
