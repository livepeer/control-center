#!/usr/bin/env bash
# Atomic publication helpers. Temporary files stay on the destination filesystem.

atomic_write() {
  local target="$1" mode="${2:-0600}" temporary
  temporary=$(mktemp "${target}.tmp.XXXXXX")
  cat > "$temporary"
  chmod "$mode" "$temporary"
  sync -- "$temporary"
  mv -fT -- "$temporary" "$target"
  sync -- "${target%/*}"
}

write_once() {
  local target="$1" value="$2"
  if [[ -e "$target" ]]; then
    [[ -f "$target" && -s "$target" && "$(cat "$target")" == "$value" ]] || die "saved credential is invalid: $target; restore it from backup"
    chmod 0600 "$target"
  else
    printf '%s' "$value" | atomic_write "$target"
  fi
}

# The old installer could stop after creating directories but before its marker.
# Adopt only its known empty directory layout, never files or arbitrary folders.
empty_bootstrap_layout() (
  local path relative
  shopt -s globstar dotglob nullglob
  for path in "$INSTALL_DIR"/**; do
    [[ "$path" != "$INSTALL_DIR/" ]] || continue
    [[ -d "$path" && ! -L "$path" ]] || return 1
    relative=${path#"$INSTALL_DIR/"}
    case "$relative" in
      bin|config|manifests|manifests/flux|systemd|logs|services|credentials|state|download|volumes|\
      volumes/http-source|volumes/orchestrator|volumes/app-reconciler|kubelet|k3s|k3s/agent|k3s/agent/etc|\
      k3s/agent/etc/containerd|k3s/agent/etc/kubelet.conf.d) ;;
      *) return 1 ;;
    esac
  done
)

initialize_installation() {
  local initial parent="${INSTALL_DIR%/*}"
  managed_installation && return 0
  [[ -n "$parent" ]] || parent=/
  if [[ -d "$INSTALL_DIR" ]]; then empty_bootstrap_layout || die 'refusing to adopt an unmarked directory containing data'; fi
  [[ -d "$parent" ]] || install -d -m 0755 "$parent"
  initial=$(mktemp -d "${INSTALL_DIR}.initial.XXXXXX")
  install -d -m 0700 "$initial/state"
  printf '%s\n' "$INSTALL_DIR" | atomic_write "$initial/state/install-dir"
  if [[ -d "$INSTALL_DIR" ]]; then
    install -d -m 0700 "$INSTALL_DIR/state"
    # Publish the complete marker in one operation, without a partial file in the root.
    ln "$initial/state/install-dir" "$INSTALL_DIR/state/install-dir"
    sync -- "$INSTALL_DIR/state"
    rm -rf -- "$initial"
  else
    # The root appears only after its ownership marker is complete.
    mv -T -- "$initial" "$INSTALL_DIR"
    sync -- "$parent"
  fi
}

atomic_binary() {
  local source="$1" target="$2"
  if [[ -f "$target" ]] && cmp -s "$source" "$target"; then
    chmod 0755 "$target"
    return
  fi
  atomic_write "$target" 0755 < "$source"
}

atomic_symlink() {
  local target="$1" link="$2" temporary
  temporary=$(mktemp "${link}.link.XXXXXX")
  rm -- "$temporary"
  ln -s -- "$target" "$temporary"
  mv -fT -- "$temporary" "$link"
  sync -- "${link%/*}"
}
