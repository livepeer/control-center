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

initialize_installation() {
  local initial parent="${INSTALL_DIR%/*}"
  managed_installation && return 0
  [[ -n "$parent" ]] || parent=/
  if [[ -d "$INSTALL_DIR" && -n "$(ls -A "$INSTALL_DIR")" ]]; then
    die 'installation directory is nonempty and has no installation marker'
  fi
  [[ -d "$parent" ]] || install -d -m 0755 "$parent"
  initial=$(mktemp -d "${INSTALL_DIR}.initial.XXXXXX")
  install -d -m 0700 "$initial/state"
  printf '%s\n' "$INSTALL_DIR" | atomic_write "$initial/state/install-dir"
  # Remove an empty destination before publishing the complete installation.
  if [[ -d "$INSTALL_DIR" ]]; then rmdir -- "$INSTALL_DIR"; fi
  mv -T -- "$initial" "$INSTALL_DIR"
  sync -- "$parent"
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
