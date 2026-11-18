#!/usr/bin/env bash
# Test-only adapters for the GNU commands the bootstrap fixtures exercise.
realpath() {
  if [[ ${1:-} == -m && ${2:-} == -- ]]; then
    "$BOOTSTRAP_TEST_PYTHON" -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$3"
  else
    command realpath "$@"
  fi
}

macos_mv() {
  case $1 in
    -T|-fT)
      [[ $2 == -- && $# == 4 ]] || return 2
      "$BOOTSTRAP_TEST_PYTHON" -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$3" "$4" ;;
    *) command mv "$@" ;;
  esac
}

mv() { macos_mv "$@"; }
sha256sum() { shasum -a 256 "$@"; }
sha512sum() { shasum -a 512 "$@"; }
# The system sync flushes all filesystems. These fixtures check publication.
sync() { :; }
