#!/usr/bin/env bash
set -euo pipefail

must() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing env var: $name" >&2
    exit 1
  fi
}

addr_from_pk() {
  cast wallet address --private-key "$PRIVATE_KEY"
}
