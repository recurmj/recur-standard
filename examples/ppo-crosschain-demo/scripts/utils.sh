# examples/ppo-crosschain-demo/scripts/utils.sh

must() {
  local var="$1"
  [[ -n "${!var:-}" ]] || { echo "Missing env: $var"; exit 1; }
}

addr_from_pk() {
  local pk="${1:-$PRIVATE_KEY}"
  cast wallet address --private-key "$pk"
}

save_kv() {
  # save_kv <file> <KEY> <VALUE>
  local file="$1" key="$2" val="$3"
  echo "${key}=${val}" >> "$file"
}
