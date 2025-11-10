#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

set -a; source ./.env; set +a
source ./.A
source ./.B
source ./.AUTH

# Choose one observe path based on your Registry version.

echo "→ Attempting hash-only observe on B…"
set +e
cast send "$REGISTRY_B" "observe(bytes32,address)" "$AUTH_HASH" "$GRANTOR" \
  --rpc-url "$RPC_B" --private-key "$PRIVATE_KEY"
RC=$?
set -e

if [[ "$RC" -ne 0 ]]; then
  echo "→ Hash-only failed; trying full observe(auth, sig)…"
  cast send "$REGISTRY_B" \
  "observe((address,address,address,uint256,uint256,uint256,bytes32),bytes)" \
  "($GRANTOR,$GRANTEE,$TOKEN_A,$MAX_PER_PULL,$VALID_AFTER,$VALID_BEFORE,$NONCE)" \
  "$SIG_A" \
  --rpc-url "$RPC_B" --private-key "$PRIVATE_KEY"
fi

OWNER=$(cast call "$REGISTRY_B" "ownerOf(bytes32)(address)" "$AUTH_HASH" --rpc-url "$RPC_B")
echo "✓ ownerOf(AUTH_HASH) on B = $OWNER"
