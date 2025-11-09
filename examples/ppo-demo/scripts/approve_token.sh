#!/usr/bin/env bash
set -euo pipefail

# Load env + deployed addrs
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
set -a; source "$ROOT_DIR/examples/ppo-demo/.env"; set +a
source "$ROOT_DIR/examples/ppo-demo/.addrs"

: "${TOKEN_ADDRESS:?TOKEN_ADDRESS missing in .env}"
: "${RPC_URL:?RPC_URL missing in .env}"
: "${PRIVATE_KEY:?PRIVATE_KEY missing in .env}"

GRANTOR_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY")
echo "→ Grantor: $GRANTOR_ADDR"
echo "→ Token:   $TOKEN_ADDRESS"
echo "→ PullSafe: $PULLSAFE"

echo "→ Balance (pre):"
cast call "$TOKEN_ADDRESS" "balanceOf(address)(uint256)" "$GRANTOR_ADDR" --rpc-url "$RPC_URL"

echo "→ Approving max allowance to PullSafe…"
cast send "$TOKEN_ADDRESS" "approve(address,uint256)" "$PULLSAFE" \
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

echo "→ Allowance now:"
cast call "$TOKEN_ADDRESS" "allowance(address,address)(uint256)" "$GRANTOR_ADDR" "$PULLSAFE" --rpc-url "$RPC_URL"
echo "✓ approve_token.sh done"
