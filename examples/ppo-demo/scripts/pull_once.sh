#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <amount-ether-like 0.0005>"; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
set -a; source "$ROOT_DIR/examples/ppo-demo/.env"; set +a
source "$ROOT_DIR/examples/ppo-demo/.addrs"
source "$ROOT_DIR/examples/ppo-demo/.ppo"

AMOUNT_WEI=$(cast to-wei "$1" ether)
echo "→ Pulling amount = $AMOUNT_WEI wei"

# Tuple: (Authorization, bytes signature)
# Try signature with pull(auth,amount) variant
TXHASH=$(
  cast send "$PULLSAFE" \
    'pull((address,address,address,uint256,uint256,uint256,bytes32,bytes),uint256)' \
    "($GRANTOR,$GRANTEE,$TOKEN,$MAX_PER_PULL,$VALID_AFTER,$VALID_BEFORE,$NONCE,$SIGNATURE)" \
    "$AMOUNT_WEI" \
    --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  | awk '/transactionHash/ {print $2}'
)

echo "→ Pull tx: $TXHASH"

echo "→ Post-balances:"
echo -n "  Grantee: "
cast call "$TOKEN" "balanceOf(address)(uint256)" "$GRANTEE" --rpc-url "$RPC_URL"
echo "✓ pull_once.sh done"
