#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

set -a; source ./.env; set +a
source ./.B
source ./.AUTH

# IMPORTANT: Sign a NEW signature for Chain B domain if PullSafe uses chainId in EIP-712 domain (it usually does).
echo "→ Approving token on Chain B…"
cast send "$TOKEN_B" "approve(address,uint256)" "$PULLSAFE_B" 100000000000000000000 \
  --rpc-url "$RPC_B" --private-key "$PRIVATE_KEY" >/dev/null

echo "→ Recomputing digest for Chain B domain…"
DOMAIN_B=$(cast call "$PULLSAFE_B" "domainSeparator()(bytes32)" --rpc-url "$RPC_B")
DIGEST_B=$(cast keccak "0x1901${DOMAIN_B#0x}${STRUCT_HASH#0x}")
SIG_B=$(cast wallet sign --private-key "$PRIVATE_KEY" "$DIGEST_B")

AMOUNT_WEI=500000000000000

echo "→ Pulling on Chain B…"
cast send "$PULLSAFE_B" \
"pull((address,address,address,uint256,uint256,uint256,bytes32),bytes,address,uint256)" \
"($GRANTOR,$GRANTEE,$TOKEN_B,$MAX_PER_PULL,$VALID_AFTER,$VALID_BEFORE,$NONCE)" \
"$SIG_B" "$TOKEN_B" "$AMOUNT_WEI" \
--rpc-url "$RPC_B" --private-key "$PRIVATE_KEY"

echo "✓ pull() on B sent."
