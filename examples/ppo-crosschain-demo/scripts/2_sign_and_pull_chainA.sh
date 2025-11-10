#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

set -a; source ./.env; set +a
source ./.A

GRANTOR="$GRANTOR_A"
GRANTEE="$GRANTOR_A"    # demo; change to another addr if desired
TOKEN="$TOKEN_A"

echo "→ Approving token on Chain A…"
cast send "$TOKEN" "approve(address,uint256)" "$PULLSAFE_A" 100000000000000000000 \
  --rpc-url "$RPC_A" --private-key "$PRIVATE_KEY" >/dev/null

AUTH_TYPEHASH=$(cast keccak "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
STRUCT_ENC=$(cast abi-encode "(bytes32,address,address,address,uint256,uint256,uint256,bytes32)" "$AUTH_TYPEHASH" "$GRANTOR" "$GRANTEE" "$TOKEN" "$MAX_PER_PULL" "$VALID_AFTER" "$VALID_BEFORE" "$NONCE")
STRUCT_HASH=$(cast keccak "$STRUCT_ENC")
DOMAIN_A=$(cast call "$PULLSAFE_A" "domainSeparator()(bytes32)" --rpc-url "$RPC_A")
DIGEST_A=$(cast keccak "0x1901${DOMAIN_A#0x}${STRUCT_HASH#0x}")
SIG_A=$(cast wallet sign --private-key "$PRIVATE_KEY" "$DIGEST_A")

AUTH_HASH=$(cast keccak "$(cast abi-encode '(address,address,address,uint256,uint256,uint256,bytes32)' "$GRANTOR" "$GRANTEE" "$TOKEN" "$MAX_PER_PULL" "$VALID_AFTER" "$VALID_BEFORE" "$NONCE")")

echo "→ Pulling once on Chain A…"
AMOUNT_WEI=500000000000000   # 0.0005 ETH
cast send "$PULLSAFE_A" \
"pull((address,address,address,uint256,uint256,uint256,bytes32),bytes,address,uint256)" \
"($GRANTOR,$GRANTEE,$TOKEN,$MAX_PER_PULL,$VALID_AFTER,$VALID_BEFORE,$NONCE)" \
"$SIG_A" "$TOKEN" "$AMOUNT_WEI" \
--rpc-url "$RPC_A" --private-key "$PRIVATE_KEY"

cat > ./.AUTH <<EOF
GRANTOR=$GRANTOR
GRANTEE=$GRANTEE
TOKEN_A=$TOKEN
STRUCT_HASH=$STRUCT_HASH
DOMAIN_A=$DOMAIN_A
DIGEST_A=$DIGEST_A
SIG_A=$SIG_A
AUTH_HASH=$AUTH_HASH
EOF

echo "✓ AUTH_HASH=$AUTH_HASH"
