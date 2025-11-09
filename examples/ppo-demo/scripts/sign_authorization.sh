#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
set -a; source "$ROOT_DIR/examples/ppo-demo/.env"; set +a
source "$ROOT_DIR/examples/ppo-demo/.addrs"

: "${GRANTEE:?GRANTEE missing in .env}"
: "${TOKEN_ADDRESS:?TOKEN_ADDRESS missing in .env}"
: "${MAX_PER_PULL:?}"
: "${VALID_AFTER:?}"
: "${VALID_BEFORE:?}"

GRANTOR_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY")
AUTH_TYPEHASH=$(cast keccak "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)")

# Generate NONCE if not set
if [ -z "${NONCE:-}" ]; then
  NONCE=$(cast keccak "recur-$(date +%s)-$RANDOM")
fi

echo "→ Grantor: $GRANTOR_ADDR"
echo "→ Grantee: $GRANTEE"
echo "→ Token:   $TOKEN_ADDRESS"
echo "→ maxPerPull=$MAX_PER_PULL validAfter=$VALID_AFTER validBefore=$VALID_BEFORE"
echo "→ nonce=$NONCE"

# structHash (type list MUST be quoted)
ENC_STRUCT=$(cast abi-encode \
  '(bytes32,address,address,address,uint256,uint256,uint256,bytes32)' \
  "$AUTH_TYPEHASH" "$GRANTOR_ADDR" "$GRANTEE" "$TOKEN_ADDRESS" "$MAX_PER_PULL" "$VALID_AFTER" "$VALID_BEFORE" "$NONCE")
STRUCT_HASH=$(cast keccak "$ENC_STRUCT")

DOMAIN=$(cast call "$PULLSAFE" 'domainSeparator()(bytes32)' --rpc-url "$RPC_URL")
DIGEST=$(cast keccak "0x1901${DOMAIN#0x}${STRUCT_HASH#0x}")

# EIP-712: sign the digest raw (no rehash)
SIGNATURE=$(cast wallet sign --no-hash "$DIGEST" --private-key "$PRIVATE_KEY")

# Save for pull
cat > "$ROOT_DIR/examples/ppo-demo/.ppo" <<EOF
GRANTOR=$GRANTOR_ADDR
GRANTEE=$GRANTEE
TOKEN=$TOKEN_ADDRESS
MAX_PER_PULL=$MAX_PER_PULL
VALID_AFTER=$VALID_AFTER
VALID_BEFORE=$VALID_BEFORE
NONCE=$NONCE
STRUCT_HASH=$STRUCT_HASH
DOMAIN=$DOMAIN
DIGEST=$DIGEST
SIGNATURE=$SIGNATURE
EOF

echo "STRUCT_HASH=$STRUCT_HASH"
echo "DOMAIN=$DOMAIN"
echo "DIGEST=$DIGEST"
echo "SIGNATURE=$SIGNATURE"
echo "AUTH_HASH (== STRUCT_HASH) = $STRUCT_HASH"
echo "✓ sign_authorization.sh done"
