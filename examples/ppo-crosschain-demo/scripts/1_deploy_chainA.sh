#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../" && pwd)"
cd "$ROOT_DIR"

set -a; source examples/ppo-crosschain-demo/.env; set +a
source examples/ppo-crosschain-demo/scripts/utils.sh

must RPC_A; must PRIVATE_KEY

ADDR=$(addr_from_pk)
echo "→ Chain A deployer: $ADDR"

echo "→ Deploying Registry (A)…"
forge create --rpc-url "$RPC_A" \
  --private-key "$PRIVATE_KEY" \
  contracts/RecurConsentRegistry.sol:RecurConsentRegistry \
  | tee examples/ppo-crosschain-demo/.deploy_registry_A.txt
REGISTRY_A=$(awk '/Deployed to:/ {print $3}' examples/ppo-crosschain-demo/.deploy_registry_A.txt)

echo "→ Deploying PullSafe (A)…"
forge create --rpc-url "$RPC_A" \
  --private-key "$PRIVATE_KEY" \
  contracts/RecurPullSafeV2.sol:RecurPullSafeV2 \
  --constructor-args "$REGISTRY_A" \
  | tee examples/ppo-crosschain-demo/.deploy_pullsafe_A.txt
PULLSAFE_A=$(awk '/Deployed to:/ {print $3}' examples/ppo-crosschain-demo/.deploy_pullsafe_A.txt)

cast send "$REGISTRY_A" "setTrustedExecutor(address,bool)" "$PULLSAFE_A" true \
  --rpc-url "$RPC_A" --private-key "$PRIVATE_KEY" >/dev/null

cat > examples/ppo-crosschain-demo/.A <<EOF
REGISTRY_A=$REGISTRY_A
PULLSAFE_A=$PULLSAFE_A
GRANTOR_A=$ADDR
EOF

echo "✓ A: REGISTRY_A=$REGISTRY_A  PULLSAFE_A=$PULLSAFE_A"
