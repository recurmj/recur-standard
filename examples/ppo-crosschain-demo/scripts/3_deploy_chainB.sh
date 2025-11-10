#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../" && pwd)"
cd "$ROOT_DIR"

set -a; source examples/ppo-crosschain-demo/.env; set +a
source examples/ppo-crosschain-demo/scripts/utils.sh

must RPC_B; must PRIVATE_KEY

ADDR=$(addr_from_pk)
echo "→ Chain B deployer: $ADDR"

echo "→ Deploying Registry (B)…"
forge create --rpc-url "$RPC_B" \
  --private-key "$PRIVATE_KEY" \
  contracts/RecurConsentRegistry.sol:RecurConsentRegistry \
  | tee examples/ppo-crosschain-demo/.deploy_registry_B.txt
REGISTRY_B=$(awk '/Deployed to:/ {print $3}' examples/ppo-crosschain-demo/.deploy_registry_B.txt)

echo "→ Deploying PullSafe (B)…"
forge create --rpc-url "$RPC_B" \
  --private-key "$PRIVATE_KEY" \
  contracts/RecurPullSafeV2.sol:RecurPullSafeV2 \
  --constructor-args "$REGISTRY_B" \
  | tee examples/ppo-crosschain-demo/.deploy_pullsafe_B.txt
PULLSAFE_B=$(awk '/Deployed to:/ {print $3}' examples/ppo-crosschain-demo/.deploy_pullsafe_B.txt)

cast send "$REGISTRY_B" "setTrustedExecutor(address,bool)" "$PULLSAFE_B" true \
  --rpc-url "$RPC_B" --private-key "$PRIVATE_KEY" >/dev/null

cat > examples/ppo-crosschain-demo/.B <<EOF
REGISTRY_B=$REGISTRY_B
PULLSAFE_B=$PULLSAFE_B
EOF

echo "✓ B: REGISTRY_B=$REGISTRY_B  PULLSAFE_B=$PULLSAFE_B"
