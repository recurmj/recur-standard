#!/usr/bin/env bash
set -euo pipefail
# Requires ETHERSCAN_API_KEY or Basescan key depending on RPC
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT_DIR"

set -a; source examples/ppo-demo/.env; set +a
source examples/ppo-demo/.addrs

: "${ETHERSCAN_API_KEY:?Set ETHERSCAN_API_KEY for Sepolia verification}"

echo "→ Verifying Registry…"
forge verify-contract \
  --rpc-url "$RPC_URL" \
  --etherscan-api-key "$ETHERSCAN_API_KEY" \
  "$REGISTRY" contracts/RecurConsentRegistry.sol:RecurConsentRegistry

echo "→ Verifying PullSafe…"
forge verify-contract \
  --rpc-url "$RPC_URL" \
  --etherscan-api-key "$ETHERSCAN_API_KEY" \
  "$PULLSAFE" contracts/RecurPullSafeV2.sol:RecurPullSafeV2

echo "✓ Verification submitted (watch Etherscan for status)."
