#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/deploy_registry_and_pullsafe.sh [--force]
FORCE=0
if [[ "${1:-}" == "--force" ]]; then FORCE=1; fi

# ── Load env ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f examples/ppo-demo/.env ]]; then
  echo "✗ Missing examples/ppo-demo/.env"; exit 1
fi
set -a; source examples/ppo-demo/.env; set +a

: "${RPC_URL:?RPC_URL not set}"
: "${PRIVATE_KEY:?PRIVATE_KEY not set}"

ADDR="$(cast wallet address --private-key "$PRIVATE_KEY")"
CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)"

echo "→ Deployer:   $ADDR"
echo "→ RPC:        $RPC_URL"
echo "→ chainId:    ${CHAIN_ID:-unknown}"

OUT_TX_REG="examples/ppo-demo/.deploy_registry.txt"
OUT_TX_SAFE="examples/ppo-demo/.deploy_pullsafe.txt"
OUT_ADDRS="examples/ppo-demo/.addrs"
OUT_ADDRS_JSON="examples/ppo-demo/.addrs.json"

# If addresses already exist and not forcing, skip deploy
if [[ -f "$OUT_ADDRS" && "$FORCE" -eq 0 ]]; then
  echo "• Found $OUT_ADDRS (use --force to redeploy)."
  cat "$OUT_ADDRS"
  exit 0
fi

# ── Deploy Registry ─────────────────────────────────────────────────────────────
echo "→ Deploying RecurConsentRegistry…"
forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  contracts/RecurConsentRegistry.sol:RecurConsentRegistry \
  | tee "$OUT_TX_REG"

REGISTRY="$(awk '/Deployed to:/ {print $3}' "$OUT_TX_REG" | tail -n1)"
if [[ -z "${REGISTRY:-}" ]]; then
  echo "✗ Could not parse Registry address from forge output"; exit 1
fi
echo "   REGISTRY=$REGISTRY"

# Verify code present
REG_CODE="$(cast code "$REGISTRY" --rpc-url "$RPC_URL")"
if [[ "${REG_CODE,,}" == "0x" || -z "$REG_CODE" ]]; then
  echo "✗ Registry has no code at $REGISTRY"; exit 1
fi

# ── Deploy PullSafeV2 ───────────────────────────────────────────────────────────
echo "→ Deploying RecurPullSafeV2 (registry -> $REGISTRY)…"
forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  contracts/RecurPullSafeV2.sol:RecurPullSafeV2 \
  --constructor-args "$REGISTRY" \
  | tee "$OUT_TX_SAFE"

PULLSAFE="$(awk '/Deployed to:/ {print $3}' "$OUT_TX_SAFE" | tail -n1)"
if [[ -z "${PULLSAFE:-}" ]]; then
  echo "✗ Could not parse PullSafe address from forge output"; exit 1
fi
echo "   PULLSAFE=$PULLSAFE"

SAFE_CODE="$(cast code "$PULLSAFE" --rpc-url "$RPC_URL")"
if [[ "${SAFE_CODE,,}" == "0x" || -z "$SAFE_CODE" ]]; then
  echo "✗ PullSafe has no code at $PULLSAFE"; exit 1
fi

# ── Trust executor in Registry ──────────────────────────────────────────────────
echo "→ Trusting executor (PullSafe) in Registry…"
TX_TRUST="$(cast send "$REGISTRY" \
  "setTrustedExecutor(address,bool)" "$PULLSAFE" true \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  | awk '/transactionHash/ {print $2}' | tail -n1 || true)"

if [[ -z "${TX_TRUST:-}" ]]; then
  echo "✗ Failed to send setTrustedExecutor"; exit 1
fi

# Wait and confirm status
REC_STATUS="$(cast receipt "$TX_TRUST" --rpc-url "$RPC_URL" | awk '/status/ {print $2}' | tail -n1)"
if [[ "$REC_STATUS" != "1" && "$REC_STATUS" != "0x1" ]]; then
  echo "✗ setTrustedExecutor reverted (tx: $TX_TRUST)"; exit 1
fi
echo "   ✓ Trusted executor set (tx: $TX_TRUST)"

# ── Persist outputs ─────────────────────────────────────────────────────────────
cat > "$OUT_ADDRS" <<EOF
REGISTRY=$REGISTRY
PULLSAFE=$PULLSAFE
GRANTOR=$ADDR
CHAIN_ID=${CHAIN_ID:-}
EOF

cat > "$OUT_ADDRS_JSON" <<EOF
{
  "registry": "$REGISTRY",
  "pullSafe": "$PULLSAFE",
  "grantor": "$ADDR",
  "chainId": "${CHAIN_ID:-}"
}
EOF

echo "✓ Done. Addresses saved:"
echo "  - $OUT_ADDRS"
echo "  - $OUT_ADDRS_JSON"
echo "  (use --force to redeploy)"
