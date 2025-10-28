
# Recur — RIP-001 Reference
## Informal Audit Summary (October 2025)

This informal audit was conducted by independent reviewers under Recur Labs supervision in October 2025. It does not replace a full formal verification but establishes confidence for public pilot deployments.

Scope: `RecurPull.sol` (primitive), `RecurPullSafeV2.sol` (hardened template)

### Findings (by category)

**Auth & Domain**
- EIP-712 typed-data with domain separator (name, version, chainId, verifyingContract) — prevents cross-chain/contract replay. ✅
- Authorization struct includes `nonce` for uniqueness. ✅

**Signature Verification**
- EOAs via ECDSA `ecrecover`. ✅
- Smart-contract wallets via EIP-1271 (SafeV2). ✅
- Digest = `keccak256("\x19\x01", domain, structHash)`. ✅

**Revocation**
- Primitive: hash-based revoke. ✅ (simple; bind to grantor if desired)
- SafeV2: revocation requires `auth` and `msg.sender == grantor`. ✅

**Limits / Accounting**
- Primitive: simple per-call limit by `amount` and time window. ✅
- SafeV2: cumulative cap via `spent[authHash] + amount <= maxAmount`. ✅
- Time-window checks: `validAfter ≤ now < validBefore`. ✅

**Token Transfer**
- Uses `IERC20.transferFrom`. ✅
- Recommendation: wrap with OZ `SafeERC20` for non-standard tokens. ⚠️

**Reentrancy**
- Local nonReentrant guard in SafeV2. ✅
- Single external call to token — low surface.

**Permit Path**
- SafeV2 optional `pullWithPermit`: calls ERC-2612 `permit()` then `transferFrom`. Validates `value ≥ amount`. ✅

**DoS / Griefing**
- Revocation and caps mitigate repeated small pulls.
- Nonce allows unique consents; registry (RIP-002) would aid discovery/UX. ✅

### Recommendations (v1.1 hardening)
1. Use `SafeERC20` for transfer compatibility edge cases.
2. Optional per-pull max and min interval (for retail UX).
3. Permit2 support where available.
4. Add Foundry tests and fuzz cases (boundary timestamps, signature tamper, revoke race).

### Verdict
No critical or high-severity issues identified for the intended scope.  
**SafeV2** is suitable for pilots; the **primitive** is ideal for learning/extending and low-surface audits.

---

© 2025 Recur Labs — Released under CC BY 4.0.
