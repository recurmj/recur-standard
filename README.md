# Recur v1.1: Permissioned Pull Core Stabilization

## Overview

Recur defines the **permissioned-pull standard**: a secure, on-chain method to authorize value transfers under explicit grantor consent.  

v1.1 stabilizes:

- **RIP-001**: Permissioned Pull primitive  
- **RIP-002**: Consent Registry (revocation & audit)

These are ready for first production pilot deployments.  

> Note: RIP-003 → RIP-008 remain part of the standard but are **not updated in v1.1**.

---

## Why v1.1

This release focuses on **technical stabilization**:

- RIP-001 enforces pull authorization at call time.  
- RIP-002 provides a canonical ledger for consent and revocation, emitting standardized audit events.  
- All code has been reviewed and reference-tested for predictable execution and safe, granular control.  

This release removes ambiguity in signature validation, revocation logic, and event consistency.

---

## RIP-001 — Permissioned Pull

**Core behavior:**

- Grantor signs a structured EIP-712 authorization off-chain.  
- Grantee can `pull()` value from grantor within the signed limits.  
- No custody contract required.  

**Enforced at pull():**

- Caller = authorized grantee  
- Amount ≤ `maxPerPull`  
- Within validity window (`validAfter` / `validBefore`)  
- Valid signature from grantor  
- Authorization not revoked

---

## RIP-002 — Consent Registry

Tracks all active authorizations (`authHash`):

- Ownership (grantor)  
- Revocation status  
- Total pulled amount  
- Optional soft cap for dashboards

Registry emits standard events:

- `PullExecuted`  
- `AuthorizationRevoked`  
- `AuthorizationBudgetUpdated`

All audits and dashboards consume this single, canonical registry.

---

## Contracts Shipped

| Contract | RIP | Role | Custody? |
|-----------|-----|------|----------|
| `RecurPullSafeV2.sol` | 001/002 | Executes per-call pulls under signed authorization | No |
| `RecurConsentRegistry.sol` | 002 | Tracks authorization revocation & pull totals, emits audit events | No |

> Example usage and SDK helpers are provided in `/sdk` for signing, submitting, and verifying PPOs.

---

## SDK Helpers (JavaScript / ESM)

### `ppo.js` — Build & sign PPO

```js
import { buildPPO, signPPO } from "./sdk/ppo.js";

const ppo = buildPPO({ /* grantor, grantee, token, maxPerPull, validAfter, validBefore, nonce */ });
const signedPPO = await signPPO(grantorSigner, recurPullSafeV2Addr, ppo);
await recurPullSafeV2.connect(granteeSigner).pull(signedPPO, "500000");
```

### `registry.js` — Query / revoke authorizations
~~~
import { isRevoked, pulledTotal, revoke } from "./sdk/registry.js";

const dead = await isRevoked(registryContract, authHash);
await revoke(registryContract, authHash, { from: grantorSigner.address });
~~~

---

## Stewardship

Maintained by **Recur Labs**, canonical reference for the permissioned-pull standard. 
All text & code © 2025 Recur Labs under Apache-2.0.

No token. No governance coin. This is an open technical standard, not a financial instrument.

---

## Authorship & Attribution

v1.1 updates RIP-001 and RIP-002 for technical stability.
Reference prior work (RIP-001 → RIP-008) as canonical prior art.

