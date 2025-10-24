# Recur — Permissioned Pull for Digital Value
### The open standard for consented continuity (RIP-001)

## Quick Start (RIP-001 + RIP-002)

Recur is a permissioned-pull standard.
It lets value move under consent before failure; instead of reacting after.

Core flow:

1. The grantor (user / treasury / protocol) signs an Authorization off-chain:
   - who can pull (grantee)
   - which token
   - how much per pull
   - valid time window
   - nonce

2. The grantee calls `pull()` on `RecurPullSafeV2.sol`.
   - The contract checks:
     - it’s the right grantee
     - we’re inside the time window
     - the amount is within limits
     - the Authorization signature is valid (stubbed here, audit-ready EIP-712 later)
     - the consent has NOT been revoked in the Consent Registry

3. Funds move directly from grantor → grantee using ERC-20 `transferFrom()`.
   No custody, no pooled funds.

4. The contract tells `RecurConsentRegistry.sol` to record the pull.
   - The registry emits canonical RIP-002 events (`PullExecuted`, `AuthorizationRevoked`, etc.)
   - Indexers / wallets / auditors can now track flows, totals, and revocations.

5. At any point, the grantor can revoke by calling `revoke()` on the Consent Registry.
   After that, any future `pull()` using that authHash will fail automatically.

This is the first complete loop of consented continuity:
- programmable pull,
- global revocation,
- standard events,
- zero custody.

**Recur** defines the first general-purpose *permissioned-pull* primitive for ERC-20 (and other EVM assets).  
It lets value flow safely and continuously — **before failure, not after** — via explicit, revocable consent.

---

## Overview

Push-based payments react after imbalance. That delay creates volatility and operational risk.  
Recur introduces **pull within consent**: the grantor signs an EIP-712 authorization, the grantee can pull within limits, and the grantor can revoke instantly. Consent becomes structure.

This repository is the **canonical reference** for **RIP-001**, including:
- `contracts/RecurPull.sol` — minimal standard primitive
- `contracts/RecurPullSafeV2.sol` — hardened template for pilots
- `docs/RIP-001.md` — specification
- `docs/RIP-002.md` — *Consent Registry & Events* (optional index, draft)
- `docs/AUDIT_SUMMARY.md` — informal review notes
- `tests/` — test scaffold notes

License: **Apache-2.0**. No token. Open standard.

---

## ⚙️ Quick Start

### 1) Install & build (Foundry or Hardhat)
```bash
forge build
```
or with hardhat: 

``` bash
npm i && npx hardhat compile
```

### 2) Import the primitive (or the safe template)

~~~

import "./contracts/RecurPull.sol";          // minimal primitive (standard)
import "./contracts/RecurPullSafeV2.sol";    // recommended for pilots

~~~

### 3) Grantor signs an Authorization (EIP-712)

~~~

Authorization {
  grantor:    0xSender,
  grantee:    0xReceiver,   // must be msg.sender in pull()
  token:      0xToken,
  maxAmount:  1000e18,      // total cap (SafeV2) or per-call (primitive)
  validAfter: 1720000000,
  validBefore:1730000000,
  nonce:      keccak256("unique")
}

~~~

### 4) Grantee pulls within consent

~~~

pull(auth, amount, signature);          // requires allowance
pullWithPermit(auth, amount, sig, data);// for ERC-2612 tokens (SafeV2)

~~~

### 5) Grantor can revoke at any time

~~~

revoke(auth);                 // SafeV2 (bound to grantor)
revoke(authHash);             // primitive (hash-based)

~~~

See docs/RIP-001.md for full semantics.

---

## Contracts

| **Contract**             | **Purpose**                 | **Notes**                                                                                                                                                                                                                                                                             |
|----------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **RecurPull.sol**    | Minimal RIP-001 reference | Smallest surface to audit/extend. Includes **EIP-712** authorization, `verify → pull` flow, and simple revoke. Perfect for understanding & composing your own modules.                                                                    |
| **RecurPullSafeV2.sol** | Hardened pilot template  | Adds cumulative cap, revocation bound to grantor, **EIP-1271** smart wallet support, optional **ERC-2612** `permit()`, reentrancy guard, and helper functions. Recommended starting point for pilots.                                      |

Both implement the same **authorize → verify → pull → revoke** logic that defines the permissioned-pull standard.

---

## Folder Structure

~~~

contracts/
 ├─ RecurPull.sol
 └─ RecurPullSafeV2.sol
docs/
 ├─ RIP-001.md
 ├─ RIP-002.md      # Authorization Registry & Events (optional index, draft)
 ├─ AUDIT_SUMMARY.md
 └─ CHANGELOG.md
tests/
 └─ README.md
LICENSE
README.md

~~~

---

## Audit Summary (informal)
-	✅ Domain separation (chainId + verifyingContract)  
-	✅ ECDSA (EOA) + EIP-1271 (SCW) signature verification (SafeV2)  
-	✅ Revocation (hash or grantor-bound)  
-	✅ Cumulative cap (SafeV2)  
-	✅ Reentrancy guard (SafeV2)  
-	✅ Zero address & time-window checks  
-	✅ permit() path (SafeV2) to avoid pre-approve UX  

Recommended v1.1 improvements:
-	Use SafeERC20 for non-standard tokens  
-	Optional per-pull limit / rate-limit  
-	Permit2 compatibility  

→ Full notes in docs/AUDIT_SUMMARY.md.

---

## Specs & RIPs  
	
- RIP-001: Permissioned Pull Primitive (core standard)
- RIP-002: Authorization Registry & Events (optional index layer, draft)

Future RIPs: ERC-721 / 4626 adaptations, metered/streamed limits, cross-chain consent registries.

---


## Philosophy

Recur encodes **freedom as structure:** replacing reactive control with consented continuity.
Liquidity moves before failure; stability becomes emergent.

---

## Stewardship

This repository is maintained by **Recur Labs** as the canonical reference for the permissioned-pull standard (RIP-001). 
Recur Labs invites implementation feedback, formal audits, and ecosystem integrations.
All text and code are © 2025 M J / Recur Labs under the Apache 2.0 License.

There is **no token** associated with this repository.
Recur is an open standard — not a financial instrument or investment project.

---

## Authorship & Attribution

Recur (RIP-001) — The Permissioned-Pull Standard for Digital Value —
was first published by **M J (Recur Labs)** in October 2025 as the original specification introducing *consented continuity* and *permissioned-pull flow* for EVM-based assets.

All text, architecture, and reference code are © 2025 Recur Labs.

Any subsequent EIPs, ERCs, or derivative works referencing the permissioned-pull model or consented continuity should cite this repository as **prior art** and include attribution to *Recur Labs and M J* as the canonical source.

---

## Resources

- Whitepaper: [Recur — The Flow Layer for Digital Value](https://recurprotocol.com/Recur_Whitepaper_v1.0_Oct2025.pdf)
- Technical Paper: Releasing October 28, 2025
- Website: recurprotocol.com
- Labs Updates: @recurlabs (X/Twitter)
- Founder: @recurmj (X/Twitter)

