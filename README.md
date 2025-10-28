# Recur — Permissioned Pull for Digital Value

## The open standard for consented continuity (RIP-001 → RIP-008)

Recur defines the permissioned-pull standard for safe, programmable movement of value across accounts, contracts, domains, and venues; without custodial bridges or “just trust ops” spreadsheets.

This repo ships audited-style reference contracts and SDK helpers for:

- **RIP-001**: Permissioned Pull primitive (per-call consent)
- **RIP-002**: Consent Registry (revocation + global audit log)
- **RIP-003**: FlowIntents (cross-domain signed liquidity rights)
- **RIP-004**: CrossNetworkRebalancer (domain-to-domain routing under signed intent)
- **RIP-005**: FlowChannelHardened (continuous streaming channel with rate limit, pause, revoke)
- **RIP-006**: AdaptiveRouter + UniversalClock (routing + shared epoch slicing)
- **RIP-007**: PolicyEnforcer (per-epoch spend ceilings / allowlists)
- **RIP-008**: SettlementMesh (treasury-level allocator / balancer)

**Status:**
- RIP-001 → RIP-008: reference complete
- Ready to freeze for first production pilot
- Licensed under **Apache-2.0**
- No token, no governance coin, no protocols to ape

---

## Why Recur exists

Push-based finance reacts after something is wrong. You notice imbalance (too much on exchange, not enough on L2, OTC desk dry), then you scramble.

Recur inverts that.  
Instead of reacting *after* risk, you pre-authorize *safe pulls* under hard conditions:

- who can pull
- which asset
- how much per call / per epoch
- where it can go
- when it expires
- ability to nuke it instantly

You get:
- automated liquidity routing without pooled custody
- programmable limits instead of “please don’t rug me”
- fully on-chain, machine-readable consent and revocation
- auditable global flow history

This is “consented continuity.”

---

## High-level architecture

### RIP-001: Permissioned Pull

Grantor signs a structured EIP-712 Authorization off-chain.  
Grantee can pull within that Authorization.  
Transfer is **direct grantor → grantee via `transferFrom()`**.  
No custody in the executor contract.

Rules enforced at pull() time:
- caller must be the authorized grantee
- within time window
- amount ≤ `maxPerPull`
- signature must match grantor (EOA or 1271)
- Authorization not revoked

### RIP-002: Consent Registry

Global ledger for each Authorization (`authHash`):
- who owns it (the grantor)
- has it been revoked?
- how much total has been pulled so far?
- optional declared “soft cap” for dashboards

Every successful pull calls `recordPull()` and the registry emits canonical events:
- `PullExecuted`
- `AuthorizationRevoked`
- `AuthorizationBudgetUpdated`

Explorers and auditors only have to watch this one registry.

### RIP-003 / RIP-004: Cross-domain liquidity

Now zoom out.

You don’t just want “Alice can pull 100 USDC per call.”  
You want “Move 5m USDC from domain A to domain B under policy, without bridges or internal chaos.”

That’s a **FlowIntent**.

- Grantor signs:  
  “Executor X can migrate up to `maxTotal` of token T from `srcDomain` to `dstDomain` between `validAfter` and `validBefore`.”

- The **FlowIntentRegistry** (RIP-003) verifies the signature, enforces time window, enforces total cap, and tracks how much has already been consumed.

- The **CrossNetworkRebalancer** (RIP-004) executes a piece of that intent:
  - checks that the executor is approved in both domains,
  - checks that the underlying per-channel consent (authHash) is still live (not revoked in the Consent Registry),
  - asks the registry to `verifyAndConsume()` the intent budget,
  - calls a domain adapter to actually move real tokens directly from the grantor to the canonical treasury receiver of the destination domain.

No bridge, no wrapper token, no pooled “vault”.  
It’s just orchestrated `transferFrom()` under layered, revokeable consent.

### RIP-005 / RIP-006 / RIP-007 / RIP-008: Treasury-grade flow control

At treasury scale, you rarely move one big chunk. You continuously rebalance across multiple venues, desks, chains, custodians.

You need:
- streaming channels (rate-limited drip instead of giant one-offs),
- per-epoch spend ceilings,
- who’s allowed to receive,
- “route funds here because this venue is underweight,”
- a single multisig / Safe that can turn the whole thing off if panicking.

That’s the rest of the stack.

---

## Contracts shipped in this repo

| Contract | RIP | Role | Custodies funds? |
|-----------|-----|------|------------------|
| `RecurPullSafeV2.sol` | 001/002 | Execute per-call pulls under a signed Authorization. Enforces window, maxPerPull, signature, revocation. | No |
| `RecurConsentRegistry.sol` | 002 | Canonical revocation + accounting for each Authorization (`authHash`). Emits audit events. | No |
| `FlowIntentRegistry.sol` | 003 | Verifies FlowIntents (cross-domain rights): checks signature, enforces total cap, tracks consumption, supports revoke. | No |
| `CrossNetworkRebalancer.sol` | 004 | Uses a FlowIntent to actually route value from srcDomain → dstDomain via domain adapters, under DomainDirectory policy. | No |
| `DomainDirectory.sol` | 004/008 | Governance map of domains → approved executors, canonical receiver addresses, adapter metadata, active/paused flag. | No |
| `FlowChannelHardened.sol` | 005 | Streaming payment channel with pause, revoke, rate limit, accrued buffer. Calls PolicyEnforcer before every pull. | No |
| `AdaptiveRouter.sol` | 006 | Chooses which active channel to drain and calls its `pull()` into a destination. | No |
| `UniversalClock.sol` | 006 | Canonical epoch index for this deployment (e.g. 3600s epochs). PolicyEnforcer trusts this clock. | No |
| `PolicyEnforcer.sol` | 007 | Enforces per-epoch spend ceilings, per-call ceilings, and receiver allowlists using UniversalClock epochs. | No |
| `SettlementMesh.sol` | 008 | Treasury-level allocator. Figures out which destination is most underweight and tells AdaptiveRouter to feed it. | No |

---

## SDK helpers (JavaScript / ethers)

We ship a tiny `sdk/` directory (ESM) to make signing and submitting flows easier.

### `ppo.js` — build and sign a Permissioned Pull Object

~~~js
import { buildPPO, signPPO } from "./sdk/ppo.js";

const ppo = buildPPO({
  grantor: "0xGrantor",
  grantee: "0xGrantee",
  token: "0xUSDC",
  maxPerPull: "1000000",
  validAfter: 1720000000,
  validBefore: 1730000000,
  nonce: "0xuniqueSalt"
});

const signedPPO = await signPPO(grantorSigner, recurPullSafeV2Addr, ppo);

await recurPullSafeV2.connect(granteeSigner).pull(signedPPO, "500000");
~~~

### `registry.js` — talk to the Consent Registry

~~~js
import { isRevoked, pulledTotal, capOf, revoke } from "./sdk/registry.js";

const dead = await isRevoked(registryContract, authHash);
const used = await pulledTotal(registryContract, authHash);
const cap = await capOf(registryContract, authHash);

await revoke(registryContract, authHash, { from: grantorSigner.address });
~~~

### `flowIntent.js` — build and sign a FlowIntent for cross-domain moves

~~~js
import { buildFlowIntent, signFlowIntent } from "./sdk/flowIntent.js";

const flowIntent = buildFlowIntent({
  grantor: "0xTreasurySafe",
  executor: "0xRouterOrOpsBot",
  token: "0xUSDC",
  srcDomain: "base:treasury",
  dstDomain: "ethereum:settlement",
  maxTotal: "5000000000",
  validAfter: 1720000000,
  validBefore: 1730000000,
  nonce: "0xnonceSalt",
  metadataHash: "0xoptionalPolicyRef"
});

const signature = await signFlowIntent(treasurySafeSigner, flowIntentRegistryAddr, flowIntent);
const crossPayload = { ...flowIntent, authHash: someUnderlyingChannelOrPPOAuthHash, signature };
~~~

---

## Philosophy

Recur encodes **freedom as structure:** replacing reactive control with consented continuity.
Liquidity moves before failure; stability becomes emergent.

---

## Stewardship

This repository is maintained by **Recur Labs** as the canonical reference for the permissioned-pull standard. 
Recur Labs invites implementation feedback, formal audits, and ecosystem integrations.
All text and code are © 2025 M J / Recur Labs under the Apache 2.0 License.

There is **no token** associated with this repository.
Recur is an open standard — not a financial instrument or investment project.

---

## Authorship & Attribution

Recur (RIP-001 → RIP-008) — The Permissioned-Pull Standard for Digital Value —
was first published by **M J (Recur Labs)** in October 2025 as the original specification introducing *consented continuity* and *permissioned-pull flow* for EVM-based assets.

All text, architecture, and reference code are © 2025 Recur Labs.

Any subsequent EIPs, ERCs, or derivative works referencing the permissioned-pull model or consented continuity should cite this repository as **prior art** and include attribution to *Recur Labs and M J* as the canonical source.

---

## Resources

- Whitepaper: [Recur — The Flow Layer for Digital Value](https://recurprotocol.com/Recur_Whitepaper_v1.0_Oct2025.pdf)
- Technical Paper: [Recur — Defining the Permissioned-Pull Standard for Digital Value](https://recurprotocol.com/Recur_Technical_Paper_v1.0_Oct2025.pdf)
- Website: recurprotocol.com
- Labs Updates: @recurlabs (X/Twitter)
- Founder: @recurmj (X/Twitter)
