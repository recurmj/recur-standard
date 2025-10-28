# Recur — Change Log

All notable changes to this repository are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [v1.0.0] — 2025-10-28  
### Overview  
**Recur v1.0 — Permissioned Pull Standard (RIP-001 → RIP-008 Complete)**  
This release publicly freezes the first full reference stack for consented, policy-bound, cross-domain liquidity movement.

It defines an auditable, revocable, non-custodial flow layer for ERC-20 and other EVM-based value:  
- pre-authorized pull under revocable consent,  
- policy-aware rate limiting,  
- cross-domain routing without bridges or pooled custody,  
- treasury-grade allocation.

### Added  
- **RIP-001 / RIP-002 core path**

  - `RecurPull.sol` — **minimal reference implementation** of the permissioned-pull primitive.  
    - smallest possible surface to audit or fork  
    - enforces: grantee match, time window, per-call max, signature validity, revocation via registry  
    - used as canonical RIP-001 teaching / testing reference  
    - not intended for production but critical for verifying the spec
  - `RecurPullSafeV2.sol` — executes per-call, revocable permissioned pulls under an off-chain EIP-712 Authorization (supports EOAs + EIP-1271 smart contract wallets). Enforces:
    - `maxPerPull`
    - time window `[validAfter, validBefore]`
    - caller must be authorized grantee
    - signature bound to chainId + contract
    - global revocation via the Consent Registry

  - `RecurConsentRegistry.sol` — canonical revocation + accounting:
    - tracks if an Authorization (by `authHash`) is revoked
    - tracks cumulative amount pulled under that authorization
    - binds `authHash → grantor` on first recorded pull so only the real grantor can revoke
    - emits standard audit events (`PullExecuted`, `AuthorizationRevoked`, etc.)

- **RIP-003 / RIP-004 cross-domain path**
  - `FlowIntentRegistry.sol` — verifies and meters “Flow Intents,” which are signed instructions from a treasury like:
    > “Executor X can migrate up to maxTotal of token T from srcDomain → dstDomain between validAfter and validBefore.”
    It enforces:
    - grantor signature (EOA or 1271)
    - validity window
    - cumulative cap tracking
    - revocation by the bound grantor only

  - `CrossNetworkRebalancer.sol` — executes part of a Flow Intent without ever taking custody:
    - confirms executor is approved in both source and destination domains
    - confirms the underlying per-channel authorization (authHash) hasn’t been revoked in the Consent Registry
    - calls `FlowIntentRegistry.verifyAndConsume()` to atomically reserve budget
    - pulls funds directly from the source grantor to the canonical receiver of the destination domain via a domain adapter  
    - no bridge, no wrapper asset, no pooled treasury in this contract

  - `DomainDirectory.sol` — governance map of “domains” (L1s, L2 treasuries, custodians, venues):
    - marks each domain active/inactive
    - defines the canonical receiver address for that domain
    - tracks which executors are approved to act in that domain
    - exposes this to the CrossNetworkRebalancer for enforcement

- **RIP-005 / RIP-006 / RIP-007 / RIP-008 treasury flow control**
  - `FlowChannelHardened.sol` — continuous streaming channel:
    - accrues balance over time at `ratePerSecond`, capped by `maxBalance`
    - grantee can pull accrued funds in discrete chunks
    - grantor can pause, resume, update rate/cap, or revoke permanently
    - never holds funds; always uses `transferFrom(grantor → receiver)`
    - calls into `PolicyEnforcer` before every pull

  - `UniversalClock.sol` — canonical epoch counter for the deployment:
    - defines consistent “epoch windows” on-chain
    - used by `PolicyEnforcer` so all spend ceilings share the same notion of “this epoch”

  - `PolicyEnforcer.sol` — per-epoch spend ceilings / receiver allowlists:
    - enforces `maxPerPull`
    - enforces `maxPerEpoch` using the shared epoch index from `UniversalClock`
    - can restrict receivers to an allowlist
    - can be revoked by the grantor

  - `AdaptiveRouter.sol` — routing coordinator:
    - chooses which active FlowChannelHardened channel to drain
    - asks that channel to pay a given destination directly (no custody)
    - callable only by a controller (e.g. Safe / multisig)

  - `SettlementMesh.sol` — treasury allocator / balancer:
    - tracks desired balance targets (in basis points) per destination venue
    - controller reports current balances (L1 cold, L2 hot, CEX desk, custodian, etc.)
    - finds the venue most underweight vs target
    - nudges liquidity toward it by calling `AdaptiveRouter.routeStep(...)`

### SDK
- `/sdk/ppo.js`  
  - Builds and signs Permissioned Pull Objects (RIP-001) for `RecurPullSafeV2`.
  - Handles EIP-712 domain data and returns `{...ppo, signature}` ready to submit on-chain.

- `/sdk/registry.js`  
  - Thin helpers for `RecurConsentRegistry`: check revocation, get cumulative pulled total, update caps, revoke.

- `/sdk/flowIntent.js`  
  - Builds and signs Flow Intents (RIP-003) for `FlowIntentRegistry`.
  - Produces the exact struct CrossNetworkRebalancer expects, including the grantor signature.

- `/sdk/pull.js`  
  - Optional client-side preflight helpers (window checks, revocation checks) before actually calling `pull()`.

### Security characteristics
- All contracts in this release are **non-custodial**.  
  Nothing here escrows user funds.  
  Every movement is still `transferFrom(grantor → destination)` under explicit consent.

- All high-privilege actions are:
  - permissioned by explicit `controller` / `onlyController` or `onlyGrantor`,
  - revocable by the grantor or by pausing/marking domains inactive,
  - observable via on-chain events for audit.

- Signature paths:
  - EOAs (ECDSA with low-s enforcement)
  - smart contract wallets (EIP-1271)
  - EIP-712 typed data binding chainId + verifyingContract to prevent replay across deployments

- Treasury ops can emergency-stop flow in multiple ways:
  - revoke at `RecurConsentRegistry`
  - revoke an intent in `FlowIntentRegistry`
  - pause or revoke a `FlowChannelHardened` channel
  - set a domain inactive in `DomainDirectory`
  - rotate/disable executors via `DomainDirectory`
  - rotate controller on `AdaptiveRouter`, `SettlementMesh`, etc.

### Internal consistency / naming
- The canonical “per-call consent executor” for RIP-001 / RIP-002 is `RecurPullSafeV2.sol`.  
  This is the contract you actually call in production.
- All other contracts are written to integrate directly with that model (or with `FlowChannelHardened`), not with any legacy prototypes.

### License
- All contracts and SDK code are released under **Apache-2.0**.
- © 2025 Recur Labs / M J.
- There is **no token** associated with this release.

---

## [Pre-release & Draft Work] — 2025-05 → 2025-10  
- Iterated on RIP-001 (“permissioned pull”) and RIP-002 (registry + revocation).  
- Established the `authHash` pattern as a universal handle for consent objects.  
- Prototyped cross-domain “Flow Intents,” leading to `FlowIntentRegistry` + `CrossNetworkRebalancer`.  
- Added streaming/epoch layer (`FlowChannelHardened`, `PolicyEnforcer`, `UniversalClock`) to support treasury-grade rate limiting.  
- Added routing/targeting layer (`AdaptiveRouter`, `SettlementMesh`) for autonomous liquidity balancing across venues.

---

## [Unreleased / Roadmap]  
These items are not part of v1.0.0 but are planned:

- **Permit2 / meta-approval path**  
  Let a grantor authorize spend without setting a persistent ERC-20 allowance.

- **Receiver policy registries at the domain layer**  
  DomainDirectory-level KYC / jurisdiction metadata surfaced on-chain.

- **Typed SDK for TypeScript / viem**  
  Ship well-typed method wrappers and ABIs for each contract.

- **RIP-009+**  
  Extended vault coordination, rate-bounded pipes across custodians, automated unwind paths after revoke.

---

## Integrity / Governance Notes
- Each contract with a `controller` assumes that address is a Safe / multisig, not an EOA.
- `DomainDirectory`, `AdaptiveRouter`, `SettlementMesh`, and `CrossNetworkRebalancer` should all point to the same treasury Safe for first deployment unless you have a reason to decentralize those authorities.
- `RecurConsentRegistry` and `FlowIntentRegistry` do **not** themselves move funds. They only attest and meter. This separation is intentional for auditability and legal clarity.
