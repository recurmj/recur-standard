# Tests

This repository freezes the reference contracts first, then backfills deep tests.  
Recommended stack: **Foundry** (`forge test`) and property/fuzz tests for edge cases.

## Core scenarios to cover

### RIP-001 / RIP-002 (RecurPullSafeV2 + RecurConsentRegistry)
- `pull()` succeeds:
  - msg.sender == grantee
  - within `[validAfter, validBefore]`
  - amount ≤ maxPerPull
  - signature is valid (EOA and EIP-1271 variants)
  - registry.isRevoked(authHash) == false
- Revert when:
  - signature is tampered
  - timestamp < validAfter or > validBefore
  - amount > maxPerPull
  - authHash is revoked in the registry
- Revocation:
  - grantor calls `revoke(authHash)` in registry
  - subsequent `pull()` reverts
  - registry binds `authHash` → grantor on first `recordPull` and rejects revoke from any other caller
- Accounting:
  - registry `recordPull` increments totalPulled
  - PullExecuted emitted with the correct cumulative total

### RIP-003 / RIP-004 (FlowIntentRegistry + CrossNetworkRebalancer)
- `verifyAndConsume`:
  - accepts valid FlowIntent signature
  - enforces `validAfter` / `validBefore`
  - enforces cumulative cap across multiple calls
  - stores ownerOfIntent on first successful consume
  - reverts if revoked
- `revokeIntent`:
  - only bound grantor can revoke a given intentHash
  - after revoke, further `verifyAndConsume` reverts
- CrossNetworkRebalancer:
  - only `executor` or `controller` can call
  - executor must be approved in **both** srcDomain and dstDomain in DomainDirectory
  - rejects if ConsentRegistry says underlying authHash is revoked
  - calls pull adapter and emits RebalanceExecuted

### RIP-005 (FlowChannelHardened)
- Accrual math:
  - accrues `ratePerSecond * dt`, capped at `maxBalance`
  - stops accruing when paused or revoked
- `pull()`:
  - only grantee can call
  - cannot exceed `accrued`
  - respects pause / revoke
  - calls PolicyEnforcer if set
- Admin controls:
  - pause/resume only by grantor
  - revoke only by grantor
  - updateRate only by grantor

### RIP-007 (PolicyEnforcer + UniversalClock)
- Epoch roll:
  - when epoch advances, per-epoch spend counter resets
- `checkAndConsume`:
  - rejects if:
    - caller != grantee
    - amount > maxPerPull
    - amount would push spentThisEpoch > maxPerEpoch
    - receiver not in allowlist (if enforced)
    - policy is revoked
- Receiver allowlist mutation (setReceiverAllowed) only callable by grantor

### RIP-008 (SettlementMesh + AdaptiveRouter)
- reportBalances:
  - only controller can call
  - updates reportedBalance and reportedTotal
- rebalanceTick:
  - finds most underweight destination (vs targetBps)
  - does nothing if system is already in balance
  - calls router.routeStep(bestDest, step) where `step = min(deficit, maxStepAmount)`
  - emits MeshStep(dest, deficit, step)
- controller rotation restricted to onlyController

## Foundry notes

You can scaffold a Foundry project in `tests/` like:

~~~bash
forge init recur-tests
forge install foundry-rs/forge-std
~~~

Then write focused specs, e.g.:

- `RecurPullSafeV2.t.sol`
- `RecurConsentRegistry.t.sol`
- `FlowIntentRegistry.t.sol`
- `CrossNetworkRebalancer.t.sol`
- `FlowChannelHardened.t.sol`
- `PolicyEnforcer.t.sol`
- `SettlementMesh.t.sol`

## Contribution

The standard is frozen at v1.0.  
Community PRs adding full Foundry tests, fuzz cases (timestamps, cap edges, revoke race), and invariant tests for accrual logic are welcome.
