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


## Foundry notes

You can scaffold a Foundry project in `tests/` like:

~~~bash
forge init recur-tests
forge install foundry-rs/forge-std
~~~

Then write focused specs, e.g.:

- `RecurPullSafeV2.t.sol`
- `RecurConsentRegistry.t.sol`

## Contribution

The standard is frozen at v1.1.  
Community PRs adding full Foundry tests, fuzz cases (timestamps, cap edges, revoke race), and invariant tests for accrual logic are welcome.
