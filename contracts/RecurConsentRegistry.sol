// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurConsentRegistry
/// @notice RIP-002 Consent / Revocation Registry for permissioned-pull (RIP-001).
///
/// @dev
/// This contract is the canonical index for:
///   - whether a given Permissioned Pull Object (PPO / Authorization) is still valid,
///   - how much value has actually been pulled under it so far,
///   - optional soft caps / budgets for reporting,
///   - canonical events that wallets / auditors / explorers can consume.
///
/// IMPORTANT:
/// - This contract never moves funds.
/// - This contract does not enforce spend caps by itself.
/// - Execution contracts (RecurPullSafeV2, FlowChannelHardened, CrossNetworkRebalancer, etc.)
///   MUST consult this registry *before* honoring a pull, and MUST call recordPull()
///   *after* a successful transferFrom().
///
/// SECURITY MODEL:
/// - We bind each `authHash` to an `owner` (the grantor) the first time we ever
///   see a real pull recorded for that authHash. After that, ONLY that owner
///   can revoke() future use of the authHash.
/// - Until an authHash has been used (no pulls recorded yet), no owner is set,
///   so revoke() will fail (UNKNOWN_AUTH). That prevents randoms from
///   pre-revoking someone else's unsigned intent before first use.
///
/// - In hardened deployments you should ALSO restrict recordPull() so only
///   trusted executors (your RecurPullSafeV2, routers, etc.) can call it.
///   That prevents griefing where an attacker spoof-calls recordPull() with
///   fake data to "claim ownership" of an authHash. In this reference
///   implementation we leave recordPull() open for clarity, but call this
///   out explicitly.
contract RecurConsentRegistry {
    /// -----------------------------------------------------------------------
    /// Storage
    /// -----------------------------------------------------------------------

    // authHash => has this Authorization been revoked?
    mapping(bytes32 => bool) public revoked;

    // authHash => cumulative amount pulled so far (accounting / audit trail)
    mapping(bytes32 => uint256) public totalPulled;

    // OPTIONAL: advertised soft cap / budget for UI & compliance dashboards.
    // This is not enforced here.
    mapping(bytes32 => uint256) public capOfAuth;

    // authHash => canonical grantor (the party who gave consent)
    //
    // We set this once, the FIRST time recordPull() is called for that authHash.
    // After set, only this address may revoke().
    mapping(bytes32 => address) public ownerOfAuth;

    /// -----------------------------------------------------------------------
    /// Events (canonical RIP-002 surface)
    /// -----------------------------------------------------------------------

    /// @notice Emitted when a pull succeeds under a still-valid Authorization.
    /// @dev Indexers can reconstruct flow history and running totals per authHash.
    /// Topics:
    ///   authHash (idx 1), token (idx 2), grantor (idx 3)
    event PullExecuted(
        bytes32 indexed authHash,
        address indexed token,
        address indexed grantor,
        address grantee,
        uint256 amount,
        uint256 cumulative // totalPulled[authHash] after this pull
    );

    /// @notice Emitted when a grantor revokes an Authorization.
    /// @dev After this, compliant executors MUST refuse further pulls for this authHash.
    event AuthorizationRevoked(
        bytes32 indexed authHash,
        address indexed grantor,
        uint256 timestamp
    );

    /// @notice Emitted when a soft cap (budget) is set or updated.
    /// @dev Off-chain risk / compliance tooling can diff old/new.
    event AuthorizationBudgetUpdated(
        bytes32 indexed authHash,
        uint256 oldCap,
        uint256 newCap
    );

    /// @notice Optional discovery hook.
    /// @dev Lets UIs / explorers learn that "this consent exists between X and Y
    ///      for token T" without revealing full Authorization terms.
    ///      This event is ADVISORY ONLY and can be spoofed. Wallets/auditors
    ///      MUST NOT treat observe() as proof of real consent.
    event AuthorizationObserved(
        bytes32 indexed authHash,
        address indexed grantor,
        address indexed grantee,
        address token
    );

    /// -----------------------------------------------------------------------
    /// Write functions
    /// -----------------------------------------------------------------------

    /// @notice Grantor revokes consent for this authHash.
    /// @dev
    ///  - Only the bound grantor (ownerOfAuth[authHash]) may revoke.
    ///  - If the authHash has never been used (no recordPull() yet), there is
    ///    no ownerOfAuth[authHash] and this will revert with UNKNOWN_AUTH.
    ///  - After revocation, any compliant pull() MUST revert for this authHash.
    function revoke(bytes32 authHash) external {
        address owner = ownerOfAuth[authHash];
        require(owner != address(0), "UNKNOWN_AUTH");
        require(msg.sender == owner, "NOT_GRANTOR");

        revoked[authHash] = true;

        emit AuthorizationRevoked({
            authHash:  authHash,
            grantor:   msg.sender,
            timestamp: block.timestamp
        });
    }

    /// @notice Optional discovery hook so UIs / indexers can surface "this consent may exist".
    /// @dev
    ///  - ADVISORY ONLY. Anyone can call this. It's just a hint for explorers.
    ///  - Does NOT prove validity and does NOT set ownerOfAuth.
    ///  - Does NOT imply the grantee can currently pull.
    function observe(
        bytes32 authHash,
        address grantor,
        address grantee,
        address token
    ) external {
        emit AuthorizationObserved({
            authHash: authHash,
            grantor:  grantor,
            grantee:  grantee,
            token:    token
        });
    }

    /// @notice Record a successful pull for accounting / audit trail.
    /// @dev
    ///  - MUST be called only *after* the actual ERC-20 transferFrom()
    ///    (grantor -> grantee) has succeeded in the executor contract.
    ///  - In production, restrict msg.sender to trusted executors so nobody
    ///    can spoof usage or "steal" ownerOfAuth binding.
    ///
    /// Effects:
    ///  - Increments totalPulled[authHash].
    ///  - If this is the first-ever record for `authHash`, binds that hash to
    ///    `grantor` in ownerOfAuth[authHash]. From that point on, ONLY that
    ///    grantor can revoke().
    ///
    /// Emits PullExecuted(authHash, token, grantor, grantee, amount, cumulative).
    function recordPull(
        bytes32 authHash,
        address token,
        address grantor,
        address grantee,
        uint256 amount
    ) external {
        // Bind the canonical owner (grantor) on first use.
        if (ownerOfAuth[authHash] == address(0)) {
            ownerOfAuth[authHash] = grantor;
        }

        uint256 newTotal = totalPulled[authHash] + amount;
        totalPulled[authHash] = newTotal;

        emit PullExecuted({
            authHash:   authHash,
            token:      token,
            grantor:    grantor,
            grantee:    grantee,
            amount:     amount,
            cumulative: newTotal
        });
    }

    /// @notice Set or update an advertised budget / soft cap for analytics & UI.
    /// @dev
    ///  - NOT enforced here.
    ///  - Only the canonical grantor (ownerOfAuth[authHash]) can set / update.
    ///  - Downstream systems can use this as "declared exposure ceiling."
    ///
    /// Emits AuthorizationBudgetUpdated(authHash, oldCap, newCap).
    function setCap(bytes32 authHash, uint256 newCap) external {
        address owner = ownerOfAuth[authHash];
        require(owner != address(0), "UNKNOWN_AUTH");
        require(msg.sender == owner, "NOT_GRANTOR");

        uint256 oldCap = capOfAuth[authHash];
        capOfAuth[authHash] = newCap;

        emit AuthorizationBudgetUpdated({
            authHash: authHash,
            oldCap:   oldCap,
            newCap:   newCap
        });
    }

    /// -----------------------------------------------------------------------
    /// Read functions
    /// -----------------------------------------------------------------------

    /// @notice True if this authHash has been revoked.
    /// @dev Execution contracts MUST check this before honoring a pull.
    function isRevoked(bytes32 authHash) external view returns (bool) {
        return revoked[authHash];
    }

    /// @notice Total cumulative amount recorded as pulled under this authHash.
    /// @dev Indexers / auditors can use this for exposure reporting.
    function pulledTotal(bytes32 authHash) external view returns (uint256) {
        return totalPulled[authHash];
    }

    /// @notice Advisory soft cap / budget for this authHash (0 if unset).
    /// @dev Useful for dashboards, limits monitoring, compliance tooling.
    function capOf(bytes32 authHash) external view returns (uint256) {
        return capOfAuth[authHash];
    }

    /// @notice Which address currently controls this authHash's revocation rights.
    /// @dev Will be zero address until the first successful recordPull().
    function ownerOf(bytes32 authHash) external view returns (address) {
        return ownerOfAuth[authHash];
    }
}
