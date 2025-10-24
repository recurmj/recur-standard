// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurConsentRegistry
/// @notice Minimal consent / revocation index for permissioned-pull (RIP-001).
/// @dev Matches RIP-002: tracks whether an authHash is still valid and emits canonical events.
///      This contract does NOT move funds. It is the on-chain source of truth for
///      "does this consent still exist, or has it been revoked?"
contract RecurConsentRegistry {
    // authHash => revoked?
    mapping(bytes32 => bool) public revoked;

    // authHash => cumulative amount pulled so far (for accounting / analytics)
    mapping(bytes32 => uint256) public totalPulled;

    // OPTIONAL: track a soft cap for UI/compliance (not enforced here)
    mapping(bytes32 => uint256) public capOfAuth;

    event PullExecuted(
        bytes32 indexed authHash,
        address indexed token,
        address indexed grantor,
        address grantee,
        uint256 amount,
        uint256 cumulative
    );

    event AuthorizationRevoked(
        bytes32 indexed authHash,
        address indexed grantor,
        uint256 timestamp
    );

    event AuthorizationBudgetUpdated(
        bytes32 indexed authHash,
        uint256 oldCap,
        uint256 newCap
    );

    event AuthorizationObserved(
        bytes32 indexed authHash,
        address indexed grantor,
        address indexed grantee,
        address token
    );

    /// @notice Grantor revokes consent for this authHash.
    /// @dev After this, any compliant pull() MUST revert for this authHash.
    function revoke(bytes32 authHash) external {
        revoked[authHash] = true;
        emit AuthorizationRevoked(authHash, msg.sender, block.timestamp);
    }

    /// @notice Optional discovery hook so UIs can list "this consent exists"
    ///         without revealing full terms. Gated in production.
    function observe(
        bytes32 authHash,
        address grantor,
        address grantee,
        address token
    ) external {
        emit AuthorizationObserved(authHash, grantor, grantee, token);
    }

    /// @notice Record a successful pull for accounting / analytics.
    /// @dev Called by the pull executor after transfer succeeds.
        // Emits PullExecuted with cumulative total.
    function recordPull(
        bytes32 authHash,
        address token,
        address grantor,
        address grantee,
        uint256 amount
    ) external {
        uint256 newTotal = totalPulled[authHash] + amount;
        totalPulled[authHash] = newTotal;

        emit PullExecuted(
            authHash,
            token,
            grantor,
            grantee,
            amount,
            newTotal
        );
    }

    /// @notice Optional soft cap (not enforced here).
    /// @dev In hardened version you'd restrict this to the grantor.
    function setCap(
        bytes32 authHash,
        uint256 oldCap,
        uint256 newCap
    ) external {
        capOfAuth[authHash] = newCap;
        emit AuthorizationBudgetUpdated(authHash, oldCap, newCap);
    }

    /// @notice True if this authHash has been revoked by its grantor.
    function isRevoked(bytes32 authHash) external view returns (bool) {
        return revoked[authHash];
    }

    /// @notice How much has been pulled under this authHash so far.
    function pulledTotal(bytes32 authHash) external view returns (uint256) {
        return totalPulled[authHash];
    }

    /// @notice Optional helper for UI/analytics.
    function capOf(bytes32 authHash) external view returns (uint256) {
        return capOfAuth[authHash];
    }
}
