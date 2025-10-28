// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title PolicyEnforcer — RIP-007 hardened reference (final)
/// @notice Enforces spend ceilings, per-epoch budgets, and receiver allowlists
/// @dev Sits in front of FlowChannelHardened.pull() or routers.
///      Pure accounting layer; never holds tokens.
contract PolicyEnforcer {
    struct Policy {
        address grantor;
        address grantee;
        address token;

        uint256 maxPerPull;     // ceiling for a single transfer
        uint256 maxPerEpoch;    // ceiling for an epoch window
        uint256 epochLength;    // seconds per epoch bucket

        bool hasReceiverRules;
        mapping(address => bool) allowedReceivers;

        uint64  currentEpoch;
        uint256 spentThisEpoch;
        bool revoked;
    }

    mapping(bytes32 => Policy) internal policies;

    event PolicyCreated(
        bytes32 indexed policyId,
        address indexed grantor,
        address indexed grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch,
        uint256 epochLength
    );

    event ReceiverAllowed(bytes32 indexed policyId, address receiver, bool allowed);
    event PolicyRevoked(bytes32 indexed policyId, address indexed grantor);
    event PolicySpend(
        bytes32 indexed policyId,
        uint64 indexed epochId,
        uint256 amount,
        uint256 newEpochTotal
    );

    /// -----------------------------------------------------------------------
    /// Simple local reentrancy guard
    /// -----------------------------------------------------------------------
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "REENTRANCY");
        _status = 2;
        _;
        _status = 1;
    }

    modifier onlyGrantor(bytes32 policyId) {
        require(msg.sender == policies[policyId].grantor, "NOT_GRANTOR");
        _;
    }

    /// -----------------------------------------------------------------------
    /// Policy lifecycle
    /// -----------------------------------------------------------------------

    function createPolicy(
        bytes32 policyId,
        address grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch,
        uint256 epochLength
    ) external nonReentrant {
        Policy storage p = policies[policyId];
        require(p.grantor == address(0), "EXISTS");
        require(grantee != address(0) && token != address(0), "BAD_ADDR");
        require(epochLength > 0, "EPOCH=0");
        require(maxPerPull <= maxPerEpoch, "BAD_LIMITS");

        p.grantor = msg.sender;
        p.grantee = grantee;
        p.token = token;
        p.maxPerPull = maxPerPull;
        p.maxPerEpoch = maxPerEpoch;
        p.epochLength = epochLength;
        p.currentEpoch = _epochIndex(epochLength);

        emit PolicyCreated(policyId, msg.sender, grantee, token, maxPerPull, maxPerEpoch, epochLength);
    }

    function setReceiverAllowed(
        bytes32 policyId,
        address receiver,
        bool allowed
    ) external onlyGrantor(policyId) nonReentrant {
        Policy storage p = policies[policyId];
        p.allowedReceivers[receiver] = allowed;
        p.hasReceiverRules = true;
        emit ReceiverAllowed(policyId, receiver, allowed);
    }

    function revokePolicy(bytes32 policyId) external onlyGrantor(policyId) nonReentrant {
        policies[policyId].revoked = true;
        emit PolicyRevoked(policyId, msg.sender);
    }

    /// -----------------------------------------------------------------------
    /// Enforcement entrypoint (called by FlowChannelHardened / routers)
    /// -----------------------------------------------------------------------

    /// @notice Called before releasing funds; reverts if violation.
    /// @dev Consumes epoch budget if successful.
    function checkAndConsume(
        bytes32 policyId,
        address caller,
        address to,
        uint256 amount
    ) external nonReentrant {
        Policy storage p = policies[policyId];

        require(!p.revoked, "POLICY_REVOKED");
        require(caller == p.grantee, "UNAUTHORIZED_GRANTEE");
        require(amount <= p.maxPerPull, "EXCEEDS_PULL");

        // roll epoch if window has advanced
        uint64 nowEpoch = _epochIndex(p.epochLength);
        if (nowEpoch != p.currentEpoch) {
            p.currentEpoch = nowEpoch;
            p.spentThisEpoch = 0;
        }

        require(p.spentThisEpoch + amount <= p.maxPerEpoch, "EXCEEDS_EPOCH");

        if (p.hasReceiverRules) {
            require(p.allowedReceivers[to], "RECEIVER_FORBIDDEN");
        }

        p.spentThisEpoch += amount;

        emit PolicySpend(policyId, nowEpoch, amount, p.spentThisEpoch);
    }

    /// -----------------------------------------------------------------------
    /// Views
    /// -----------------------------------------------------------------------

    function viewPolicy(bytes32 policyId) external view returns (
        address grantor,
        address grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch,
        uint256 epochLength,
        uint64 currentEpoch,
        uint256 spentThisEpoch,
        bool revoked,
        bool hasReceiverRules
    ) {
        Policy storage p = policies[policyId];
        return (
            p.grantor,
            p.grantee,
            p.token,
            p.maxPerPull,
            p.maxPerEpoch,
            p.epochLength,
            p.currentEpoch,
            p.spentThisEpoch,
            p.revoked,
            p.hasReceiverRules
        );
    }

    function isReceiverAllowed(bytes32 policyId, address receiver) external view returns (bool) {
        return policies[policyId].allowedReceivers[receiver];
    }

    function _epochIndex(uint256 epochLength) internal view returns (uint64) {
        return uint64(block.timestamp / epochLength);
    }
}
