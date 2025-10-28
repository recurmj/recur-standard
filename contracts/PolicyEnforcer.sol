// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title PolicyEnforcer — RIP-007 hardened reference (final)
/// @notice Enforces spend ceilings, per-epoch budgets, and receiver allowlists.
/// @dev This contract is meant to sit in front of FlowChannelHardened.pull()
/// or any router that moves funds on behalf of an institution/CFO/treasury.
contract PolicyEnforcer {
    struct Policy {
        address grantor;
        address grantee;
        address token;

        uint256 maxPerPull;     // ceiling for a single transfer
        uint256 maxPerEpoch;    // ceiling for a rolling epoch window
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

    // emitted every time budget is consumed
    event PolicySpend(
        bytes32 indexed policyId,
        uint64 indexed epochId,
        uint256 amount,
        uint256 newEpochTotal
    );

    modifier onlyGrantor(bytes32 policyId) {
        require(msg.sender == policies[policyId].grantor, "not grantor");
        _;
    }

    function createPolicy(
        bytes32 policyId,
        address grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch,
        uint256 epochLength
    ) external {
        Policy storage p = policies[policyId];
        require(p.grantor == address(0), "exists");
        require(grantee != address(0), "bad grantee");
        require(token != address(0), "bad token");
        require(epochLength > 0, "epoch=0");

        p.grantor = msg.sender;
        p.grantee = grantee;
        p.token = token;
        p.maxPerPull = maxPerPull;
        p.maxPerEpoch = maxPerEpoch;
        p.epochLength = epochLength;
        p.currentEpoch = _epochIndex(p.epochLength);
        p.spentThisEpoch = 0;
        p.revoked = false;
        p.hasReceiverRules = false;

        emit PolicyCreated(policyId, msg.sender, grantee, token, maxPerPull, maxPerEpoch, epochLength);
    }

    function setReceiverAllowed(bytes32 policyId, address receiver, bool allowed) external onlyGrantor(policyId) {
        Policy storage p = policies[policyId];
        p.allowedReceivers[receiver] = allowed;
        p.hasReceiverRules = true;
        emit ReceiverAllowed(policyId, receiver, allowed);
    }

    function revokePolicy(bytes32 policyId) external onlyGrantor(policyId) {
        policies[policyId].revoked = true;
        emit PolicyRevoked(policyId, msg.sender);
    }

    /// @notice Called by FlowChannelHardened (or router) before releasing funds.
    /// Consumes budget if allowed.
    function checkAndConsume(bytes32 policyId, address caller, address to, uint256 amount) external {
        Policy storage p = policies[policyId];

        require(!p.revoked, "policy revoked");
        require(caller == p.grantee, "unauthorized grantee");
        require(amount <= p.maxPerPull, "exceeds maxPerPull");

        // roll epoch window if needed
        uint64 nowEpoch = _epochIndex(p.epochLength);
        if (nowEpoch != p.currentEpoch) {
            p.currentEpoch = nowEpoch;
            p.spentThisEpoch = 0;
        }

        require(p.spentThisEpoch + amount <= p.maxPerEpoch, "exceeds epoch cap");

        if (p.hasReceiverRules) {
            require(p.allowedReceivers[to], "receiver not allowed");
        }

        p.spentThisEpoch += amount;

        emit PolicySpend(policyId, nowEpoch, amount, p.spentThisEpoch);
    }

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

    function _epochIndex(uint256 epochLength) internal view returns (uint64) {
        return uint64(block.timestamp / epochLength);
    }
}