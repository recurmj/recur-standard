// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title PolicyEnforcer — RIP-007 hardened reference (clock-synced)
/// @notice Enforces spend ceilings, per-epoch budgets, and receiver allowlists.
/// @dev
/// This contract never moves tokens. It is called by spend executors
/// (e.g. FlowChannelHardened.pull(), AdaptiveRouter, SettlementMesh)
/// BEFORE value is released. If any rule fails, we revert.
///
/// Major guarantees:
/// - Grantor can revoke the policy at any time.
/// - Grantee can't exceed maxPerPull in a single draw.
/// - Grantee can't exceed maxPerEpoch across the current epoch.
/// - (Optional) Destination `to` must be on an allowlist.
/// - Epoch boundaries are defined by a shared UniversalClock (RIP-006),
///   so "per epoch" means the same thing for every channel on this chain.
///
/// IMPORTANT:
/// - We assume the caller (FlowChannelHardened, router, etc.) enforces that
///   the *actual token movement* matches (grantor, grantee, token) described
///   in the Channel. This contract only checks limits/receivers/budgets.
/// - We assume SettlementMesh / AdaptiveRouter only calls spend paths on
///   policies that belong to the relevant treasury / grantor.
///
/// NOTE:
/// - We do NOT attempt to rate-limit *who* may call checkAndConsume() beyond
///   verifying `caller == policy.grantee`. If you want only specific executors
///   (e.g. a known FlowChannelHardened instance) to ever hit this policy,
///   you can add an `authorizedExecutor` field and require(msg.sender == that).
///   We leave that out to keep the reference minimal.
interface IUniversalClock {
    /// @notice Returns the canonical epoch index for this chain / domain.
    /// @dev Must be monotonic, non-decreasing, and only tick forward.
    function currentEpoch() external view returns (uint64);
}

contract PolicyEnforcer {
    /// -----------------------------------------------------------------------
    /// Storage
    /// -----------------------------------------------------------------------

    struct Policy {
        address grantor;          // who ultimately controls the spend
        address grantee;          // who is allowed to initiate spends
        address token;            // asset governed by this policy

        uint256 maxPerPull;       // ceiling for a single transfer
        uint256 maxPerEpoch;      // ceiling for total spending in a given epoch

        bool hasReceiverRules;    // if true, enforce receiver allowlist
        mapping(address => bool) allowedReceivers;

        uint64  currentEpoch;     // epoch this accounting bucket refers to
        uint256 spentThisEpoch;   // how much has been consumed in currentEpoch

        bool revoked;             // true => policy inert, all spends blocked
    }

    /// policyId (bytes32) => Policy
    mapping(bytes32 => Policy) internal policies;

    /// Global epoch source (RIP-006 UniversalClock).
    /// All policies share this timing source so "epoch" is consistent.
    IUniversalClock public immutable clock;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event PolicyCreated(
        bytes32 indexed policyId,
        address indexed grantor,
        address indexed grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch
    );

    event ReceiverAllowed(bytes32 indexed policyId, address receiver, bool allowed);

    event PolicyRevoked(bytes32 indexed policyId, address indexed grantor);

    /// @notice Emitted every time budget is consumed.
    /// @param policyId   Which policy enforced
    /// @param epochId    Epoch in which we accounted this spend
    /// @param amount     Amount just approved
    /// @param newEpochTotal  Spent so far this epoch AFTER this approval
    event PolicySpend(
        bytes32 indexed policyId,
        uint64 indexed epochId,
        uint256 amount,
        uint256 newEpochTotal
    );

    /// -----------------------------------------------------------------------
    /// Simple nonReentrancy guard (kept very lean)
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
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @param clockAddr Address of the UniversalClock (RIP-006) for this domain.
    ///        All policies enforced by this contract will use that shared epoch cadence.
    constructor(address clockAddr) {
        require(clockAddr != address(0), "BAD_CLOCK");
        clock = IUniversalClock(clockAddr);
    }

    /// -----------------------------------------------------------------------
    /// Policy lifecycle
    /// -----------------------------------------------------------------------

    /// @notice Create a new policy config for a grantee/token pair.
    /// @param policyId     Chosen ID (must be unique).
    /// @param grantee      Address allowed to spend under this policy (e.g. router / executor).
    /// @param token        Asset this policy governs.
    /// @param maxPerPull   Hard ceiling for a single spend call.
    /// @param maxPerEpoch  Hard ceiling for total spending across one epoch.
    ///
    /// Requirements:
    /// - policyId must not already exist.
    /// - grantee and token must be nonzero.
    /// - maxPerPull <= maxPerEpoch (sanity).
    /// - The epoch bucket is initialized to whatever clock.currentEpoch() is now.
    function createPolicy(
        bytes32 policyId,
        address grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch
    ) external nonReentrant {
        Policy storage p = policies[policyId];
        require(p.grantor == address(0), "EXISTS");
        require(grantee != address(0) && token != address(0), "BAD_ADDR");
        require(maxPerPull > 0 && maxPerEpoch > 0, "ZERO_LIMIT");
        require(maxPerPull <= maxPerEpoch, "BAD_LIMITS");

        p.grantor = msg.sender;
        p.grantee = grantee;
        p.token = token;
        p.maxPerPull = maxPerPull;
        p.maxPerEpoch = maxPerEpoch;

        uint64 nowEpoch = clock.currentEpoch();
        p.currentEpoch = nowEpoch;
        p.spentThisEpoch = 0;
        p.revoked = false;
        // hasReceiverRules defaults to false

        emit PolicyCreated(
            policyId,
            msg.sender,
            grantee,
            token,
            maxPerPull,
            maxPerEpoch
        );
    }

    /// @notice Add or remove a permitted receiver for this policy.
    /// @dev Enables "only pay into these safes / desks / venues".
    function setReceiverAllowed(
        bytes32 policyId,
        address receiver,
        bool allowed
    ) external onlyGrantor(policyId) nonReentrant {
        require(receiver != address(0), "BAD_RECEIVER");

        Policy storage p = policies[policyId];
        p.allowedReceivers[receiver] = allowed;
        p.hasReceiverRules = true;

        emit ReceiverAllowed(policyId, receiver, allowed);
    }

    /// @notice Permanently (or temporarily) kill a policy.
    /// @dev After revoke, checkAndConsume() will revert for this policyId.
    function revokePolicy(bytes32 policyId)
        external
        onlyGrantor(policyId)
        nonReentrant
    {
        policies[policyId].revoked = true;
        emit PolicyRevoked(policyId, msg.sender);
    }

    /// -----------------------------------------------------------------------
    /// Enforcement entrypoint (called by FlowChannelHardened / routers)
    /// -----------------------------------------------------------------------

    /// @notice Check spend limits + receiver rules and consume epoch budget if allowed.
    /// @dev
    /// This MUST be called by the executor *before* it actually does transferFrom().
    ///
    /// @param policyId Policy we’re enforcing.
    /// @param caller   The address initiating the spend at the channel level
    ///                 (should match Policy.grantee).
    /// @param to       Final receiver of funds.
    /// @param amount   Amount about to be sent.
    ///
    /// Reverts if:
    /// - policy is revoked,
    /// - caller != grantee,
    /// - amount > maxPerPull,
    /// - amount would push this epoch over maxPerEpoch,
    /// - receiver is not allowlisted (if allowlist enforced).
    ///
    /// On success:
    /// - updates spentThisEpoch,
    /// - emits PolicySpend.
    function checkAndConsume(
        bytes32 policyId,
        address caller,
        address to,
        uint256 amount
    ) external nonReentrant {
        Policy storage p = policies[policyId];

        require(!p.revoked, "POLICY_REVOKED");
        require(caller == p.grantee, "UNAUTHORIZED_GRANTEE");
        require(amount > 0, "AMOUNT_0");
        require(amount <= p.maxPerPull, "EXCEEDS_PULL");

        // sync epoch bucket to global clock
        uint64 nowEpoch = clock.currentEpoch();
        if (nowEpoch != p.currentEpoch) {
            p.currentEpoch = nowEpoch;
            p.spentThisEpoch = 0;
        }

        require(
            p.spentThisEpoch + amount <= p.maxPerEpoch,
            "EXCEEDS_EPOCH"
        );

        if (p.hasReceiverRules) {
            require(p.allowedReceivers[to], "RECEIVER_FORBIDDEN");
        }

        p.spentThisEpoch += amount;

        emit PolicySpend(
            policyId,
            nowEpoch,
            amount,
            p.spentThisEpoch
        );
    }

    /// -----------------------------------------------------------------------
    /// Views
    /// -----------------------------------------------------------------------

    /// @notice Read the public, auditor-facing view of this policy.
    /// @dev We cannot directly expose the receiver allowlist mapping (dynamic),
    ///      but we tell callers whether receiver rules are active.
    function viewPolicy(bytes32 policyId) external view returns (
        address grantor,
        address grantee,
        address token,
        uint256 maxPerPull,
        uint256 maxPerEpoch,
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
            p.currentEpoch,
            p.spentThisEpoch,
            p.revoked,
            p.hasReceiverRules
        );
    }

    /// @notice Convenience view for frontends / auditors to ask:
    ///         "Is X an approved receiver for this policy?"
    function isReceiverAllowed(bytes32 policyId, address receiver)
        external
        view
        returns (bool)
    {
        return policies[policyId].allowedReceivers[receiver];
    }
}
