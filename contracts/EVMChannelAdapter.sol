// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title EVMChannelAdapter
/// @notice RIP-004 / RIP-008 domain adapter for EVM-style domains that expose
///         FlowChannelHardened. This adapter NEVER takes custody. It just
///         instructs a specific Flow Channel to pay a destination directly,
///         under the grantor's pre-existing consent.
/// @dev
/// Model:
/// - Each domain (e.g. "ethereum:treasury") maps to:
///     • a FlowChannelHardened contract
///     • a specific channelId inside that contract
///
/// - CrossNetworkRebalancer calls executeAuthorizedPull() on THIS adapter,
///   telling it:
///     (grantor, token, finalReceiver, amount)
///
/// - We verify:
///     • the channel is active (not paused / not revoked)
///     • the grantor matches the channel's recorded grantor
///     • the token matches the channel's recorded token
///     • msg.sender == channel.grantee (i.e. only the approved executor
///       for this channel can actually trigger the pull)
///
/// - Then we call channel.pull(channelId, finalReceiver, amount).
///
/// Security assumptions:
/// - FlowChannelHardened enforces ratePerSecond, maxBalance, policy, etc.
/// - The grantor can pause or revoke the channel at any time,
///   which instantly halts movement.
/// - This adapter is effectively a thin "permission gate" + forwarder.
interface IFlowChannelHardened {
    function pull(bytes32 id, address to, uint256 amount) external;

    function channels(bytes32 id) external view returns (
        address grantor,          // owner / source of funds
        address grantee,          // who is allowed to initiate pulls
        address token,            // ERC-20 asset flowing through the channel
        uint256 ratePerSecond,    // flow rate (accrual rate)
        uint256 maxBalance,       // cap on accrued buffer
        uint256 accrued,          // currently accrued amount
        uint64  lastUpdate,       // last accrual timestamp
        bool    paused,           // true => channel temporarily disabled
        bool    revoked,          // true => channel permanently disabled
        address policyEnforcer,   // optional on-chain policy contract (RIP-007)
        bytes32 policyId          // policy config reference (RIP-007)
    );
}

contract EVMChannelAdapter {
    /// @notice FlowChannelHardened contract that actually holds channel state,
    ///         accrues balances, enforces policy, and performs the pull().
    IFlowChannelHardened public flow;

    /// @notice The logical channel this adapter is allowed to route from.
    /// @dev This is set once at deployment for this adapter-domain pairing.
    bytes32 public channelId;

    /// @param flowChannelAddress Address of the FlowChannelHardened instance.
    /// @param channelId_         ID of the specific channel (grantor->stream) this adapter fronts.
    constructor(address flowChannelAddress, bytes32 channelId_) {
        flow = IFlowChannelHardened(flowChannelAddress);
        channelId = channelId_;
    }

    /// @notice Trigger a consented pull from the channel's grantor toward `finalReceiver`.
    /// @dev
    /// - `grantor` and `token` are provided by the caller (CrossNetworkRebalancer),
    ///   but we RE-VERIFY them directly against channel storage for safety.
    /// - We ALSO enforce that msg.sender == channel.grantee. This prevents
    ///   random addresses from abusing the adapter, and cleanly lets you
    ///   set channel.grantee = CrossNetworkRebalancer.
    ///
    /// - If the channel is paused or revoked, we revert.
    /// - If FlowChannelHardened.pull() internally reverts due to rate caps,
    ///   maxBalance, policy, etc., we bubble that up.
    ///
    /// @param grantor        The expected source-of-funds wallet for this channel.
    /// @param token          The ERC-20 asset we're expecting this channel to stream.
    /// @param finalReceiver  The destination that should receive funds right now.
    /// @param amount         How much we're trying to move in this step.
    function executeAuthorizedPull(
        address grantor,
        address token,
        address finalReceiver,
        uint256 amount
    ) external {
        (
            address chGrantor,
            address chGrantee,
            address chToken,
            /* uint256 ratePerSecond */,
            /* uint256 maxBalance */,
            /* uint256 accrued */,
            /* uint64  lastUpdate */,
            bool paused,
            bool revoked,
            /* address policyEnforcer */,
            /* bytes32 policyId */
        ) = flow.channels(channelId);

        require(!paused && !revoked, "CHANNEL_INACTIVE");
        require(grantor == chGrantor, "GRANTOR_MISMATCH");
        require(token   == chToken,   "TOKEN_MISMATCH");

        // Only the address recorded as channel.grantee is allowed to trigger this.
        // Typical pattern: channel.grantee = CrossNetworkRebalancer.
        require(msg.sender == chGrantee, "NOT_CHANNEL_GRANTEE");

        // This call moves funds directly from the channel's tracked grantor
        // to `finalReceiver`. This adapter never holds funds.
        flow.pull(channelId, finalReceiver, amount);
    }
}
