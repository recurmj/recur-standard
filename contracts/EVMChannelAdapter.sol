// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title EVMChannelAdapter — Domain adapter using FlowChannelHardened
/// @notice Source adapter for domains where the grantor has an active FlowChannelHardened.
/// @dev The adapter never takes custody. It just calls pull() on FlowChannelHardened with a preset channelId.
///
/// Model:
/// - For a given domain, we know:
///   * channelId in FlowChannelHardened that represents "grantor -> router" stream
///   * which FlowChannelHardened contract to hit
///
/// CrossNetworkRebalancer calls this adapter, passing (grantor, token, finalReceiver, amount).
/// We assert that the grantor matches what we expect for this channelId, etc.
/// Then we call channel.pull(channelId, finalReceiver, amount).
interface IFlowChannelHardenedPull {
    function pull(bytes32 id, address to, uint256 amount) external;
    function channels(bytes32 id) external view returns (
        address grantor,
        address grantee,
        address token,
        uint256 ratePerSecond,
        uint256 maxBalance,
        uint256 accrued,
        uint64  lastUpdate,
        bool paused,
        bool revoked,
        address policyEnforcer,
        bytes32 policyId
    );
}

contract EVMChannelAdapter {
    IFlowChannelHardenedPull public flow;
    bytes32 public channelId;

    constructor(address flowChannelAddress, bytes32 channelId_) {
        flow = IFlowChannelHardenedPull(flowChannelAddress);
        channelId = channelId_;
    }

    /// @notice Execute a consented pull from the channel to the finalReceiver.
    /// @dev grantor and token are checked against the channel's config for safety.
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
            ,
            ,
            ,
            ,
            bool paused,
            bool revoked,
            ,
            /*policyId*/
        ) = flow.channels(channelId);

        require(!paused && !revoked, "channel inactive");
        require(grantor == chGrantor, "grantor mismatch");
        require(token == chToken, "token mismatch");

        // msg.sender should be allowed executor in higher layer (CrossNetworkRebalancer enforces that)
        // we assume the channel.grantee is this adapter or CrossNetworkRebalancer, depending on how you deploy.
        // If you want to lock this, add:
        require(msg.sender == chGrantee, "not channel grantee");

        // pull will internally enforce accrued, policy caps, etc.
        flow.pull(channelId, finalReceiver, amount);
    }
}