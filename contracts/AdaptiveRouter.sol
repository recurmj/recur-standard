// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title AdaptiveRouter — RIP-006 hardened reference
/// @notice Policy-aware liquidity director that coordinates pulls from multiple FlowChannels.
interface IFlowChannelHardened {
    function pull(bytes32 id, address to, uint256 amount) external;
    function claimable(bytes32 id) external view returns (uint256);
}

contract AdaptiveRouter {
    struct RouteTarget {
        bytes32 channelId;
        uint256 weight;   // priority for draining
        bool active;
    }

    address public owner;
    IFlowChannelHardened public flow;
    bytes32[] public channelList;
    mapping(bytes32 => RouteTarget) public targetFor; // channelId => target info

    event ChannelRegistered(bytes32 indexed channelId, uint256 weight);
    event ChannelUpdated(bytes32 indexed channelId, uint256 weight, bool active);
    event Routed(bytes32 indexed channelId, address to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address flowChannelAddress) {
        owner = msg.sender;
        flow = IFlowChannelHardened(flowChannelAddress);
    }

    function registerChannel(bytes32 channelId, uint256 weight) external onlyOwner {
        require(targetFor[channelId].channelId == 0, "exists");
        channelList.push(channelId);
        targetFor[channelId] = RouteTarget({
            channelId: channelId,
            weight: weight,
            active: true
        });
        emit ChannelRegistered(channelId, weight);
    }

    function updateChannel(bytes32 channelId, uint256 weight, bool active) external onlyOwner {
        require(targetFor[channelId].channelId != 0, "no channel");
        targetFor[channelId].weight = weight;
        targetFor[channelId].active = active;
        emit ChannelUpdated(channelId, weight, active);
    }

    /// @notice Attempt to route `maxDesired` from the best available channel to `to`.
    /// @dev SettlementMesh drives this to push system toward target allocation.
    function routeStep(address to, uint256 maxDesired) external onlyOwner {
        bytes32 best;
        uint256 bestW;
        for (uint256 i = 0; i < channelList.length; i++) {
            bytes32 cid = channelList[i];
            RouteTarget memory rt = targetFor[cid];
            if (!rt.active) continue;
            if (rt.weight > bestW) {
                bestW = rt.weight;
                best = cid;
            }
        }
        require(best != 0, "no active route");

        uint256 c = flow.claimable(best);
        if (c == 0) return;

        uint256 amt = c;
        if (amt > maxDesired) amt = maxDesired;

        if (amt > 0) {
            flow.pull(best, to, amt);
            emit Routed(best, to, amt);
        }
    }
}