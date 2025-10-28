// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @dev controller is expected to be the same Safe/multisig that operates
///      DomainDirectory, so that one ops key can halt routing end-to-end.
/// @title AdaptiveRouter — RIP-006 reference router
/// @notice Chooses which FlowChannelHardened channel to drain in order to
///         push the system toward a target liquidity distribution.
/// @dev
/// - This contract NEVER takes custody. It only instructs FlowChannelHardened
///   instances to transfer directly from the grantor -> destination.
/// - `controller` (typically a Safe / multisig / SettlementMesh governor)
///   controls routing policy and calls routeStep().
/// - Channels are registered with a weight. The highest-weight active
///   channel is chosen greedily each step.
///
/// SECURITY MODEL
/// - FlowChannelHardened MUST enforce pause/revoke/policy. AdaptiveRouter assumes
///   pull() will revert if the channel is paused, revoked, rate-limited,
///   or otherwise out-of-policy.
/// - claimable(channelId) is treated as "currently safe to route". The router
///   trusts that value and does not re-check limits itself.
/// - Router never escrows funds. Movement is always grantor -> `to`.
///
/// This contract is intentionally thin. It's a coordinator, not a bank.
interface IFlowChannelHardened {
    /// @notice Pull `amount` of already-accrued funds out of channel `id` to `to`.
    /// @dev MUST revert internally if channel is paused, revoked, over policy, etc.
    function pull(bytes32 id, address to, uint256 amount) external;

    /// @notice How much is currently claimable for channel `id`.
    /// @dev MUST NOT over-report. Router trusts this number to be conservative and
    ///      already reflect pause/revoke/policy state in FlowChannelHardened.
    function claimable(bytes32 id) external view returns (uint256);
}

contract AdaptiveRouter {
    /// -----------------------------------------------------------------------
    /// Data
    /// -----------------------------------------------------------------------

    struct RouteTarget {
        bytes32 channelId; // channel handle understood by FlowChannelHardened
        uint256 weight;    // routing priority (higher = drain first / prefer)
        bool active;       // if false, router ignores this channel
    }

    /// @notice Privileged authority (Safe / multisig / governance).
    address public controller;

    /// @notice FlowChannelHardened executor this router orchestrates.
    IFlowChannelHardened public flow;

    /// @notice List of all known channelIds (for iteration / inspection).
    bytes32[] public channelList;

    /// @notice channelId => metadata.
    mapping(bytes32 => RouteTarget) public targetFor;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    /// @notice Fired when controller rotates to a new address.
    event ControllerUpdated(address indexed newController);

    /// @notice Fired when a channel is first registered with the router.
    event ChannelRegistered(bytes32 indexed channelId, uint256 weight);

    /// @notice Fired when routing metadata for a channel changes.
    event ChannelUpdated(bytes32 indexed channelId, uint256 weight, bool active);

    /// @notice Fired every time the router attempts to move liquidity from a
    ///         channel into `to`. If `amount` is zero, nothing was actually
    ///         pulled (e.g. claimable() was zero or below maxDesired),
    ///         but we still emit for telemetry / mesh accounting.
    event Routed(bytes32 indexed channelId, address to, uint256 amount);

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    modifier onlyController() {
        require(msg.sender == controller, "NOT_CONTROLLER");
        _;
    }

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @param flowChannelAddress Address of the FlowChannelHardened executor
    ///        this router will coordinate.
    /// @param initialController Privileged authority (Safe / multisig).
    /// @dev
    /// - `flowChannelAddress` must be a contract that enforces pause/revoke/policy
    ///   and guarantees non-custodial transfer from grantor -> receiver.
    /// - `initialController` is allowed to register channels and call routeStep().
    constructor(address flowChannelAddress, address initialController) {
        require(flowChannelAddress != address(0), "BAD_FLOW");
        require(initialController != address(0), "BAD_CTRL");

        flow = IFlowChannelHardened(flowChannelAddress);
        controller = initialController;
    }

    /// @notice Rotate controller authority (e.g. change multisig).
    function setController(address newController) external onlyController {
        require(newController != address(0), "BAD_CTRL");
        controller = newController;
        emit ControllerUpdated(newController);
    }

    /// -----------------------------------------------------------------------
    /// Admin: channel management
    /// -----------------------------------------------------------------------

    /// @notice Register a new channel into routing consideration.
    /// @param channelId Opaque channel identifier understood by FlowChannelHardened.
    /// @param weight Higher weight means this channel is preferred in routing.
    /// @dev Reverts if channel already exists.
    function registerChannel(bytes32 channelId, uint256 weight)
        external
        onlyController
    {
        require(channelId != bytes32(0), "BAD_ID");
        require(targetFor[channelId].channelId == bytes32(0), "EXISTS");

        channelList.push(channelId);

        targetFor[channelId] = RouteTarget({
            channelId: channelId,
            weight:    weight,
            active:    true
        });

        emit ChannelRegistered(channelId, weight);
    }

    /// @notice Update routing metadata for an existing channel.
    /// @param channelId Channel identifier.
    /// @param weight New routing weight.
    /// @param active New active flag.
    function updateChannel(bytes32 channelId, uint256 weight, bool active)
        external
        onlyController
    {
        require(targetFor[channelId].channelId != bytes32(0), "NO_CHANNEL");

        targetFor[channelId].weight = weight;
        targetFor[channelId].active = active;

        emit ChannelUpdated(channelId, weight, active);
    }

    /// -----------------------------------------------------------------------
    /// Routing
    /// -----------------------------------------------------------------------

    /// @notice Attempt to route liquidity from the highest-weight active channel.
    /// @param to The destination address that should receive funds. Must not be zero.
    /// @param maxDesired Upper bound of how much we want to move this step.
    /// @dev
    /// GREEDY STRATEGY (INTENTIONAL):
    /// - We scan all registered channels and pick the active one with the
    ///   highest `weight`. That channel encodes treasury / compliance priority
    ///   (e.g. "use regulated treasury first, then exchange hot wallet, then cold").
    /// - We DO NOT try to split across multiple channels in a single call.
    ///   That keeps routing deterministic, auditable, and easy to halt.
    ///
    /// FLOW:
    /// - Pick highest-weight active channel.
    /// - Ask that channel how much is currently claimable() (which MUST already
    ///   respect pause/revoke/policy in FlowChannelHardened).
    /// - Pull up to min(claimable, maxDesired) from that single source.
    ///
    /// GOVERNANCE LOOP:
    /// - SettlementMesh (RIP-008) calls routeStep() repeatedly while updating
    ///   weights / actives between calls. That higher layer is responsible for
    ///   global allocation math and fairness across channels and destinations.
    ///
    /// SAFETY:
    /// - Router never escrows funds; FlowChannelHardened moves grantor -> `to`.
    /// - If FlowChannelHardened.pull() reverts (policy block, paused, etc.),
    ///   this whole call reverts and no fallback channel is attempted. That
    ///   "loud fail" is deliberate so governance sees the restriction signal
    ///   instead of silently draining a lower-priority source.
    function routeStep(address to, uint256 maxDesired)
        external
        onlyController
    {
        require(to != address(0), "BAD_TO");

        // Pick highest-weight active channel.
        bytes32 best;
        uint256 bestW;

        uint256 len = channelList.length;
        for (uint256 i = 0; i < len; i++) {
            bytes32 cid = channelList[i];
            RouteTarget memory rt = targetFor[cid];
            if (!rt.active) continue;
            if (rt.weight > bestW) {
                bestW = rt.weight;
                best = cid;
            }
        }

        require(best != bytes32(0), "NO_ACTIVE_ROUTE");

        // Ask that channel how much is currently safe to pull.
        uint256 c = flow.claimable(best);

        // Bound by caller's requested maxDesired.
        uint256 amt = c;
        if (amt > maxDesired) {
            amt = maxDesired;
        }

        // Non-custodial move: channel pulls grantor -> `to`.
        // If amt == 0, we skip pull() but still emit Routed(best, to, 0)
        // so Mesh can audit "attempted rebalance; nothing available".
        if (amt > 0) {
            flow.pull(best, to, amt);
        }

        emit Routed(best, to, amt);
    }

    /// -----------------------------------------------------------------------
    /// View helpers
    /// -----------------------------------------------------------------------

    /// @notice Returns all known channelIds for off-chain iterators / dashboards.
    function getChannels() external view returns (bytes32[] memory) {
        return channelList;
    }
}
