// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title AdaptiveRouter
/// @notice RIP-006 reference router. Selects which Flow Channel to draw from in order
///         to push the system toward its target liquidity distribution.
/// @dev
/// - This contract NEVER takes custody. It only instructs FlowChannelHardened
///   instances to pay directly from grantor -> destination.
/// - Owner (e.g. SettlementMesh governor / multisig) controls routing policy.
/// - Channels are registered with a weight. The highest-weight active channel
///   is chosen greedily in each routeStep().
///
/// Security model:
/// - The underlying FlowChannelHardened MUST enforce pause/revoke/policy.
///   AdaptiveRouter assumes that pull() will revert if the channel is paused,
///   revoked, rate-limited, or otherwise out-of-policy.
/// - claimable(channelId) is treated as "safe to route right now" and MUST NOT
///   over-report. Router trusts that value.
///
/// This contract is intentionally simple: it's a coordinator, not a bank.
interface IFlowChannelHardened {
    /// @notice Pull `amount` of already-accrued funds out of the channel `id` to `to`.
    /// @dev MUST revert internally if channel is paused, revoked, rate-limited, etc.
    function pull(bytes32 id, address to, uint256 amount) external;

    /// @notice View how much is currently claimable for channel `id`.
    /// @dev MUST NOT over-report. Router trusts this value.
    function claimable(bytes32 id) external view returns (uint256);
}

contract AdaptiveRouter {
    /// -----------------------------------------------------------------------
    /// Data
    /// -----------------------------------------------------------------------

    struct RouteTarget {
        bytes32 channelId; // logical channel handle used by FlowChannelHardened
        uint256 weight;    // routing priority (higher = drain first / prefer this channel)
        bool active;       // if false, router ignores this channel
    }

    address public owner;
    IFlowChannelHardened public flow;

    // All known channels (for iteration / selection).
    bytes32[] public channelList;

    // channelId => metadata
    mapping(bytes32 => RouteTarget) public targetFor;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    /// @notice Fired when a channel is first registered with the router.
    event ChannelRegistered(bytes32 indexed channelId, uint256 weight);

    /// @notice Fired when routing metadata for a channel changes.
    event ChannelUpdated(bytes32 indexed channelId, uint256 weight, bool active);

    /// @notice Fired every time the router attempts to move liquidity from a
    ///         channel into `to`. If `amount` is zero, nothing was actually
    ///         pulled (e.g. claimable() was zero or below maxDesired), but we
    ///         still emit for telemetry / mesh accounting.
    event Routed(bytes32 indexed channelId, address to, uint256 amount);

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @param flowChannelAddress Address of the FlowChannelHardened executor this router will coordinate.
    /// @dev Typically this is a contract that enforces rate limits, pause/revoke,
    ///      and grantor consent (RIP-005 / RIP-007 logic).
    constructor(address flowChannelAddress) {
        owner = msg.sender;
        flow = IFlowChannelHardened(flowChannelAddress);
    }

    /// -----------------------------------------------------------------------
    /// Admin: channel management
    /// -----------------------------------------------------------------------

    /// @notice Register a new channel into routing consideration.
    /// @param channelId Opaque channel identifier understood by FlowChannelHardened.
    /// @param weight Higher weight means this channel is preferred in routing.
    /// @dev Reverts if channel already exists.
    function registerChannel(bytes32 channelId, uint256 weight) external onlyOwner {
        require(targetFor[channelId].channelId == 0, "EXISTS");

        channelList.push(channelId);
        targetFor[channelId] = RouteTarget({
            channelId: channelId,
            weight: weight,
            active: true
        });

        emit ChannelRegistered(channelId, weight);
    }

    /// @notice Update routing metadata for an existing channel.
    /// @param channelId Channel identifier.
    /// @param weight New routing weight.
    /// @param active New active flag.
    function updateChannel(bytes32 channelId, uint256 weight, bool active) external onlyOwner {
        require(targetFor[channelId].channelId != 0, "NO_CHANNEL");

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
    /// - "Greedy drain" strategy: pick the active channel with the highest weight.
    /// - Ask that channel how much is currently claimable.
    /// - Pull up to min(claimable, maxDesired).
    ///
    /// It's expected SettlementMesh (RIP-008) or other governance logic
    /// repeatedly calls routeStep() to slowly nudge the system toward a
    /// target allocation across domains.
    ///
    /// Safety:
    /// - We rely on FlowChannelHardened.pull() to revert if the underlying
    ///   channel is paused, revoked, or out-of-policy. We do NOT re-check that here.
    /// - Router itself never touches funds; transfer is grantor -> `to`.
    function routeStep(address to, uint256 maxDesired) external onlyOwner {
        require(to != address(0), "BAD_TO");

        // Pick highest-weight active channel
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

        require(best != 0, "NO_ACTIVE_ROUTE");

        // How much that channel says is currently safe to pull
        uint256 c = flow.claimable(best);

        // Bound by caller's requested maxDesired
        uint256 amt = c;
        if (amt > maxDesired) {
            amt = maxDesired;
        }

        if (amt > 0) {
            // This should move funds directly from the grantor tracked inside the
            // FlowChannelHardened channel to `to`. Router never holds funds.
            flow.pull(best, to, amt);
        }

        emit Routed(best, to, amt);
    }
}
