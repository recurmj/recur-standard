// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @dev controller is expected to be the same Safe/multisig that operates
///      DomainDirectory, so that one ops key can halt routing end-to-end.
/// @title SettlementMesh — RIP-008 hardened reference (final)
/// @notice Self-balancing liquidity coordinator. Nudges allocations toward target
///         weights by telling AdaptiveRouter to route funds toward whichever
///         destination is currently most underweight.
/// @dev
/// - This contract NEVER holds funds.
/// - `controller` (Safe / multisig) is the only actor allowed to
///   (a) report balances and (b) trigger rebalancing steps.
/// - Balances are reported, not discovered on-chain. Treasury / ops feeds
///   real-world numbers in via reportBalances().
/// - Each call to rebalanceTick() is one incremental nudge, not a full solve.
/// - We do NOT require that sum(targetBps) == 10000. You can intentionally
///   over- or under-allocate. We just compare each destination to its own
///   desired share of `reportedTotal`.
///
/// Flow:
///   1. controller calls reportBalances(...).
///   2. controller calls rebalanceTick(maxStepAmount).
///   3. Mesh picks the most underweight destination vs its targetBps allocation
///      and asks AdaptiveRouter to push up to `maxStepAmount` toward it.
///   4. Router drains from the highest-weight eligible channel (RIP-006),
///      which in turn pays directly from grantor -> destination. No custody.
/// 
/// SECURITY / REENTRANCY NOTE:
/// - rebalanceTick() makes an external call to router.routeStep(), which is
///   expected to move real funds downstream. SettlementMesh does NOT update any
///   of its own accounting after that external call (no post-state writes),
///   so reentrancy back into Mesh can't corrupt internal state.
/// - router MUST be trusted infra (AdaptiveRouter with its controller locked).
interface IAdaptiveRouter {
    /// @notice Attempt to route up to `maxDesired` funds to `to`.
    /// @dev Router will:
    ///      - pick the best active channel,
    ///      - ask that channel to pull from grantor -> `to`,
    ///      - emit its own Routed(...) event.
    function routeStep(address to, uint256 maxDesired) external;
}

contract SettlementMesh {
    struct DestTarget {
        uint32 targetBps; // desired share of total, in basis points. 10000 = 100%
        bool active;      // if false, ignore this destination in balancing logic
    }

    /// @notice Privileged authority (treasury Safe / multisig).
    address public controller;

    /// @notice Router (RIP-006) that actually talks to FlowChannelHardened.
    IAdaptiveRouter public router;

    // List of destinations (chain treasuries, exchange hot wallets, custodians, etc.)
    address[] public destList;

    // Desired allocation per destination.
    mapping(address => DestTarget) public desired;

    // Controller-reported balances per destination (off-chain truth inserted on-chain).
    mapping(address => uint256) public reportedBalance;
    uint256 public reportedTotal;

    event ControllerUpdated(address indexed newController);

    event DestinationConfigured(
        address indexed dest,
        uint32 targetBps,
        bool active
    );

    /// @notice Emitted whenever controller feeds a new balance snapshot.
    event BalanceReported(
        address indexed dest,
        uint256 bal,
        uint256 total
    );

    /// @notice Emitted after each rebalanceTick(), showing what we tried to fix.
    /// @param dest      which destination we tried to top up
    /// @param deficit   how far below target it was before this step
    /// @param sent      how much we asked router to send in this step
    event MeshStep(
        address indexed dest,
        uint256 deficit,
        uint256 sent
    );

    modifier onlyController() {
        require(msg.sender == controller, "NOT_CONTROLLER");
        _;
    }

    /// @param routerAddr address of AdaptiveRouter (RIP-006)
    /// @param initialController address of Safe / multisig governance
    constructor(address routerAddr, address initialController) {
        require(routerAddr != address(0), "BAD_ROUTER");
        require(initialController != address(0), "BAD_CTRL");
        router = IAdaptiveRouter(routerAddr);
        controller = initialController;
    }

    /// @notice Governance can rotate controller (e.g. rotate multisig).
    function setController(address newController) external onlyController {
        require(newController != address(0), "BAD_CTRL");
        controller = newController;
        emit ControllerUpdated(newController);
    }

    /// @notice Configure/adjust desired allocation for a given destination.
    /// @dev targetBps is the desired share of the *reportedTotal* for that dest.
    ///      Example: targetBps = 4500 means "we want ~45% of total liquidity here."
    ///      We do NOT enforce that sum of all targetBps == 10000.
    /// @param dest destination address (treasury wallet, chain sink, etc.)
    /// @param targetBps basis points of desired share (0–10000)
    /// @param active whether this dest participates in balancing
    function configureDestination(
        address dest,
        uint32 targetBps,
        bool active
    ) external onlyController {
        require(dest != address(0), "BAD_DEST");
        require(targetBps <= 10000, "BPS_GT_100%");
        if (!_isKnown(dest)) {
            destList.push(dest);
        }
        desired[dest] = DestTarget({
            targetBps: targetBps,
            active: active
        });

        emit DestinationConfigured(dest, targetBps, active);
    }

    /// @dev O(n) scan is fine because destList should stay small (handful of domains).
    function _isKnown(address dest) internal view returns (bool) {
        for (uint256 i = 0; i < destList.length; i++) {
            if (destList[i] == dest) return true;
        }
        return false;
    }

    /// @notice Controller (treasury / ops / Safe) publishes the latest observed balances.
    /// @dev This is intentionally a trusted input. We assume off-chain systems
    ///      (custodians, exchanges, non-EVM venues, etc.) feed truth here.
    /// @param dests array of destination addresses
    /// @param bals  balances at those destinations, same index order as dests
    /// @param total total liquidity across all relevant venues (denominator for targetBps math)
    function reportBalances(
        address[] calldata dests,
        uint256[] calldata bals,
        uint256 total
    ) external onlyController {
        require(dests.length == bals.length, "LEN_MISMATCH");

        reportedTotal = total;
        for (uint256 i = 0; i < dests.length; i++) {
            reportedBalance[dests[i]] = bals[i];
            emit BalanceReported(dests[i], bals[i], total);
        }
    }

    /// @notice Perform one incremental rebalance step.
    /// @dev
    /// 1. Finds the *most underweight* active destination.
    /// 2. Calculates its shortfall vs target.
    /// 3. Asks router.routeStep(...) to send up to `maxStepAmount` toward it.
    ///
    /// Router then drains from the highest-weight active channel,
    /// which in turn pulls directly from the grantor on that channel
    /// (FlowChannelHardened) to the destination wallet.
    ///
    /// SettlementMesh never touches funds.
    ///
    /// SECURITY / TRUST:
    /// - This function makes an external call to `router.routeStep` which is
    ///   expected to perform real fund movement down the line.
    /// - Only `controller` can call this, so you are explicitly authorizing that
    ///   movement when you call it.
    ///
    /// @param maxStepAmount Upper bound we allow router to try to send this tick.
    function rebalanceTick(uint256 maxStepAmount) external onlyController {
        require(maxStepAmount > 0, "ZERO_STEP");

        address bestDest;
        uint256 bestDeficit;

        // Choose the destination that's most below target share.
        for (uint256 i = 0; i < destList.length; i++) {
            address d = destList[i];
            DestTarget memory tgt = desired[d];
            if (!tgt.active) continue;
            if (tgt.targetBps == 0) continue;
            if (reportedTotal == 0) continue;

            // desired stake in absolute units
            uint256 want = (reportedTotal * uint256(tgt.targetBps)) / 10000;
            uint256 have = reportedBalance[d];
            if (have >= want) continue;

            uint256 deficit = want - have;
            if (deficit > bestDeficit) {
                bestDeficit = deficit;
                bestDest = d;
            }
        }

        // Nothing underweight? We're already "balanced enough".
        if (bestDest == address(0) || bestDeficit == 0) {
            return;
        }

        uint256 step = bestDeficit;
        if (step > maxStepAmount) {
            step = maxStepAmount;
        }

        // Instruct router to nudge liquidity toward the most underweight dest.
        // router will internally pick a funding channel and perform the actual pull.
        router.routeStep(bestDest, step);

        emit MeshStep(bestDest, bestDeficit, step);
    }
}
