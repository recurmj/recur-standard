// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title SettlementMesh — RIP-008 hardened reference (final)
/// @notice Self-balancing liquidity coordinator. Nudges allocations toward target weights
///         by instructing AdaptiveRouter to route funds.
/// @dev Controller should be a Safe / multisig in production.
interface IAdaptiveRouter006 {
    function routeStep(address to, uint256 maxDesired) external;
}

contract SettlementMesh {
    struct DestTarget {
        uint32 targetBps; // 10000 = 100%
        bool active;
    }

    address public controller;
    IAdaptiveRouter006 public router;

    address[] public destList;
    mapping(address => DestTarget) public desired;

    // externally reported balances
    mapping(address => uint256) public reportedBalance;
    uint256 public reportedTotal;

    event ControllerUpdated(address indexed newController);
    event DestinationConfigured(address indexed dest, uint32 targetBps, bool active);
    event BalanceReported(address indexed dest, uint256 bal, uint256 total);
    event MeshStep(address indexed dest, uint256 deficit, uint256 sent);

    modifier onlyController() {
        require(msg.sender == controller, "not controller");
        _;
    }

    constructor(address routerAddr, address initialController) {
        router = IAdaptiveRouter006(routerAddr);
        controller = initialController;
    }

    function setController(address newController) external onlyController {
        controller = newController;
        emit ControllerUpdated(newController);
    }

    function configureDestination(address dest, uint32 targetBps, bool active) external onlyController {
        require(targetBps <= 10000, "bps>100%");
        if (!_isKnown(dest)) {
            destList.push(dest);
        }
        desired[dest] = DestTarget({ targetBps: targetBps, active: active });
        emit DestinationConfigured(dest, targetBps, active);
    }

    function _isKnown(address dest) internal view returns (bool) {
        for (uint256 i = 0; i < destList.length; i++) {
            if (destList[i] == dest) return true;
        }
        return false;
    }

    /// @notice Controller (governance / Safe) reports balances before rebalancing.
    function reportBalances(address[] calldata dests, uint256[] calldata bals, uint256 total) external onlyController {
        require(dests.length == bals.length, "len mismatch");
        reportedTotal = total;
        for (uint256 i = 0; i < dests.length; i++) {
            reportedBalance[dests[i]] = bals[i];
            emit BalanceReported(dests[i], bals[i], total);
        }
    }

    /// @notice One corrective step: find most underweight destination and feed it.
    /// @param maxStepAmount upper bound to attempt in this tick.
    function rebalanceTick(uint256 maxStepAmount) external onlyController {
        address bestDest;
        uint256 bestDeficit;

        for (uint256 i = 0; i < destList.length; i++) {
            address d = destList[i];
            DestTarget memory tgt = desired[d];
            if (!tgt.active) continue;
            if (tgt.targetBps == 0) continue;
            if (reportedTotal == 0) continue;

            uint256 want = (reportedTotal * uint256(tgt.targetBps)) / 10000;
            uint256 have = reportedBalance[d];
            if (have >= want) continue;

            uint256 deficit = want - have;
            if (deficit > bestDeficit) {
                bestDeficit = deficit;
                bestDest = d;
            }
        }

        if (bestDest == address(0) || bestDeficit == 0) {
            return;
        }

        uint256 step = bestDeficit;
        if (step > maxStepAmount) step = maxStepAmount;

        router.routeStep(bestDest, step);

        emit MeshStep(bestDest, bestDeficit, step);
    }
}