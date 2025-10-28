// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title FlowChannelHardened — RIP-005 hardened reference
/// @notice Continuous accrual channel with pause/revoke, rate updates, and optional policy enforcement.
/// @dev This version is closer to production shape.
/// - Grantee can claim streamed funds over time.
/// - Grantor can pause, resume, update rate/cap, or revoke entirely.
/// - Optional policy contract (RIP-007) can be consulted before each pull().
interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

interface IPolicyEnforcer {
    function checkAndConsume(bytes32 policyId, address caller, address to, uint256 amount) external;
}

abstract contract ReentrancyGuardFC {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "reentrancy");
        _status = 2;
        _;
        _status = 1;
    }
}

contract FlowChannelHardened is ReentrancyGuardFC {
    struct Channel {
        address grantor;
        address grantee;
        address token;

        uint256 ratePerSecond; // tokens per second
        uint256 maxBalance;    // accrual cap

        uint256 accrued;       // claimable amount
        uint64  lastUpdate;    // last accrual timestamp

        bool paused;
        bool revoked;

        // optional policy enforcing per-pull/per-epoch/etc.
        address policyEnforcer;
        bytes32 policyId;
    }

    mapping(bytes32 => Channel) public channels;

    event ChannelOpened(bytes32 indexed id, address indexed grantor, address indexed grantee, address token, uint256 ratePerSecond, uint256 maxBalance);
    event ChannelRateUpdated(bytes32 indexed id, uint256 newRatePerSecond, uint256 newMaxBalance);
    event ChannelPaused(bytes32 indexed id);
    event ChannelResumed(bytes32 indexed id);
    event ChannelRevoked(bytes32 indexed id);
    event Pulled(bytes32 indexed id, address to, uint256 amount);

    modifier onlyGrantor(bytes32 id) {
        require(msg.sender == channels[id].grantor, "not grantor");
        _;
    }
    modifier onlyGrantee(bytes32 id) {
        require(msg.sender == channels[id].grantee, "not grantee");
        _;
    }

    function openChannel(
        bytes32 id,
        address grantee,
        address token,
        uint256 ratePerSecond,
        uint256 maxBalance,
        address policyEnforcer,
        bytes32 policyId
    ) external {
        Channel storage c = channels[id];
        require(c.grantor == address(0), "channel exists");
        require(grantee != address(0) && token != address(0), "zero addr");
        require(ratePerSecond > 0 && maxBalance > 0, "bad params");

        channels[id] = Channel({
            grantor: msg.sender,
            grantee: grantee,
            token: token,
            ratePerSecond: ratePerSecond,
            maxBalance: maxBalance,
            accrued: 0,
            lastUpdate: uint64(block.timestamp),
            paused: false,
            revoked: false,
            policyEnforcer: policyEnforcer,
            policyId: policyId
        });

        emit ChannelOpened(id, msg.sender, grantee, token, ratePerSecond, maxBalance);
    }

    function _sync(bytes32 id) internal {
        Channel storage c = channels[id];
        uint256 dt = block.timestamp - c.lastUpdate;
        if (dt == 0) {
            return;
        }

        // if paused or revoked, accrual stops at pause boundary; we still update lastUpdate to prevent dt explosion later
        if (c.revoked || c.paused) {
            c.lastUpdate = uint64(block.timestamp);
            return;
        }

        uint256 newAccrued = c.accrued + (dt * c.ratePerSecond);
        if (newAccrued > c.maxBalance) {
            newAccrued = c.maxBalance;
        }

        c.accrued = newAccrued;
        c.lastUpdate = uint64(block.timestamp);
    }

    function accrue(bytes32 id) external {
        _sync(id);
    }

    function pull(bytes32 id, address to, uint256 amount) external nonReentrant onlyGrantee(id) {
        Channel storage c = channels[id];
        require(!c.revoked, "revoked");
        require(!c.paused, "paused");

        _sync(id);

        require(amount > 0, "amount=0");
        require(amount <= c.accrued, "exceeds accrued");

        // policy enforcement if configured
        if (c.policyEnforcer != address(0)) {
            IPolicyEnforcer(c.policyEnforcer).checkAndConsume(c.policyId, msg.sender, to, amount);
        }

        c.accrued -= amount;

        require(IERC20(c.token).transferFrom(c.grantor, to, amount), "transfer fail");

        emit Pulled(id, to, amount);
    }

    function pause(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        c.paused = true;
        _sync(id); // snapshot accrual at pause
        emit ChannelPaused(id);
    }

    function resume(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        require(!c.revoked, "revoked");
        c.paused = false;
        c.lastUpdate = uint64(block.timestamp); // reset accrual baseline
        emit ChannelResumed(id);
    }

    function revoke(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        c.revoked = true;
        _sync(id); // finalize accrual snapshot
        emit ChannelRevoked(id);
    }

    function updateRate(
        bytes32 id,
        uint256 newRatePerSecond,
        uint256 newMaxBalance
    ) external onlyGrantor(id) {
        require(newRatePerSecond > 0 && newMaxBalance > 0, "bad params");
        _sync(id);

        Channel storage c = channels[id];
        c.ratePerSecond = newRatePerSecond;
        c.maxBalance = newMaxBalance;

        emit ChannelRateUpdated(id, newRatePerSecond, newMaxBalance);
    }

    function claimable(bytes32 id) external view returns (uint256) {
        Channel storage c = channels[id];
        uint256 dt = block.timestamp - c.lastUpdate;
        uint256 projected = c.accrued;
        if (!(c.revoked || c.paused)) {
            projected += dt * c.ratePerSecond;
            if (projected > c.maxBalance) projected = c.maxBalance;
        }
        return projected;
    }
}