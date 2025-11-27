// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title FlowChannelHardened — RIP-005 hardened reference
/// @notice Continuous, rate-limited, revocable payment channel with optional policy enforcement.
///
/// @dev
/// High-level model:
/// - A grantor authorizes continuous accrual of an ERC20 balance to a grantee,
///   at `ratePerSecond`, capped by `maxBalance`.
/// - The grantee can call pull() to direct funds to any receiver `to`.
///   Funds NEVER sit in this contract — they flow grantor -> `to` via transferFrom.
/// - The grantor can pause(), resume(), updateRate(), or revoke() at any time.
/// - Optionally, a PolicyEnforcer (RIP-007) is checked on each pull()
///   to enforce budgets / receiver allowlists / jurisdictional rules.
///
/// Security model:
/// - This contract NEVER escrows tokens. It just calls
///     ERC20(token).transferFrom(grantor, to, amount)
///   during pull().
///   => The grantor must have given this contract sufficient allowance,
///      or pull() will revert.
/// - pause() and revoke() are instant kill switches:
///     * paused  => accrual stops *and* pull() reverts, but can later resume().
///     * revoked => accrual frozen forever; pull() will always revert.
/// - Reentrancy is guarded.
/// - AdaptiveRouter (RIP-006) / SettlementMesh (RIP-008) can be the grantee
///   so they can orchestrate rebalancing without custody.
///
/// Accounting model:
/// - Accrual math is deterministic and saturating:
///     accrued' = min(maxBalance, accrued + ratePerSecond * dt)
/// - _sync() is called before any state mutation that depends on up-to-date accrual.
/// - claimable() simulates that same math in view-only mode without mutating.
///
/// Integration expectations:
/// - One channel ~= "stream token T from grantor → grantee at rate R,
///   with a buffer cap of B".
/// - AdaptiveRouter decides *which* channel to drain and *where* to send the funds (`to`).
/// - PolicyEnforcer can enforce spend ceilings per epoch, receiver allowlists, etc.

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IPolicyEnforcer {
    /// @notice MUST revert if this pull should not be allowed.
    /// @dev Typical checks:
    ///  - caller is the approved grantee
    ///  - `to` is allowed
    ///  - amount fits per-epoch / per-day budget
    ///  - consume budget
    function checkAndConsume(
        bytes32 policyId,
        address caller,
        address to,
        uint256 amount
    ) external;
}

/// @dev Minimal in-contract reentrancy guard (kept local for portability).
abstract contract ReentrancyGuardFC {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "REENTRANCY");
        _status = 2;
        _;
        _status = 1;
    }
}

contract FlowChannelHardened is ReentrancyGuardFC {
    using SafeERC20 for IERC20;

    struct Channel {
        address grantor;          // who ultimately pays
        address grantee;          // who is authorized to call pull()
        address token;            // ERC-20 being streamed

        uint256 ratePerSecond;    // tokens/sec accruing to grantee
        uint256 maxBalance;       // cap on accrued buffer

        uint256 accrued;          // currently claimable (after last _sync)
        uint64  lastUpdate;       // last accrual timestamp (unix seconds)

        bool paused;              // if true: accrual stops, pull() reverts (but can resume)
        bool revoked;             // if true: dead forever (no accrual, no pull ever again)

        // Optional policy layer (RIP-007)
        address policyEnforcer;   // contract that enforces spend rules
        bytes32 policyId;         // policy key understood by that enforcer
    }

    /// channelId (bytes32) => Channel
    mapping(bytes32 => Channel) public channels;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event ChannelOpened(
        bytes32 indexed id,
        address indexed grantor,
        address indexed grantee,
        address token,
        uint256 ratePerSecond,
        uint256 maxBalance
    );

    /// @notice Emitted when streaming parameters are updated.
    /// @param id Channel ID.
    /// @param oldRatePerSecond Previous accrual rate.
    /// @param oldMaxBalance    Previous buffer cap.
    /// @param newRatePerSecond New accrual rate.
    /// @param newMaxBalance    New buffer cap.
    event ChannelRateUpdated(
        bytes32 indexed id,
        uint256 oldRatePerSecond,
        uint256 oldMaxBalance,
        uint256 newRatePerSecond,
        uint256 newMaxBalance
    );

    event ChannelPaused(bytes32 indexed id);
    event ChannelResumed(bytes32 indexed id);
    event ChannelRevoked(bytes32 indexed id);

    /// @notice Fired whenever value actually streams out.
    /// @dev `to` is the final receiver of the funds in this pull().
    event Pulled(bytes32 indexed id, address to, uint256 amount);

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyGrantor(bytes32 id) {
        require(msg.sender == channels[id].grantor, "NOT_GRANTOR");
        _;
    }

    modifier onlyGrantee(bytes32 id) {
        require(msg.sender == channels[id].grantee, "NOT_GRANTEE");
        _;
    }

    // -----------------------------------------------------------------------
    // Channel lifecycle
    // -----------------------------------------------------------------------

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
        require(c.grantor == address(0), "CHANNEL_EXISTS");
        require(grantee != address(0) && token != address(0), "BAD_ADDR");
        require(ratePerSecond > 0 && maxBalance > 0, "BAD_PARAMS");

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

    // -----------------------------------------------------------------------
    // Internal accrual logic (saturating, overflow-safe)
    // -----------------------------------------------------------------------

    /// @dev Sync a channel's `accrued` balance up to `block.timestamp`.
    ///      Accrual stops immediately if paused or revoked.
    ///
    ///      Implementation is saturating:
    ///      - If accrued is already at maxBalance, we do nothing but bump lastUpdate.
    ///      - Otherwise we compute the maximum dt before hitting maxBalance as:
    ///            maxDt = (maxBalance - accrued) / ratePerSecond
    ///        and either:
    ///            - set accrued = maxBalance if dt >= maxDt, or
    ///            - accrued += dt * ratePerSecond (which is safe because dt < maxDt).
    function _sync(bytes32 id) internal {
        Channel storage c = channels[id];

        // Bump timestamp and halt accrual if paused/revoked.
        if (c.revoked || c.paused) {
            c.lastUpdate = uint64(block.timestamp);
            return;
        }

        uint256 dt = block.timestamp - c.lastUpdate;
        if (dt == 0) {
            return;
        }

        // If we've already hit the cap, just update lastUpdate.
        if (c.accrued >= c.maxBalance) {
            c.accrued = c.maxBalance;
            c.lastUpdate = uint64(block.timestamp);
            return;
        }

        // No accrual if rate is zero (defensive; rate should normally > 0).
        if (c.ratePerSecond == 0) {
            c.lastUpdate = uint64(block.timestamp);
            return;
        }

        uint256 remaining = c.maxBalance - c.accrued;

        // Maximum dt we can apply before hitting the cap.
        uint256 maxDt = remaining / c.ratePerSecond;

        if (maxDt == 0 || dt >= maxDt) {
            // One more second at this rate would exceed the cap
            // => saturate to maxBalance.
            c.accrued = c.maxBalance;
            c.lastUpdate = uint64(block.timestamp);
            return;
        }

        // Here: dt < maxDt, so dt * ratePerSecond < remaining.
        // This guarantees no overflow and accrued' <= maxBalance.
        c.accrued = c.accrued + (dt * c.ratePerSecond);
        c.lastUpdate = uint64(block.timestamp);
    }

    /// @notice Public helper to force accrual update without pulling.
    /// @dev Anyone can call this — it only updates accounting for `id`.
    function accrue(bytes32 id) external {
        _sync(id);
    }

    // -----------------------------------------------------------------------
    // Pull / spend path
    // -----------------------------------------------------------------------

    function pull(bytes32 id, address to, uint256 amount)
        external
        nonReentrant
        onlyGrantee(id)
    {
        require(to != address(0), "BAD_TO");

        Channel storage c = channels[id];
        require(!c.revoked, "REVOKED");
        require(!c.paused, "PAUSED");

        _sync(id);

        require(amount > 0, "AMOUNT_0");
        require(amount <= c.accrued, "EXCEEDS_ACCRUED");

        // Optional policy guard (RIP-007)
        if (c.policyEnforcer != address(0)) {
            IPolicyEnforcer(c.policyEnforcer).checkAndConsume(
                c.policyId,
                msg.sender,
                to,
                amount
            );
        }

        // Deduct BEFORE external transferFrom()
        c.accrued -= amount;

        // Non-custodial transfer out of the grantor's balance (SafeERC20).
        IERC20(c.token).safeTransferFrom(c.grantor, to, amount);

        emit Pulled(id, to, amount);
    }

    // -----------------------------------------------------------------------
    // Grantor controls
    // -----------------------------------------------------------------------

    function pause(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        _sync(id);          // snapshot first for clean accounting
        c.paused = true;    // then flip the flag
        emit ChannelPaused(id);
    }

    function resume(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        require(!c.revoked, "REVOKED");
        c.paused = false;
        c.lastUpdate = uint64(block.timestamp);
        emit ChannelResumed(id);
    }

    function revoke(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        _sync(id);          // snapshot "final" accrued for audit
        c.revoked = true;   // dead forever
        emit ChannelRevoked(id);
    }

    function updateRate(
        bytes32 id,
        uint256 newRatePerSecond,
        uint256 newMaxBalance
    ) external onlyGrantor(id) {
        require(newRatePerSecond > 0 && newMaxBalance > 0, "BAD_PARAMS");

        Channel storage c = channels[id];

        _sync(id);

        uint256 oldRate = c.ratePerSecond;
        uint256 oldCap  = c.maxBalance;

        c.ratePerSecond = newRatePerSecond;
        c.maxBalance    = newMaxBalance;

        emit ChannelRateUpdated(
            id,
            oldRate,
            oldCap,
            newRatePerSecond,
            newMaxBalance
        );
    }

    // -----------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------

    /// @notice View how much is currently claimable, *as if* we synced now,
    ///         without mutating state.
    /// @dev Uses the same saturating, overflow-safe accrual logic as _sync().
    function claimable(bytes32 id) external view returns (uint256) {
        Channel storage c = channels[id];

        // If paused/revoked, no further accrual.
        if (c.revoked || c.paused) {
            return c.accrued;
        }

        // Defensive: if rate is zero, nothing accrues.
        if (c.ratePerSecond == 0) {
            return c.accrued;
        }

        uint256 dt = block.timestamp - c.lastUpdate;
        if (dt == 0) {
            return c.accrued;
        }

        if (c.accrued >= c.maxBalance) {
            return c.maxBalance;
        }

        uint256 remaining = c.maxBalance - c.accrued;
        uint256 maxDt = remaining / c.ratePerSecond;

        if (maxDt == 0 || dt >= maxDt) {
            return c.maxBalance;
        }

        // dt < maxDt ⇒ dt * ratePerSecond < remaining ⇒
        // accrued + dt*ratePerSecond <= maxBalance and cannot overflow.
        return c.accrued + (dt * c.ratePerSecond);
    }
}
