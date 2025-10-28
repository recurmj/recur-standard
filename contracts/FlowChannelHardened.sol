// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title FlowChannelHardened — RIP-005 hardened reference
/// @notice Continuous, rate-limited, revocable payment channel with optional policy enforcement.
/// @dev
/// - Grantor authorizes continuous accrual to a grantee.
/// - Value accrues over time at `ratePerSecond`, up to `maxBalance`.
/// - Grantee can pull accrued funds in chunks (no custody here; funds go grantor -> destination).
/// - Grantor can pause(), resume(), updateRate(), or revoke() at any time.
/// - Optional policyEnforcer (RIP-007) is called before each pull to enforce compliance / KYC / caps.
///
/// SECURITY MODEL
/// - This contract NEVER holds user funds. It just calls `transferFrom(grantor, to, amount)`.
///   => Grantor must approve this contract as spender on the token.
/// - If paused or revoked, accrual stops and pull() reverts.
/// - Reentrancy is guarded.
/// - AdaptiveRouter (RIP-006) and SettlementMesh (RIP-008) can call pull() indirectly
///   by being set as the grantee, or by being the `to` they route to, depending on deployment.
///
/// AUDIT-READY BEHAVIOR
/// - Accrual math is deterministic: accrued += ratePerSecond * dt, then capped at maxBalance.
/// - `_sync()` is always called before state transitions that depend on `accrued`.
/// - `claimable()` simulates `_sync()` without mutating, for routing decisions.
///
/// INTEGRATION EXPECTATION
/// - For institutional treasuries, each Channel maps 1:1 to "stream X of token T from grantor to grantee".
/// - AdaptiveRouter picks *which* channel to drain and *where* to send it (the `to` param).
/// - PolicyEnforcer (if present) can enforce jurisdiction, per-epoch limits, etc.
interface ITrackedERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

interface IPolicyEnforcer {
    /// @notice MUST revert if this pull should not be allowed.
    /// @dev Typical checks:
    ///  - caller is approved
    ///  - `to` is on an allowlist
    ///  - amount is within per-epoch / per-day budget
    ///  - consume against running budget
    function checkAndConsume(
        bytes32 policyId,
        address caller,
        address to,
        uint256 amount
    ) external;
}

/// @dev Simple reentrancy guard dedicated to FlowChannelHardened.
/// We do NOT import OpenZeppelin here to keep the reference lean.
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
    struct Channel {
        address grantor;          // who is ultimately paying
        address grantee;          // who is authorized to call pull()
        address token;            // ERC-20 being streamed

        uint256 ratePerSecond;    // tokens/sec that accrue
        uint256 maxBalance;       // cap on accrued buffer

        uint256 accrued;          // currently claimable
        uint64  lastUpdate;       // last accrual timestamp (unix seconds)

        bool paused;              // true => accrual stops, pull() reverts
        bool revoked;             // true => permanently dead

        // Optional policy layer (RIP-007)
        address policyEnforcer;   // contract implementing IPolicyEnforcer
        bytes32 policyId;         // policy key understood by that enforcer
    }

    /// @notice channelId (bytes32) → Channel
    mapping(bytes32 => Channel) public channels;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event ChannelOpened(
        bytes32 indexed id,
        address indexed grantor,
        address indexed grantee,
        address token,
        uint256 ratePerSecond,
        uint256 maxBalance
    );

    event ChannelRateUpdated(
        bytes32 indexed id,
        uint256 newRatePerSecond,
        uint256 newMaxBalance
    );

    event ChannelPaused(bytes32 indexed id);
    event ChannelResumed(bytes32 indexed id);
    event ChannelRevoked(bytes32 indexed id);

    /// @notice Fired whenever value is actually streamed out of the channel.
    /// @dev `to` is the final receiver of funds in this pull().
    event Pulled(bytes32 indexed id, address to, uint256 amount);

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    modifier onlyGrantor(bytes32 id) {
        require(msg.sender == channels[id].grantor, "NOT_GRANTOR");
        _;
    }

    modifier onlyGrantee(bytes32 id) {
        require(msg.sender == channels[id].grantee, "NOT_GRANTEE");
        _;
    }

    /// -----------------------------------------------------------------------
    /// Channel lifecycle
    /// -----------------------------------------------------------------------

    /// @notice Create a new streaming channel.
    /// @param id            Chosen channel identifier (must be unique).
    /// @param grantee       Address allowed to call pull() / spend the stream.
    /// @param token         ERC-20 being streamed.
    /// @param ratePerSecond Tokens per second that accrue.
    /// @param maxBalance    Maximum unclaimed buffer before accrual stops.
    /// @param policyEnforcer Contract to enforce policy (optional, can be address(0)).
    /// @param policyId      Policy identifier understood by policyEnforcer.
    ///
    /// Requirements:
    /// - `id` must not already exist.
    /// - `ratePerSecond` > 0 and `maxBalance` > 0.
    /// - `grantee` and `token` must be nonzero.
    /// - Grantor MUST separately approve this contract as ERC20 spender
    ///   or nothing can ever actually transfer.
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

    /// -----------------------------------------------------------------------
    /// Internal accrual logic
    /// -----------------------------------------------------------------------

    /// @dev Sync a channel's `accrued` balance up to `block.timestamp`.
    ///      Accrual stops if paused or revoked.
    function _sync(bytes32 id) internal {
        Channel storage c = channels[id];

        uint256 dt = block.timestamp - c.lastUpdate;
        if (dt == 0) {
            return;
        }

        // If paused or revoked, accrual halts. We still bump lastUpdate so dt
        // doesn't accumulate infinitely while paused.
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

    /// @notice Public helper to force accrual update without pulling.
    /// @dev Anyone can call this — it only updates accounting for `id`.
    function accrue(bytes32 id) external {
        _sync(id);
    }

    /// -----------------------------------------------------------------------
    /// Pull / spend path
    /// -----------------------------------------------------------------------

    /// @notice Grantee withdraws part of the accrued balance to any `to`.
    /// @param id     Channel identifier.
    /// @param to     Final receiver of funds on this chain.
    /// @param amount Amount to pull right now.
    ///
    /// Requirements:
    /// - Caller MUST be the channel's grantee.
    /// - Channel MUST NOT be paused or revoked.
    /// - `amount` ≤ claimable() at the time of call.
    /// - `to` cannot be address(0).
    ///
    /// On success:
    /// - `accrued` is reduced.
    /// - Token is transferred via ERC20.transferFrom(grantor -> to).
    /// - PolicyEnforcer (if set) can veto or burn budget first.
    ///
    /// SECURITY: This contract never takes custody.
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

        // Deduct before external call
        c.accrued -= amount;

        // Non-custodial transfer
        require(
            ITrackedERC20(c.token).transferFrom(c.grantor, to, amount),
            "TRANSFER_FAIL"
        );

        emit Pulled(id, to, amount);
    }

    /// -----------------------------------------------------------------------
    /// Grantor controls
    /// -----------------------------------------------------------------------

    /// @notice Pause accrual + block pulls (but do not revoke permanently).
    /// @dev We _sync first so `accrued` reflects balance up to this pause boundary.
    function pause(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        c.paused = true;
        _sync(id);
        emit ChannelPaused(id);
    }

    /// @notice Resume accrual and allow pulls again.
    /// @dev We reset `lastUpdate` so accrual restarts from "now".
    function resume(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        require(!c.revoked, "REVOKED");
        c.paused = false;
        c.lastUpdate = uint64(block.timestamp);
        emit ChannelResumed(id);
    }

    /// @notice Permanently revoke a channel.
    /// @dev After revoke():
    ///  - accrual is frozen forever
    ///  - pull() will revert
    ///  - any remaining `accrued` is effectively stranded unless you build a recovery path
    ///    (deliberately conservative: grantor is cutting the cord)
    function revoke(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        c.revoked = true;
        _sync(id); // snapshot final accrued for audit visibility
        emit ChannelRevoked(id);
    }

    /// @notice Update streaming rate / cap for a still-live channel.
    /// @dev We sync first so accrued reflects earnings up to this point
    ///      under the OLD rate. Then we overwrite rate/maxBalance and emit.
    function updateRate(
        bytes32 id,
        uint256 newRatePerSecond,
        uint256 newMaxBalance
    ) external onlyGrantor(id) {
        require(newRatePerSecond > 0 && newMaxBalance > 0, "BAD_PARAMS");

        _sync(id);

        Channel storage c = channels[id];
        c.ratePerSecond = newRatePerSecond;
        c.maxBalance = newMaxBalance;

        emit ChannelRateUpdated(id, newRatePerSecond, newMaxBalance);
    }

    /// -----------------------------------------------------------------------
    /// Views
    /// -----------------------------------------------------------------------

    /// @notice Pure view of how much is currently claimable, *as if* we synced now,
    ///         without mutating state.
    /// @dev AdaptiveRouter / dashboards call this.
    function claimable(bytes32 id) external view returns (uint256) {
        Channel storage c = channels[id];

        uint256 projected = c.accrued;
        uint256 dt = block.timestamp - c.lastUpdate;

        if (!(c.revoked || c.paused)) {
            projected += dt * c.ratePerSecond;
            if (projected > c.maxBalance) {
                projected = c.maxBalance;
            }
        }

        return projected;
    }
}
