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
///      or pull() will revert with TRANSFER_FAIL.
/// - pause() and revoke() are instant kill switches:
///     * paused  => accrual stops *and* pull() reverts, but can later resume().
///     * revoked => accrual frozen forever; pull() will always revert.
/// - Reentrancy is guarded.
/// - AdaptiveRouter (RIP-006) / SettlementMesh (RIP-008) can be the grantee
///   so they can orchestrate rebalancing without custody.
///
/// Accounting model:
/// - Accrual math is deterministic:
///     accrued += ratePerSecond * dt
///     capped at maxBalance
/// - _sync() is called before any state mutation that depends on up-to-date accrual.
/// - claimable() simulates that same math in view-only mode without mutating.
///
/// Integration expectations:
/// - One channel ~= "stream token T from grantor → grantee at rate R,
///   with a buffer cap of B".
/// - AdaptiveRouter decides *which* channel to drain and *where* to send the funds (`to`).
/// - PolicyEnforcer can enforce spend ceilings per epoch, receiver allowlists, etc.
interface ITrackedERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

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

    /// @notice Create a new streaming channel.
    /// @param id              Chosen channel identifier (must be unique).
    /// @param grantee         Address allowed to call pull() / spend the stream.
    /// @param token           ERC-20 being streamed.
    /// @param ratePerSecond   Tokens per second that accrue.
    /// @param maxBalance      Maximum unclaimed buffer before accrual stops.
    /// @param policyEnforcer  Optional policy module (address(0) = none).
    /// @param policyId        Policy identifier for that enforcer.
    ///
    /// @dev
    /// NON-CUSTODIAL CONSENT MODEL:
    /// - This contract NEVER escrows tokens.
    /// - pull() calls token.transferFrom(grantor -> receiver).
    /// - Therefore the grantor MUST have given this contract sufficient ERC20 allowance
    ///   (via token.approve(address(this), amount)) before any pull can succeed.
    /// - If allowance is missing or too low, pull() will revert with TRANSFER_FAIL.
    ///
    /// SAFETY:
    /// - The grantor can yank or reduce allowance at any time to cut off outflow,
    ///   even without pausing/revoking the channel.
    ///
    /// Requirements:
    /// - `id` must not already exist.
    /// - `ratePerSecond` > 0 and `maxBalance` > 0.
    /// - `grantee` and `token` must be nonzero.
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
    // Internal accrual logic
    // -----------------------------------------------------------------------

    /// @dev Sync a channel's `accrued` balance up to `block.timestamp`.
    ///      Accrual stops immediately if paused or revoked.
    function _sync(bytes32 id) internal {
        Channel storage c = channels[id];

        uint256 dt = block.timestamp - c.lastUpdate;
        if (dt == 0) {
            return;
        }

        // If paused or revoked, accrual halts. Still bump lastUpdate
        // so dt doesn't accumulate while off.
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

    // -----------------------------------------------------------------------
    // Pull / spend path
    // -----------------------------------------------------------------------

    /// @notice Grantee withdraws part of the accrued balance to any `to`.
    /// @param id     Channel identifier.
    /// @param to     Final receiver of funds on this chain.
    /// @param amount Amount to pull right now.
    ///
    /// @dev
    /// NON-CUSTODIAL TRANSFER:
    /// - This contract does NOT hold tokens.
    /// - It simply calls token.transferFrom(grantor -> to, amount).
    /// - The grantor MUST maintain ERC20 allowance for this contract or
    ///   pull() will revert with TRANSFER_FAIL.
    ///
    /// EMERGENCY CONTROL:
    /// - Grantor can pause() (or revoke()) the channel, which halts accrual
    ///   and makes pull() revert.
    /// - Grantor can also drop allowance on the ERC20 itself.
    ///
    /// Requirements:
    /// - Caller MUST be the channel's grantee.
    /// - Channel MUST NOT be paused or revoked.
    /// - `amount` > 0 and `amount` ≤ claimable() at this instant.
    /// - `to` cannot be address(0).
    ///
    /// Effects on success:
    /// - `accrued` is reduced.
    /// - Optional PolicyEnforcer is checked and consumes budget.
    /// - ERC20 tokens move directly grantor -> `to`.
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

        // Non-custodial transfer out of the grantor's balance.
        require(
            ITrackedERC20(c.token).transferFrom(c.grantor, to, amount),
            "TRANSFER_FAIL"
        );

        emit Pulled(id, to, amount);
    }

    // -----------------------------------------------------------------------
    // Grantor controls
    // -----------------------------------------------------------------------

    /// @notice Pause accrual and block pulls (but do not permanently revoke).
    ///
    /// @dev
    /// Behavior:
    /// - After pause():
    ///    * accrual stops,
    ///    * pull() will revert,
    ///    * channel can later resume().
    ///
    /// Implementation detail:
    /// - We _sync first to snapshot accrued up to "now",
    ///   THEN mark paused=true.
    function pause(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        _sync(id);          // snapshot first for clean accounting
        c.paused = true;    // then flip the flag
        emit ChannelPaused(id);
    }

    /// @notice Resume accrual and allow pulls again.
    ///
    /// @dev
    /// Behavior:
    /// - After resume():
    ///    * accrual restarts from the current timestamp,
    ///    * pull() is allowed again (unless revoked separately).
    ///
    /// Implementation detail:
    /// - We clear paused AFTER ensuring not revoked,
    ///   and reset lastUpdate to "now" so accrual restarts cleanly.
    function resume(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        require(!c.revoked, "REVOKED");
        c.paused = false;
        c.lastUpdate = uint64(block.timestamp);
        emit ChannelResumed(id);
    }

    /// @notice Permanently revoke a channel.
    ///
    /// @dev
    /// Behavior:
    /// - After revoke():
    ///    * accrual is frozen forever,
    ///    * pull() will always revert,
    ///    * channel cannot be resumed.
    /// - Any remaining `accrued` is effectively stranded unless you implement
    ///   an explicit "recover leftovers" path in a custom fork. We intentionally
    ///   do NOT provide that here — revoke() is an emergency hard kill.
    ///
    /// Implementation detail:
    /// - We _sync first so accrued reflects earnings up to this exact revoke boundary,
    ///   THEN mark revoked=true.
    function revoke(bytes32 id) external onlyGrantor(id) {
        Channel storage c = channels[id];
        _sync(id);          // snapshot "final" accrued for audit
        c.revoked = true;   // dead forever
        emit ChannelRevoked(id);
    }

    /// @notice Update streaming rate / cap for a still-live channel.
    ///
    /// @param id                Channel identifier.
    /// @param newRatePerSecond  New accrual rate.
    /// @param newMaxBalance     New accrual buffer cap.
    ///
    /// @dev
    /// - We _sync first so `accrued` reflects earnings at the OLD rate,
    ///   then update to the NEW rate.
    /// - Emits ChannelRateUpdated with both old and new values for audit.
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
    /// @dev Routers / dashboards / SettlementMesh call this.
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
