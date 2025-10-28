// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title EVMPPOAdapter
/// @notice RIP-004 / RIP-008 domain adapter for EVM domains that settle using
///         discrete, consented pulls via RecurPullSafeV2 (RIP-001 + RIP-002).
///
/// @dev
/// This adapter NEVER takes custody.
/// It just forwards an already-signed Authorization into RecurPullSafeV2,
/// under tight checks. The actual USDC/asset transfer is done by
/// RecurPullSafeV2: grantor -> grantee, directly.
///
/// IMPORTANT MODEL DIFFERENCE vs the channel adapter:
/// - FlowChannelHardened (RIP-005) can pay arbitrary `to` per pull
///   because it exposes `pull(channelId, to, amount)`.
///
/// - RecurPullSafeV2 pays the `grantee` that the grantor authorized
///   in the signed Authorization. There's no per-call override of the
///   receiver. So for "cross-domain rebalancing", the `grantee` in the
///   Authorization MUST already be the correct destination (e.g. a
///   treasury or settlement address for that domain).
///
/// Security assumptions:
/// - The Authorization is signed by `auth.grantor`.
/// - RecurPullSafeV2.verify() enforces:
//      * signature is valid (EOA or 1271)
//      * msg.sender == auth.grantee
//      * time window, maxPerPull, revocation via registry
/// - We enforce here that only that same grantee can call this adapter.
///   So no one else can drain someone else's PPO.
interface IRecurPullSafeV2 {
    struct Authorization {
        address grantor;      // wallet giving consent
        address grantee;      // wallet/agent allowed to pull (and who receives funds)
        address token;        // ERC-20 being pulled
        uint256 maxPerPull;   // per-call ceiling
        uint256 validAfter;   // earliest timestamp allowed
        uint256 validBefore;  // latest timestamp allowed
        bytes32 nonce;        // unique salt
        bytes   signature;    // grantor's signature over these terms (EIP-712 / 1271)
    }

    /// @notice Execute a permissioned pull under a signed Authorization.
    /// @dev Will revert if:
    ///   - revoked in Consent Registry,
    ///   - outside validAfter/validBefore,
    ///   - amount > maxPerPull,
    ///   - signature invalid,
    ///   - msg.sender != auth.grantee.
    /// On success, transfers `token` from `grantor` to `grantee`.
    function pull(
        Authorization calldata auth,
        uint256 amount
    ) external;
}

contract EVMPPOAdapter {
    /// @notice The RecurPullSafeV2 executor for this domain.
    IRecurPullSafeV2 public recurPull;

    /// @dev Optionally pin an expected grantor + token for this adapter,
    ///      so you can't use this adapter to drain unrelated authorizations.
    ///      If you don't want to hard-bind, you can leave them as zero and
    ///      skip those checks. Here we store them to be explicit/safe.
    address public expectedGrantor;
    address public expectedToken;

    event PulledViaPPO(address indexed grantor, address indexed grantee, address indexed token, uint256 amount);

    /// @param recurPullAddr    Address of the deployed RecurPullSafeV2 for this domain.
    /// @param grantorAllowed   (optional) The grantor wallet this adapter is meant to act for.
    /// @param tokenAllowed     (optional) The asset this adapter is meant to move.
    ///
    /// You can set these to address(0) if you truly want to allow any,
    /// but locking them in is safer for production because it prevents
    /// someone from reusing this adapter for a totally different grantor/token.
    constructor(address recurPullAddr, address grantorAllowed, address tokenAllowed) {
        recurPull = IRecurPullSafeV2(recurPullAddr);
        expectedGrantor = grantorAllowed;
        expectedToken = tokenAllowed;
    }

    /// @notice Execute one authorized pull on behalf of CrossNetworkRebalancer / SettlementMesh.
    ///
    /// @param auth   The signed Authorization from the grantor.
    ///               - auth.grantee is BOTH:
    ///                   * who must call recurPull.pull()
    ///                   * who receives the funds
    /// @param amount How much to move right now.
    ///
    /// Security gates:
    /// - Only `auth.grantee` can call this adapter (so attackers can't replay).
    /// - If `expectedGrantor` / `expectedToken` are set, auth.grantor and auth.token
    ///   must match them. That prevents someone from sneaking in an unrelated PPO.
    ///
    /// NOTE:
    /// We do NOT override destination here. Destination IS auth.grantee.
    /// That's just how RecurPullSafeV2 works. If you need dynamic receivers,
    /// use the FlowChannelHardened + EVMChannelAdapter path instead.
    function executeAuthorizedPullPPO(
        IRecurPullSafeV2.Authorization calldata auth,
        uint256 amount
    ) external {
        // Caller must be the grantee in the signed Authorization.
        // This matches the invariant enforced inside RecurPullSafeV2.pull().
        require(msg.sender == auth.grantee, "NOT_AUTH_GRANTEE");

        // Optional safety: ensure we're only moving the specific treasury/token
        // this adapter was deployed for.
        if (expectedGrantor != address(0)) {
            require(auth.grantor == expectedGrantor, "GRANTOR_MISMATCH");
        }
        if (expectedToken != address(0)) {
            require(auth.token == expectedToken, "TOKEN_MISMATCH");
        }

        // This will:
        // - check revocation via Consent Registry
        // - check time window / maxPerPull
        // - verify auth.signature against auth.grantor
        // - transfer token from grantor -> grantee (msg.sender)
        recurPull.pull(auth, amount);

        emit PulledViaPPO(auth.grantor, auth.grantee, auth.token, amount);
    }
}
