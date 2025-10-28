// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title EVMPPOAdapter
/// @notice RIP-004 / RIP-008 domain adapter for EVM domains that settle using
///         discrete, consented pulls via RecurPullSafeV2 (RIP-001 + RIP-002).
///
/// @dev
/// This adapter NEVER takes custody.
/// It forwards an already-signed Authorization (a PPO) into RecurPullSafeV2.
/// RecurPullSafeV2 then:
///   - verifies the grantor's signature (EOA or 1271),
///   - enforces time window + maxPerPull,
///   - checks Consent Registry for revocation,
///   - requires msg.sender == auth.grantee,
///   - transfers token grantor -> grantee directly,
///   - records the pull in the Consent Registry.
///
/// IMPORTANT MODEL DIFFERENCE vs the streaming/FlowChannel path:
/// - FlowChannelHardened (RIP-005) exposes `pull(channelId, to, amount)`, so the
///   router / mesh can choose where funds land on each call.
///
/// - RecurPullSafeV2 always pays `auth.grantee`. There is no override per call.
///   So for "cross-domain liquidity moves", the Authorization itself must already
///   point at the correct destination wallet for that domain (e.g. the settlement
///   wallet on that chain / custodian).
///
/// How this is normally wired:
/// - DomainDirectory for a PPO-style domain will map:
///     domainId -> { adapter = this adapter, destination = <ignored or just == that grantee> }
/// - CrossNetworkRebalancer won't pass a custom receiver; instead it will invoke
///   this adapter in a domain-specific branch / executor.
///
/// Security assumptions:
/// - Only the authorized grantee (the address that will receive funds) may call this adapter.
/// - Optionally, this adapter can be pinned to a specific grantor+token, to prevent
///   someone from using it for an unrelated Authorization.
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
    /// @dev Reverts if:
    ///   - revoked in Consent Registry,
    ///   - outside validAfter/validBefore,
    ///   - amount > maxPerPull,
    ///   - signature invalid,
    ///   - msg.sender != auth.grantee.
    /// On success, transfers `token` from `grantor` to `grantee` (msg.sender)
    /// and records the pull in the Consent Registry.
    function pull(
        Authorization calldata auth,
        uint256 amount
    ) external;
}

contract EVMPPOAdapter {
    /// @notice The RecurPullSafeV2 executor for this domain.
    IRecurPullSafeV2 public recurPull;

    /// @dev Optional binding: restrict this adapter to a specific (grantor, token)
    ///      so it *cannot* be abused to drain unrelated authorizations.
    ///      If either is zero, that dimension is considered "open".
    address public expectedGrantor;
    address public expectedToken;

    event PulledViaPPO(
        address indexed grantor,
        address indexed grantee,
        address indexed token,
        uint256 amount
    );

    /// @param recurPullAddr    Address of the deployed RecurPullSafeV2 for this domain.
    /// @param grantorAllowed   Optional: the grantor wallet this adapter is meant to act for.
    /// @param tokenAllowed     Optional: the ERC-20 asset this adapter is meant to move.
    ///
    /// You can set grantorAllowed/tokenAllowed to address(0) to allow "any", but
    /// locking them in is safer for production because it prevents someone from
    /// reusing this adapter for a totally different grantor/token.
    constructor(
        address recurPullAddr,
        address grantorAllowed,
        address tokenAllowed
    ) {
        recurPull = IRecurPullSafeV2(recurPullAddr);
        expectedGrantor = grantorAllowed;
        expectedToken = tokenAllowed;
    }

    /// @notice Execute one authorized pull using a signed PPO-style Authorization.
    ///
    /// @param auth   The signed Authorization from the grantor.
    ///               - auth.grantee is BOTH:
    ///                   * the only address allowed to call recurPull.pull()
    ///                   * the address that will receive the funds
    /// @param amount How much to move right now.
    ///
    /// Security gates (pre-checks before we forward the call):
    /// - msg.sender MUST equal auth.grantee (so nobody else can relay this).
    /// - If expectedGrantor / expectedToken are configured, auth.grantor /
    ///   auth.token must match them.
    /// - amount must be > 0.
    function executeAuthorizedPullPPO(
        IRecurPullSafeV2.Authorization calldata auth,
        uint256 amount
    ) external {
        require(amount > 0, "AMOUNT_0");
        require(auth.grantor != address(0), "BAD_GRANTOR");
        require(auth.grantee != address(0), "BAD_GRANTEE");

        // Caller must be the grantee in the signed Authorization.
        // This mirrors the invariant enforced inside RecurPullSafeV2.pull().
        require(msg.sender == auth.grantee, "NOT_AUTH_GRANTEE");

        // Optional safety rails: adapter-scoped grantor/token lock.
        if (expectedGrantor != address(0)) {
            require(auth.grantor == expectedGrantor, "GRANTOR_MISMATCH");
        }
        if (expectedToken != address(0)) {
            require(auth.token == expectedToken, "TOKEN_MISMATCH");
        }

        // Delegate to RecurPullSafeV2. This will:
        // - check revocation via Consent Registry
        // - enforce time window / maxPerPull
        // - verify signature against auth.grantor
        // - check msg.sender == auth.grantee (again)
        // - transfer token grantor -> grantee
        // - emit / record in Consent Registry
        recurPull.pull(auth, amount);

        emit PulledViaPPO(
            auth.grantor,
            auth.grantee,
            auth.token,
            amount
        );
    }
}
