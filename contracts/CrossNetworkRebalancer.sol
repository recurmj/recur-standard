// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title CrossNetworkRebalancer
/// @notice RIP-004 reference executor. Moves liquidity across "domains"
///         (chains, L2s, custodians, treasuries) without bridging, wrapping,
///         pooled custody, or holding funds.
/// @dev
/// - This contract NEVER escrows funds. It only coordinates authorized pulls
///   under revocable consent.
/// - A FlowIntent (RIP-003) says:
///       "executor X may move up to maxTotal of token
///        from srcDomain to dstDomain before validBefore."
/// - CrossNetworkRebalancer checks that intent is still valid,
///   checks executor permissions in both domains,
///   checks the underlying pull authorization (PPO / authHash) is still live,
///   then instructs a source-domain pull adapter to move funds
///   directly from the grantor toward the destination receiver.
///
/// Important trust points:
/// - FlowIntentRegistry is assumed to have already verified the grantor's
///   EIP-712 signature for this intent and registered it.
/// - DomainDirectory encodes who is allowed to act in a domain
///   and where funds should land in that domain.
/// - The source pull adapter (IRecurPullLike) is assumed to enforce
///   the lower-level Permissioned Pull Object (PPO) rules:
///   signature validity, per-call ceiling (maxPerPull),
///   time window, revocation, etc.
/// - The Consent Registry (RIP-002) must reflect PPO revocation in real time.
/// - `controller` is a Safe / multisig that can batch-call or rotate control.
///
/// This contract is deliberately scoped and auditable:
/// no custody, no wrapping. It is a trigger, not a bridge.

/// @notice FlowIntentRegistry (RIP-003)
/// Tracks whether an intent is revoked, how much has been consumed,
/// and records new executions. Also expected to have validated the
/// grantor's signature off-chain or at registration time.
interface IFlowIntentRegistry {
    function isRevoked(bytes32 intentHash) external view returns (bool);
    function consumed(bytes32 intentHash) external view returns (uint256);
    function recordExecution(bytes32 intentHash, uint256 amount) external;
}

/// @notice Consent Registry (RIP-002)
/// Global source of truth for whether the underlying PPO / Authorization
/// (referred to by authHash) is still valid.
interface IRecurConsentRegistry {
    function isRevoked(bytes32 authHash) external view returns (bool);
}

/// @notice DomainDirectory links abstract "domains" (like "ethereum:treasury"
/// or "base:settlement" or "custodian:x") to:
///  - which executors are permitted to act there
///  - which address is the designated receiver in that domain
interface IDomainDirectory {
    function isApprovedExecutor(bytes32 domainId, address executor) external view returns (bool);
    function receiverOf(bytes32 domainId) external view returns (address);
}

/// @notice Source-side pull adapter interface.
/// This adapter sits in the source domain and actually performs the consented pull
/// under RIP-001 / RecurPullSafeV2 semantics. It MUST:
///   - enforce the PPO's per-call ceiling (maxPerPull),
///   - enforce PPO timing window,
///   - verify PPO signature,
///   - check registry revocation,
///   - and transfer directly from the grantor to `to`.
///
/// CrossNetworkRebalancer never takes custody; it just asks this adapter to act.
interface IRecurPullLike {
    function pull(
        bytes32 authHash,
        address to,
        uint256 amount
    ) external returns (bool ok);
}

/// @notice FlowIntent (RIP-003 core object, projected here)
/// Describes cross-domain target movement under explicit grantor consent.
/// We assume FlowIntentRegistry has already verified its EIP-712 signature
/// from `grantor` and registered the canonical parameters.
struct FlowIntent {
    address grantor;        // owner of the liquidity / signer of the intent
    address executor;       // who is authorized to act on this intent
    address token;          // asset being rebalanced
    bytes32 srcDomain;      // where funds are coming from
    bytes32 dstDomain;      // where funds should land
    uint256 maxTotal;       // TOTAL cap (all executions combined) under this intent
    uint256 validBefore;    // expiry timestamp
    uint256 nonce;          // uniqueness / replay isolation
    bytes32 authHash;       // PPO / pull authorization hash for the source funds
    bytes   signature;      // grantor signature (not rechecked here; registry is source of truth)
}

/// @title CrossNetworkRebalancer
/// @dev This contract enforces:
///  1. intent not revoked, not expired
///  2. total usage so far + this amount <= maxTotal
///  3. caller is authorized (executor or controller)
///  4. executor is approved in BOTH src & dst domains
///  5. underlying pull authorization (authHash) is still live
///  6. destination receiver for dstDomain is known and nonzero
///  7. source-side pull adapter successfully moved funds DIRECTLY to that receiver
///
/// If all checks pass, we record usage in FlowIntentRegistry and emit.
contract CrossNetworkRebalancer {
    IFlowIntentRegistry public intents;
    IRecurConsentRegistry public consent;
    IDomainDirectory public directory;
    address public controller; // governance / Safe / multisig

    event RebalanceExecuted(
        bytes32 indexed intentHash,
        bytes32 indexed srcDomain,
        bytes32 indexed dstDomain,
        address token,
        uint256 amount,
        address executor
    );

    modifier onlyController() {
        require(msg.sender == controller, "NOT_CONTROLLER");
        _;
    }

    constructor(
        address intentRegistry,
        address consentRegistry,
        address domainDirectory,
        address initialController
    ) {
        intents = IFlowIntentRegistry(intentRegistry);
        consent = IRecurConsentRegistry(consentRegistry);
        directory = IDomainDirectory(domainDirectory);
        controller = initialController;
    }

    function setController(address next) external onlyController {
        controller = next;
    }

    /// @notice Execute part of a FlowIntent, moving `amount` of liquidity from
    ///         `intent.srcDomain` toward `intent.dstDomain`.
    /// @param intent Full FlowIntent struct. MUST match what FlowIntentRegistry
    ///               registered under its hash.
    /// @param amount Amount to attempt this step. Must be > 0.
    /// @param sourcePullContract Address of the source-domain pull adapter
    ///        (IRecurPullLike). That adapter actually executes the consented pull
    ///        under the PPO identified by `authHash`.
    ///
    /// Security expectations:
    /// - FlowIntentRegistry already validated the grantor's signature and
    ///   stored this intent.
    /// - recordExecution() in that registry MUST be access-controlled so only
    ///   this contract / controller can increment usage (to prevent spoofing).
    function executeFlowIntent(
        FlowIntent calldata intent,
        uint256 amount,
        address sourcePullContract
    ) external returns (bool ok) {
        require(amount > 0, "ZERO_AMOUNT");

        // 1. Canonical intent hash (must match FlowIntentRegistry derivation)
        bytes32 intentHash = keccak256(
            abi.encode(
                intent.grantor,
                intent.executor,
                intent.token,
                intent.srcDomain,
                intent.dstDomain,
                intent.maxTotal,
                intent.validBefore,
                intent.nonce
            )
        );

        // Intent must be live.
        require(!intents.isRevoked(intentHash), "INTENT_REVOKED");
        require(block.timestamp <= intent.validBefore, "INTENT_EXPIRED");

        // Enforce total cap across all executions.
        uint256 used = intents.consumed(intentHash);
        require(used + amount <= intent.maxTotal, "CAP_EXCEEDED");

        // 2. Caller authority
        // Either the named executor calls directly, OR controller batches on their behalf.
        require(
            msg.sender == intent.executor || msg.sender == controller,
            "NOT_AUTHORIZED_EXECUTOR"
        );

        // Executor must be approved for BOTH src and dst domains.
        require(
            directory.isApprovedExecutor(intent.srcDomain, intent.executor),
            "SRC_EXEC_FORBIDDEN"
        );
        require(
            directory.isApprovedExecutor(intent.dstDomain, intent.executor),
            "DST_EXEC_FORBIDDEN"
        );

        // 3. Underlying PPO / pull auth must still be live (RIP-002 revocation check)
        require(!consent.isRevoked(intent.authHash), "PPO_REVOKED");

        // 4. Destination receiver for dstDomain
        address dstReceiver = directory.receiverOf(intent.dstDomain);
        require(dstReceiver != address(0), "NO_DST_RECEIVER");

        // 5. Perform the actual non-custodial pull on the source side.
        //    The adapter enforces per-call maxPerPull, timing, sig validity, etc.
        ok = IRecurPullLike(sourcePullContract).pull(
            intent.authHash,
            dstReceiver,
            amount
        );
        require(ok, "PULL_FAIL");

        // 6. Record usage and emit.
        intents.recordExecution(intentHash, amount);

        emit RebalanceExecuted(
            intentHash,
            intent.srcDomain,
            intent.dstDomain,
            intent.token,
            amount,
            intent.executor
        );
    }
}
