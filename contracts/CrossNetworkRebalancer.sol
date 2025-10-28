// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @dev controller is expected to be the same Safe/multisig that operates
///      DomainDirectory, so that one ops key can halt routing end-to-end.
/// @title CrossNetworkRebalancer — RIP-004 reference executor
/// @notice Non-custodial liquidity coordinator that executes verified FlowIntents (RIP-003)
///         across domains without bridges, wrappers, pooled custody, or this contract
///         ever holding user funds.
///
/// High-level flow:
///   1. A FlowIntent (RIP-003) is signed off-chain by the grantor. It says:
///        "executor X may move up to maxTotal of token T from srcDomain → dstDomain
///         between validAfter and validBefore."
///   2. Caller (executor or controller multisig) calls executeFlowIntent(...) here,
///      providing:
///        - that FlowIntent,
///        - its signature,
///        - the PPO/channel authHash authorizing source-side movement,
///        - desired amount.
///   3. We enforce:
///        - caller authority (executor OR controller)
///        - executor approved in both src & dst domains
///        - PPO/channel auth (authHash) not revoked in ConsentRegistry (RIP-002)
///   4. We call FlowIntentRegistry.verifyAndConsume(...) to:
///        - verify the grantor's EIP-712 signature (EOA or 1271 SCW)
///        - enforce validity window
///        - enforce cumulative cap (maxTotal) and reserve this amount
///        - refuse if revoked
///   5. If registry approves, we pull funds directly from grantor → dstReceiver
///      using the source domain adapter. This contract never escrows funds.
///
/// TRUST SURFACE / RESPONSIBILITIES
/// - FlowIntentRegistry: signature validity, cap, expiry, replay, revocation.
/// - ConsentRegistry (RIP-002): underlying PPO / channel authHash must still be live.
/// - DomainDirectory: which executors are allowed in each domain, and
///   the canonical destination address for that domain.
/// - Source adapter (IRecurPullLike): actually executes the pull under RIP-001 / RIP-005,
///   enforcing per-call ceilings, timing windows, revocation, policy, etc.
///
/// CONTROLLER
/// - `controller` (Safe / governance) can batch or emergency-drive rebalancing
///   even if the named executor isn't the direct caller.
interface IFlowIntentRegistry {
    struct FlowIntent {
        address grantor;
        address executor;
        bytes32 srcDomain;
        bytes32 dstDomain;
        address token;
        uint256 maxTotal;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        bytes32 metadataHash;
    }

    /// @notice Verify + consume budget from a FlowIntent.
    /// @dev MUST revert if:
    ///      - signature invalid
    ///      - intent expired / not yet valid
    ///      - revoked
    ///      - cap exceeded
    ///      If it returns, it has already incremented internal accounting,
    ///      so the caller SHOULD proceed with execution.
    function verifyAndConsume(
        FlowIntent calldata i,
        bytes calldata signature,
        uint256 amountToMove
    ) external returns (bytes32 intentHash);
}

/// @notice Consent Registry (RIP-002).
/// Global source of truth for whether a PPO / channel authorization (authHash)
/// is still live.
interface IRecurConsentRegistry {
    function isRevoked(bytes32 authHash) external view returns (bool);
}

/// @notice DomainDirectory:
/// - Which executors are allowed to act in a given domain
/// - Where funds should be delivered in that destination domain
interface IDomainDirectory {
    function isApprovedExecutor(bytes32 domainId, address executor) external view returns (bool);
    function receiverOf(bytes32 domainId) external view returns (address);
}

/// @notice Source-side adapter interface.
/// The adapter runs in/for the *source* domain and actually does the transfer
/// (grantor -> final receiver) under an Authorization / PPO / FlowChannel.
///
/// It MUST:
///  - enforce per-call ceilings (maxPerPull),
///  - enforce timing windows,
///  - verify grantor signature / consent,
///  - respect revocation in the Consent Registry,
///  - and revert if paused/revoked/out-of-policy.
///
/// CrossNetworkRebalancer never touches funds; it just instructs this adapter.
interface IRecurPullLike {
    function pull(bytes32 authHash, address to, uint256 amount) external returns (bool ok);
}

/// @notice Full FlowIntent payload passed into executeFlowIntent().
/// Includes:
///  - authHash: hash of the lower-level PPO / channel authorization that
///              actually lets the adapter pull funds from the grantor.
///  - signature: the grantor's EIP-712 signature for the FlowIntent (RIP-003).
///
/// We down-convert this to IFlowIntentRegistry.FlowIntent before calling
/// verifyAndConsume(), because the registry doesn't need authHash.
struct FlowIntentFull {
    address grantor;
    address executor;
    bytes32 srcDomain;
    bytes32 dstDomain;
    address token;
    uint256 maxTotal;
    uint256 validAfter;
    uint256 validBefore;
    bytes32 nonce;
    bytes32 metadataHash;
    bytes32 authHash;   // PPO / channel authorization hash (RIP-001 / RIP-002 / RIP-005)
    bytes   signature;  // grantor signature over the FlowIntent terms above
}

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
        require(intentRegistry != address(0), "BAD_INTENT_REG");
        require(consentRegistry != address(0), "BAD_CONSENT_REG");
        require(domainDirectory != address(0), "BAD_DIRECTORY");
        require(initialController != address(0), "BAD_CTRL");

        intents = IFlowIntentRegistry(intentRegistry);
        consent = IRecurConsentRegistry(consentRegistry);
        directory = IDomainDirectory(domainDirectory);
        controller = initialController;
    }

    /// @notice Governance can rotate controller (Safe / emergency authority).
    function setController(address next) external onlyController {
        require(next != address(0), "BAD_CTRL");
        controller = next;
    }

    /// @notice Execute a portion of a FlowIntent.
    ///
    /// @param intentFull         The full FlowIntent payload (including authHash + signature).
    /// @param amount             How much to move in this step (> 0).
    /// @param sourcePullContract Address of the source-domain adapter that will actually
    ///                           perform the consented pull.
    ///
    /// Steps:
    ///   1. Check caller authority + domain approvals.
    ///   2. Check PPO/channel authHash still live (not revoked).
    ///   3. Call FlowIntentRegistry.verifyAndConsume() to:
    ///        - verify grantor signature (EOA or 1271)
    ///        - enforce time window
    ///        - enforce cumulative maxTotal and reserve this amount
    ///        - refuse if revoked/expired/out-of-cap
    ///      This returns a canonical intentHash.
    ///   4. Look up destination receiver from DomainDirectory.
    ///   5. Ask sourcePullContract to pull funds grantor -> receiver under that authHash.
    ///   6. Emit RebalanceExecuted.
    ///
    /// SECURITY:
    /// - This contract never escrows anything. Funds go directly from the
    ///   grantor's balance on the source domain to the approved receiver on
    ///   the destination domain.
    function executeFlowIntent(
        FlowIntentFull calldata intentFull,
        uint256 amount,
        address sourcePullContract
    ) external returns (bool ok) {
        require(amount > 0, "ZERO_AMOUNT");
        require(sourcePullContract != address(0), "BAD_SOURCE_ADAPTER");

        // ---------------------------------------------------------------------
        // 1. Caller authority + domain approval
        // ---------------------------------------------------------------------
        // Either the named executor calls directly, OR controller batches on their behalf.
        require(
            msg.sender == intentFull.executor || msg.sender == controller,
            "NOT_AUTHORIZED_CALLER"
        );

        // Executor must be approved in BOTH src and dst domains.
        require(
            directory.isApprovedExecutor(intentFull.srcDomain, intentFull.executor),
            "SRC_EXEC_FORBIDDEN"
        );
        require(
            directory.isApprovedExecutor(intentFull.dstDomain, intentFull.executor),
            "DST_EXEC_FORBIDDEN"
        );

        // ---------------------------------------------------------------------
        // 2. Underlying PPO / channel authorization still live
        // ---------------------------------------------------------------------
        // authHash is the RIP-001 / RIP-002 / RIP-005 identifier for actual pull authority.
        // If it's revoked, we bail out now.
        require(!consent.isRevoked(intentFull.authHash), "PPO_REVOKED");

        // ---------------------------------------------------------------------
        // 3. Verify + reserve in FlowIntentRegistry
        // ---------------------------------------------------------------------
        // Build the core struct expected by the registry (no authHash).
        IFlowIntentRegistry.FlowIntent memory core = IFlowIntentRegistry.FlowIntent({
            grantor:      intentFull.grantor,
            executor:     intentFull.executor,
            srcDomain:    intentFull.srcDomain,
            dstDomain:    intentFull.dstDomain,
            token:        intentFull.token,
            maxTotal:     intentFull.maxTotal,
            validAfter:   intentFull.validAfter,
            validBefore:  intentFull.validBefore,
            nonce:        intentFull.nonce,
            metadataHash: intentFull.metadataHash
        });

        // verifyAndConsume enforces:
        //  - signature (intentFull.signature)
        //  - validity window
        //  - revocation at the intent layer
        //  - cumulative cap (maxTotal)
        //  - and increments usage atomically
        bytes32 intentHash = intents.verifyAndConsume(
            core,
            intentFull.signature,
            amount
        );

        // ---------------------------------------------------------------------
        // 4. Destination receiver
        // ---------------------------------------------------------------------
        address dstReceiver = directory.receiverOf(intentFull.dstDomain);
        require(dstReceiver != address(0), "NO_DST_RECEIVER");

        // ---------------------------------------------------------------------
        // 5. Trigger the actual non-custodial pull on the source side.
        // ---------------------------------------------------------------------
        // The adapter MUST:
        //  - enforce per-call maxPerPull
        //  - enforce timing window / pause / revoke at channel/PPO level
        //  - perform ERC20.transferFrom(grantor -> dstReceiver)
        ok = IRecurPullLike(sourcePullContract).pull(
            intentFull.authHash,
            dstReceiver,
            amount
        );
        require(ok, "PULL_FAIL");

        // ---------------------------------------------------------------------
        // 6. Emit audit event
        // ---------------------------------------------------------------------
        emit RebalanceExecuted(
            intentHash,
            intentFull.srcDomain,
            intentFull.dstDomain,
            intentFull.token,
            amount,
            intentFull.executor
        );
    }
}
