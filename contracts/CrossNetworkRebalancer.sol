// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title CrossNetworkRebalancer — RIP-004 reference
/// @notice Non-custodial executor that fulfills a Flow Intent (RIP-003) across domains
///         by triggering permissioned pulls under revocable consent,
///         instead of bridging, wrapping, or taking custody.
/// @dev This contract never holds funds. It only coordinates allowed movement.
///      Controller should be a Safe / multisig in production.

/// @notice Minimal interface for the FlowIntentRegistry (RIP-003).
/// Tracks whether an intent is revoked and how much has already been executed.
interface IFlowIntentRegistry {
    function isRevoked(bytes32 intentHash) external view returns (bool);
    function consumed(bytes32 intentHash) external view returns (uint256);
    function recordExecution(bytes32 intentHash, uint256 amount) external;
}

/// @notice Minimal interface for the Consent Registry (RIP-002).
/// Used to confirm that the underlying pull authorization (PPO) is still live.
interface IRecurConsentRegistry {
    function isRevoked(bytes32 authHash) external view returns (bool);
}

/// @notice DomainDirectory exposes routing metadata for domains like
/// "ethereum:treasury", "base:settlement", "custodian:x".
/// It answers:
///  - Is this executor actually allowed to act in this domain?
///  - Where should funds land for this domain?
interface IDomainDirectory {
    function isApprovedExecutor(bytes32 domainId, address executor) external view returns (bool);
    function receiverOf(bytes32 domainId) external view returns (address);
}

/// @notice Minimal pull surface compatible with RIP-001 / RecurPullSafeV2.
/// The executor calls pull() on the source side under grantor consent.
/// The contract itself enforces signature validity, revocation, caps, etc.
interface IRecurPullLike {
    function pull(bytes32 authHash, uint256 amount) external returns (bool ok);
}

/// @notice A FlowIntent is the signed instruction (RIP-003) describing
/// "move up to maxAmount of token from srcDomain to dstDomain before validBefore,
/// and only executor X is allowed to do it."
///
/// We assume the off-chain signer (grantor) produced this and it was registered
/// in a FlowIntentRegistry that can give us canonical state.
///
/// For simplicity, we pass it in as a struct here instead of bytes.
/// In a hardened version, you'd pass the full EIP-712 payload + signature
/// and verify it on-chain.
struct FlowIntent {
    address grantor;        // owner of the liquidity
    address executor;       // who is allowed to act on this intent
    address token;          // asset to move
    bytes32 srcDomain;      // domain where funds currently sit
    bytes32 dstDomain;      // domain where funds should land
    uint256 maxAmount;      // cap (total) authorized under this intent
    uint256 validBefore;    // expiry timestamp
    uint256 nonce;          // uniqueness / replay isolation
    bytes32 authHash;       // underlying PPO / pull authorization hash
    bytes   signature;      // grantor signature over the FlowIntent (EIP-712)
}

/// @notice CrossNetworkRebalancer enforces FlowIntent + registry state.
/// It does two main checks before attempting movement:
///  1. The FlowIntent is still valid (not revoked, not expired, not over cap).
///  2. The executor is allowed to act in both the source and destination domains.
///
/// If those hold, it triggers a permissioned pull from the source domain
/// (under the grantor's PPO / authHash) directly into the destination's receiver.
///
/// The Rebalancer never escrows funds. Movement is direct:
///    grantor/source -> approved receiver/destination
contract CrossNetworkRebalancer {
    IFlowIntentRegistry public intents;
    IRecurConsentRegistry public consent;
    IDomainDirectory public directory;
    address public controller;

    /// @notice Emitted when we successfully execute part of a FlowIntent.
    event RebalanceExecuted(
        bytes32 indexed intentHash,
        bytes32 indexed srcDomain,
        bytes32 indexed dstDomain,
        address token,
        uint256 amount,
        address executor
    );

    modifier onlyController() {
        require(msg.sender == controller, "not controller");
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

    /// @notice Controller (Safe / governance) can update control.
    function setController(address next) external onlyController {
        controller = next;
    }

    /// @notice Execute part of a FlowIntent, moving `amount` toward dstDomain.
    /// @dev In hardened form:
    ///  - verify FlowIntent.signature via EIP-712
    ///  - check chain/domain binding for src/dst
    ///  - restrict callable roles (e.g. only the named executor, or onlyController driving batches)
    ///
    /// @param intent the FlowIntent (RIP-003) describing desired cross-domain move
    /// @param amount how much to attempt to move in this step
    /// @param sourcePullContract address of the RecurPull-like contract in the source domain
    function executeFlowIntent(
        FlowIntent calldata intent,
        uint256 amount,
        address sourcePullContract
    ) external returns (bool ok) {
        // 1. basic validity checks against intent registry ------------------

        bytes32 intentHash = keccak256(
            abi.encode(
                intent.grantor,
                intent.executor,
                intent.token,
                intent.srcDomain,
                intent.dstDomain,
                intent.maxAmount,
                intent.validBefore,
                intent.nonce
            )
        );

        require(!intents.isRevoked(intentHash), "intent revoked");
        require(block.timestamp <= intent.validBefore, "intent expired");

        // Cap enforcement: don't exceed maxAmount across all executions.
        uint256 used = intents.consumed(intentHash);
        require(used + amount <= intent.maxAmount, "cap exceeded");

        // 2. executor permissions ------------------------------------------

        // Only the authorized executor may trigger this intent,
        // OR governance may batch-call on their behalf (optional).
        require(
            msg.sender == intent.executor || msg.sender == controller,
            "not authorized executor"
        );

        // The executor (or controller) must be approved for BOTH src and dst domains.
        require(
            directory.isApprovedExecutor(intent.srcDomain, intent.executor),
            "src domain no exec"
        );
        require(
            directory.isApprovedExecutor(intent.dstDomain, intent.executor),
            "dst domain no exec"
        );

        // 3. underlying consent (PPO / authHash) still live ----------------

        // authHash is the RIP-001/RIP-002 identifier of the permissioned pull.
        // If it's revoked at the Consent Registry layer, we refuse to act.
        require(!consent.isRevoked(intent.authHash), "pull auth revoked");

        // 4. figure out destination receiver for dstDomain -----------------

        address dstReceiver = directory.receiverOf(intent.dstDomain);
        require(dstReceiver != address(0), "no dst receiver");

        // 5. actually perform the pull on the source domain ----------------
        //
        // Assumption:
        // - sourcePullContract is deployed on (or bound to) the source domain
        // - calling pull() there moves funds from grantor toward dstReceiver
        //   under the grantor's PPO (authHash)
        //
        // NOTE: This call is *non-custodial*. We never receive the funds here.
        ok = IRecurPullLike(sourcePullContract).pull(
            intent.authHash,
            amount
        );

        require(ok, "pull failed");

        // 6. accounting / emit ---------------------------------------------

        // Record consumption so we can't replay forever.
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
