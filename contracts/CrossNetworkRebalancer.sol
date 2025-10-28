// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title CrossNetworkRebalancer — RIP-004 reference executor
/// @notice Non-custodial liquidity coordinator that executes verified FlowIntents (RIP-003)
///         across domains without bridges or pooled custody.
///
/// Model:
///   1. A FlowIntent (RIP-003) is signed off-chain by the grantor.
///   2. CrossNetworkRebalancer calls FlowIntentRegistry.verifyAndConsume()
///      to validate signature, cap, window, and mark usage.
///   3. If valid, it triggers a pull on the source domain adapter,
///      which moves funds grantor → destination receiver directly.
///
/// SECURITY:
///   - Never holds tokens.
///   - Fully bound by registries:
///       * FlowIntentRegistry enforces signature, caps, revocation.
///       * ConsentRegistry enforces PPO validity (RIP-002).
///       * DomainDirectory defines which executors are approved where.
///   - Controller (multisig/governance) may batch or emergency-stop.
///
/// Trust surface:
///   - Source-side adapter (RecurPullSafeV2 or FlowChannelHardened)
///     must itself enforce PPO or channel-level rules.
///   - Destination receiver is set in DomainDirectory for that domain.
interface IFlowIntentRegistry {
    function verifyAndConsume(
        // RIP-003 FlowIntent struct
        (
            address grantor,
            address executor,
            bytes32 srcDomain,
            bytes32 dstDomain,
            address token,
            uint256 maxAmount,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce,
            bytes32 metadataHash
        ) calldata intent,
        bytes calldata signature,
        uint256 amount
    ) external returns (bytes32 intentHash);
}

interface IRecurConsentRegistry {
    function isRevoked(bytes32 authHash) external view returns (bool);
}

interface IDomainDirectory {
    function isApprovedExecutor(bytes32 domainId, address executor) external view returns (bool);
    function receiverOf(bytes32 domainId) external view returns (address);
}

interface IRecurPullLike {
    function pull(bytes32 authHash, address to, uint256 amount) external returns (bool ok);
}

/// @notice Minimal local projection of FlowIntent (matches RIP-003 registry struct)
struct FlowIntent {
    address grantor;
    address executor;
    bytes32 srcDomain;
    bytes32 dstDomain;
    address token;
    uint256 maxAmount;
    uint256 validAfter;
    uint256 validBefore;
    bytes32 nonce;
    bytes32 metadataHash;
    bytes32 authHash;   // underlying PPO / channel auth
    bytes   signature;  // grantor signature
}

contract CrossNetworkRebalancer {
    IFlowIntentRegistry public intents;
    IRecurConsentRegistry public consent;
    IDomainDirectory public directory;
    address public controller;

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

    /// @notice Execute a portion of a verified FlowIntent.
    /// @param intent   The full FlowIntent struct (as signed by grantor).
    /// @param amount   How much to move this step.
    /// @param sourcePullContract Address of the source-domain adapter implementing IRecurPullLike.
    ///
    /// Steps:
    ///   1. Verify & consume via FlowIntentRegistry (signature, window, cap, etc).
    ///   2. Check PPO (authHash) not revoked in ConsentRegistry.
    ///   3. Check executor authority + domain approvals.
    ///   4. Fetch destination receiver from DomainDirectory.
    ///   5. Instruct source adapter to pull grantor→receiver.
    function executeFlowIntent(
        FlowIntent calldata intent,
        uint256 amount,
        address sourcePullContract
    ) external returns (bool ok) {
        require(amount > 0, "ZERO_AMOUNT");

        // 1. Verify + reserve in registry (enforces cap/time/sig).
        bytes32 intentHash = intents.verifyAndConsume(
            (
                intent.grantor,
                intent.executor,
                intent.srcDomain,
                intent.dstDomain,
                intent.token,
                intent.maxAmount,
                intent.validAfter,
                intent.validBefore,
                intent.nonce,
                intent.metadataHash
            ),
            intent.signature,
            amount
        );

        // 2. PPO authorization (RIP-002)
        require(!consent.isRevoked(intent.authHash), "PPO_REVOKED");

        // 3. Executor or controller must call; executor must be approved in both domains.
        require(
            msg.sender == intent.executor || msg.sender == controller,
            "NOT_AUTHORIZED_EXECUTOR"
        );
        require(
            directory.isApprovedExecutor(intent.srcDomain, intent.executor),
            "SRC_EXEC_FORBIDDEN"
        );
        require(
            directory.isApprovedExecutor(intent.dstDomain, intent.executor),
            "DST_EXEC_FORBIDDEN"
        );

        // 4. Destination receiver.
        address dstReceiver = directory.receiverOf(intent.dstDomain);
        require(dstReceiver != address(0), "NO_DST_RECEIVER");

        // 5. Trigger the source-domain pull.
        ok = IRecurPullLike(sourcePullContract).pull(
            intent.authHash,
            dstReceiver,
            amount
        );
        require(ok, "PULL_FAIL");

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
