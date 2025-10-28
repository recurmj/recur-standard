// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title DomainDirectory
/// @notice RIP-004 / RIP-008 governance registry for "domains"
///         (chains, L2 settlement vaults, custodians, internal treasuries).
///
/// Each domain is identified by a bytes32 ID, e.g.:
///   keccak256("ethereum:treasury")
///   keccak256("base:settlement")
///   keccak256("custodian:prime-broker-x")
///
/// This contract is the source of truth for:
///   - Which destination address (vault / receiver) is canonical for that domain.
///   - Which adapter contract (if any) should be used operationally to execute
///     a pull on behalf of that domain.
///   - Which executors are approved to act in that domain when driving
///     CrossNetworkRebalancer.
///   - Whether the domain is currently active (routable).
///
/// SECURITY MODEL
///  - `controller` (Safe / multisig / governance) is the only address allowed
///    to configure domains, approve executors, or rotate control.
///  - Setting active = false immediately offlines a domain for routing.
///  - CrossNetworkRebalancer:
///       1. checks isApprovedExecutor(srcDomain, intent.executor)
///          and isApprovedExecutor(dstDomain, intent.executor)
///       2. fetches receiverOf(dstDomain)
///
/// IMPORTANT:
///  - DomainDirectory NEVER moves funds.
///  - It's pure policy/metadata.
///
/// OPERATIONAL NOTE:
///  - When you "turn off" a domain by setting active=false,
///    you SHOULD also clear executor approvals for that domain (setExecutorApproval(..., false))
///    so even stale callers get denied.
contract DomainDirectory {
    /// -----------------------------------------------------------------------
    /// Data structures
    /// -----------------------------------------------------------------------

    struct DomainInfo {
        address adapter;        // domain's pull adapter (EVMPPOAdapter, FlowChannel adapter, etc.)
        address destination;    // canonical receiver / treasury / vault for this domain
        bool active;            // if false, domain is offline / not routable
    }

    /// domainId => DomainInfo
    mapping(bytes32 => DomainInfo) public domains;

    /// domainId => executor => approved?
    mapping(bytes32 => mapping(address => bool)) public approvedExecutor;

    /// Governance controller (Safe / multisig).
    address public controller;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event ControllerUpdated(address indexed newController);

    event DomainSet(
        bytes32 indexed id,
        address adapter,
        address destination,
        bool active
    );

    event ExecutorApproval(
        bytes32 indexed id,
        address indexed executor,
        bool approved
    );

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    modifier onlyController() {
        require(msg.sender == controller, "NOT_CONTROLLER");
        _;
    }

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @param initialController governance address (usually a Safe / multisig)
    constructor(address initialController) {
        require(initialController != address(0), "BAD_CTRL");
        controller = initialController;
    }

    /// -----------------------------------------------------------------------
    /// Admin / governance functions
    /// -----------------------------------------------------------------------

    /// @notice Rotate governance / control authority.
    /// @param newController The address that will take over configuration rights.
    function setController(address newController) external onlyController {
        require(newController != address(0), "BAD_CTRL");
        controller = newController;
        emit ControllerUpdated(newController);
    }

    /// @notice Register or update a domain entry.
    /// @param id          bytes32 identifier for the domain (e.g. keccak256("base:settlement"))
    /// @param adapter     Adapter contract for that domain. If `active` is true,
    ///                    this MUST NOT be address(0).
    /// @param destination Canonical receiver for that domain. If `active` is true,
    ///                    this MUST NOT be address(0).
    /// @param active      Whether this domain should currently be treated as routable.
    ///
    /// SETTING active = false:
    ///  - Immediately "offlines" the domain for routing / receiving.
    ///  - CrossNetworkRebalancer will effectively refuse to route there because
    ///    isApprovedExecutor() will return false (it checks .active).
    function setDomain(
        bytes32 id,
        address adapter,
        address destination,
        bool active
    ) external onlyController {
        if (active) {
            require(adapter != address(0), "BAD_ADAPTER");
            require(destination != address(0), "BAD_DEST");
        }

        domains[id] = DomainInfo({
            adapter: adapter,
            destination: destination,
            active: active
        });

        emit DomainSet(id, adapter, destination, active);
    }

    /// @notice Approve or revoke an executor for a given domain.
    /// @dev CrossNetworkRebalancer checks this before allowing an executor
    ///      to act in srcDomain or dstDomain for a FlowIntent.
    function setExecutorApproval(
        bytes32 id,
        address executor,
        bool approved
    ) external onlyController {
        approvedExecutor[id][executor] = approved;
        emit ExecutorApproval(id, executor, approved);
    }

    /// -----------------------------------------------------------------------
    /// Views consumed by CrossNetworkRebalancer / monitoring
    /// -----------------------------------------------------------------------

    /// @notice Returns true if `executor` is currently approved to operate in `domainId`
    ///         AND the domain is active.
    function isApprovedExecutor(
        bytes32 domainId,
        address executor
    ) external view returns (bool) {
        DomainInfo memory info = domains[domainId];
        if (!info.active) {
            return false;
        }
        return approvedExecutor[domainId][executor];
    }

    /// @notice Canonical receiver / vault / treasury address for the given domain.
    /// @dev CrossNetworkRebalancer delivers funds here on the destination side.
    function receiverOf(bytes32 domainId) external view returns (address) {
        return domains[domainId].destination;
    }

    /// @notice Adapter contract for the domain.
    /// @dev Optional operational getter. Current CrossNetworkRebalancer version
    ///      takes the adapter address directly as an argument, but infra/off-chain
    ///      orchestration tooling inspects this.
    function adapterOf(bytes32 domainId) external view returns (address) {
        return domains[domainId].adapter;
    }

    /// @notice Full tuple for explorers / dashboards.
    function domainInfo(bytes32 domainId) external view returns (
        address adapter,
        address destination,
        bool active
    ) {
        DomainInfo memory info = domains[domainId];
        return (info.adapter, info.destination, info.active);
    }
}
