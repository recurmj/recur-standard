// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title DomainDirectory
/// @notice RIP-004 / RIP-008 helper. Maps logical domain IDs (L1, L2, custodian,
///         venue bucket, etc.) to an adapter contract and a destination address.
/// @dev
/// - CrossNetworkRebalancer asks this contract:
///      • "For srcDomain, which adapter should I call to perform the pull?"
///      • "For dstDomain, where should the funds land?"
///
/// - Each domain is identified by a bytes32 ID (e.g. keccak256("ethereum:treasury")).
/// - `adapter` is expected to be something like an EVMPPOAdapter or other domain-
///   specific executor that can actually trigger a permissioned pull under consent.
/// - `destination` is the canonical receiver account / vault for that domain.
///
/// Security model:
/// - `controller` (a Safe / governance address) is the only address allowed to
///   register or update domains and to rotate control.
/// - Setting `active = false` is the fastest way to freeze routing into/out of
///   a domain without touching every upstream contract.
///
/// NOTE:
/// - We do not try to solve "is this executor allowed?" at the directory layer
///   in this minimal version. That can be enforced in the adapter itself and/or
///   by only letting controller-driven code call CrossNetworkRebalancer.
contract DomainDirectory {
    struct DomainInfo {
        address adapter;      // contract that can execute authorized pulls for this domain
        address destination;  // receiver / treasury / vault on that domain
        bool active;          // if false, Rebalancer should treat this domain as offline
    }

    mapping(bytes32 => DomainInfo) public domains;

    address public controller;

    event ControllerUpdated(address indexed newController);

    event DomainSet(
        bytes32 indexed id,
        address adapter,
        address destination,
        bool active
    );

    modifier onlyController() {
        require(msg.sender == controller, "NOT_CONTROLLER");
        _;
    }

    constructor(address initialController) {
        controller = initialController;
    }

    /// @notice Rotate governance / control authority.
    /// @param newController The address (e.g. Safe) that will control this directory.
    function setController(address newController) external onlyController {
        controller = newController;
        emit ControllerUpdated(newController);
    }

    /// @notice Register or update a domain entry.
    /// @param id          bytes32 identifier for the domain (e.g. keccak256("base:settlement"))
    /// @param adapter     Adapter contract for that domain. Must not be zero if `active` = true.
    /// @param destination Canonical receiver for that domain. Must not be zero if `active` = true.
    /// @param active      Whether this domain is currently routable.
    /// @dev
    /// - CrossNetworkRebalancer will read this to decide:
    ///    • which adapter to call to initiate the pull on the source side, and
    ///    • which destination address to send funds to on the target side.
    ///
    /// - Setting `active = false` effectively offlines the domain for routing.
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
}
