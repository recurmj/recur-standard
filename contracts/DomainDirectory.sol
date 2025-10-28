// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title DomainDirectory — maps domain IDs to adapters and destination addresses.
/// @notice Used by CrossNetworkRebalancer (RIP-004) to resolve src/dst domains.
contract DomainDirectory {
    struct DomainInfo {
        address adapter;     // contract that can executeAuthorizedPull() for this domain
        address destination; // receiver/treasury/vault on that domain
        bool active;
    }

    mapping(bytes32 => DomainInfo) public domains;

    address public controller;

    event ControllerUpdated(address indexed newController);
    event DomainSet(bytes32 indexed id, address adapter, address destination, bool active);

    modifier onlyController() {
        require(msg.sender == controller, "not controller");
        _;
    }

    constructor(address initialController) {
        controller = initialController;
    }

    function setController(address newController) external onlyController {
        controller = newController;
        emit ControllerUpdated(newController);
    }

    function setDomain(bytes32 id, address adapter, address destination, bool active) external onlyController {
        domains[id] = DomainInfo({
            adapter: adapter,
            destination: destination,
            active: active
        });
        emit DomainSet(id, adapter, destination, active);
    }
}