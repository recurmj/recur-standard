// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurRelay (RIP-003 draft)
/// @notice Minimal consent-status relay for cross-network liquidity coordination.
/// @dev This contract does NOT custody assets and does NOT move funds.
///      It only stores/verifies consent state for a given authHash as reported
///      by an approved reporter. Destination-chain pull contracts MAY query
///      this contract before allowing a pull() under RIP-001.
///
///      Status pushed here is considered advisory / safety info,
///      not execution authority.
contract RecurRelay {
    /// @dev A consent "snapshot" for one authorization (authHash) as observed on some origin chain.
    struct ConsentStatus {
        address grantor;        // wallet / treasury that granted the pull right
        address grantee;        // address allowed to pull
        uint256 chainId;        // source chain the status refers to
        bool revoked;           // whether this authHash is considered revoked there
        uint256 pulledTotal;    // cumulative amount already pulled under that authHash
        uint256 cap;            // maxTotal cap (0 if not tracked / unknown)
        uint256 timestamp;      // when this snapshot was last updated in this contract
    }

    /// @dev authHash => latest known status
    mapping(bytes32 => ConsentStatus) public statusOf;

    /// @dev simple reporter role; in a mature version this could be
    ///      a multisig, bonded relayer, zk-light-client, etc.
    mapping(address => bool) public isReporter;

    event ReporterUpdated(address indexed reporter, bool allowed);

    event ConsentStatusRelayed(
        bytes32 indexed authHash,
        address indexed grantor,
        address indexed grantee,
        uint256 chainId,
        bool revoked,
        uint256 pulledTotal,
        uint256 cap,
        uint256 timestamp
    );

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyReporter() {
        require(isReporter[msg.sender], "not reporter");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Owner can add/remove approved reporters.
    function setReporter(address reporter, bool allowed) external onlyOwner {
        isReporter[reporter] = allowed;
        emit ReporterUpdated(reporter, allowed);
    }

    /// @notice Reporter posts the latest observed consent status for a given authHash.
    /// @dev In future this SHOULD include a proof field (Merkle / signature bundle).
    function relayConsentStatus(
        bytes32 authHash,
        address grantor,
        address grantee,
        uint256 chainId,
        bool revoked,
        uint256 pulledTotal,
        uint256 cap
    ) external onlyReporter {
        ConsentStatus memory snap = ConsentStatus({
            grantor: grantor,
            grantee: grantee,
            chainId: chainId,
            revoked: revoked,
            pulledTotal: pulledTotal,
            cap: cap,
            timestamp: block.timestamp
        });

        statusOf[authHash] = snap;

        emit ConsentStatusRelayed(
            authHash,
            grantor,
            grantee,
            chainId,
            revoked,
            pulledTotal,
            cap,
            block.timestamp
        );
    }

    /// @notice View helper for downstream pull executors on this chain.
    /// @dev A destination-chain RecurPull variant MAY call this before allowing a pull,
    ///      if it wants to enforce cross-chain caps or global revocation.
    function getStatus(bytes32 authHash) external view returns (ConsentStatus memory) {
        return statusOf[authHash];
    }
}