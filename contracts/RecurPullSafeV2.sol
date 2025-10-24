// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Light interface to the Consent Registry (RIP-002).
interface IRecurConsentRegistry {
    function isRevoked(bytes32 authHash) external view returns (bool);

    function recordPull(
        bytes32 authHash,
        address token,
        address grantor,
        address grantee,
        uint256 amount
    ) external;
}

/// @title RecurPullSafeV2
/// @notice Reference executor for RIP-001 permissioned pull,
///         enforcing revocation via the Consent Registry (RIP-002).
/// @dev Flow:
///   1. Grantor signs an Authorization off-chain.
///   2. Grantee calls pull().
///   3. We verify timing / limit / revocation / signature stub.
///   4. We transfer directly from grantor to grantee via ERC20.transferFrom().
///   5. We log the pull in the Consent Registry for audit / analytics.
///
///   No custody. Grantor can revoke globally at any time.
contract RecurPullSafeV2 {

    struct Authorization {
        address grantor;     // wallet giving consent
        address grantee;     // wallet/agent allowed to pull
        address token;       // ERC-20 being pulled
        uint256 maxPerPull;  // per-call ceiling
        uint256 validAfter;  // earliest timestamp allowed
        uint256 validBefore; // latest timestamp allowed
        bytes32 nonce;       // unique salt
        bytes   signature;   // grantor's signature over this auth scope
    }

    IRecurConsentRegistry public registry;

    event PullExecutedDirect(
        bytes32 indexed authHash,
        address indexed token,
        address indexed grantor,
        address grantee,
        uint256 amount
    );

    constructor(address registryAddr) {
        registry = IRecurConsentRegistry(registryAddr);
    }

    /// @dev Compute canonical hash ID for this Authorization.
    ///      Must match RIP-002 derivation so wallets/indexers align.
    function authHashOf(Authorization calldata auth) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                auth.grantor,
                auth.grantee,
                auth.token,
                auth.maxPerPull,
                auth.validAfter,
                auth.validBefore,
                auth.nonce
            )
        );
    }

    /// @notice Execute a permissioned pull under a signed Authorization.
    /// @param auth   The signed Authorization.
    /// @param amount Requested amount for this call.
    function pull(
        Authorization calldata auth,
        uint256 amount
    ) external {
        bytes32 h = authHashOf(auth);

        // 1. revocation: grantor can globally kill future pulls
        require(!registry.isRevoked(h), "REVOKED");

        // 2. enforce that only the authorized grantee can pull
        require(msg.sender == auth.grantee, "NOT_AUTHORIZED");

        // 3. enforce timing guarantees
        require(block.timestamp >= auth.validAfter, "TOO_SOON");
        require(block.timestamp <= auth.validBefore, "EXPIRED");

        // 4. enforce per-call ceiling
        require(amount <= auth.maxPerPull, "LIMIT");

        // 5. signature check (placeholder stub)
        //    In audited version:
        //    - recover signer via ECDSA/EIP-712
        //    - require(signer == auth.grantor)
        require(_verifyGrantorSig(auth.grantor, h, auth.signature), "BAD_SIG");

        // 6. direct non-custodial transfer
        require(
            IERC20(auth.token).transferFrom(auth.grantor, auth.grantee, amount),
            "TRANSFER_FAIL"
        );

        // 7. local emit (for explorers / debugging)
        emit PullExecutedDirect(
            h,
            auth.token,
            auth.grantor,
            auth.grantee,
            amount
        );

        // 8. registry accounting + canonical events
        registry.recordPull(
            h,
            auth.token,
            auth.grantor,
            auth.grantee,
            amount
        );
    }

    // Signature verification placeholder.
    // We leave it stubbed so we don't pretend unaudited sig logic is production.
    function _verifyGrantorSig(
        address grantor,
        bytes32 authHash,
        bytes calldata signature
    ) internal pure returns (bool) {
        grantor; authHash; signature;
        return true;
    }
}
