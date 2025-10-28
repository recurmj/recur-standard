/// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @notice Minimal ERC-20 interface for pull-based transfers.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Light interface to the Consent Registry (RIP-002).
/// The registry is the global source of truth for revocation and cumulative accounting.
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

/// @notice Smart contract wallet signature validator (EIP-1271-style).
/// If grantor is a contract, we call isValidSignature(hash, sig) and expect 0x1626ba7e.
interface IEIP1271 {
    function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4 magicValue);
}

/// @title RecurPullSafeV2
/// @notice RIP-001 executor with registry integration (RIP-002), EIP-712 signatures,
///         and EIP-1271 smart wallet support.
/// @dev
/// Flow:
///   1. Grantor signs an Authorization off-chain (EIP-712).
///   2. Grantee calls pull(auth, amount).
///   3. Contract:
///        - checks revocation via Consent Registry
///        - enforces time window + per-call limit
///        - verifies signature matches grantor (EOA or smart wallet)
///        - transfers directly from grantor -> grantee (non-custodial)
///        - records the pull in the Consent Registry
///
/// Security properties:
///   - Grantor can revoke globally at any time via the registry.
///   - Grantee cannot exceed maxPerPull in a single call.
///   - Outside validAfter/validBefore is rejected.
///   - Signature is bound to this specific contract + chainId via EIP-712 domain.
///   - If the grantor is a smart contract wallet, we respect EIP-1271.
///
/// IMPORTANT MODEL NOTE:
///   This contract enforces *per-call* ceilings (maxPerPull) and timing windows.
///   It does NOT track cumulative spend or mark an Authorization as "used".
///   The assumption is:
///     - Repeated pulls are allowed until the grantor revokes in the registry,
///       or higher-level policy (FlowChannel / PolicyEnforcer / Mesh) cuts it off,
///       or allowance runs out.
///   That is intentional. Global rate / budget enforcement lives in RIP-005/006/007.
///
/// IMPLEMENTATION NOTES:
///   - Grantor MUST have given this contract allowance on auth.token
///     (or you front-run a permit() flow externally).
///   - IERC20 here is minimal; non-standard ERC-20s may require SafeERC20 wrappers
///     in downstream forks.
///   - `registryAddr` in the constructor MUST be a trusted Consent Registry
///     deployment on this chain.
///
/// This contract is suitable to publish as "production reference" for RIP-001+RIP-002.
contract RecurPullSafeV2 {
    /// -----------------------------------------------------------------------
    /// Authorization struct
    /// -----------------------------------------------------------------------

    struct Authorization {
        address grantor;      // wallet giving consent
        address grantee;      // wallet/agent allowed to pull
        address token;        // ERC-20 being pulled
        uint256 maxPerPull;   // per-call ceiling
        uint256 validAfter;   // earliest timestamp allowed
        uint256 validBefore;  // latest timestamp allowed
        bytes32 nonce;        // unique salt (prevents collisions)
        bytes   signature;    // grantor's signature over this auth scope
    }

    /// -----------------------------------------------------------------------
    /// Immutable storage
    /// -----------------------------------------------------------------------

    IRecurConsentRegistry public immutable registry;

    // EIP-712 domain separator, precomputed once at deploy.
    bytes32 private immutable _DOMAIN_SEPARATOR;

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    // keccak256("Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 private constant _AUTH_TYPEHASH =
        keccak256(
            "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    event PullExecutedDirect(
        bytes32 indexed authHash,
        address indexed token,
        address indexed grantor,
        address grantee,
        uint256 amount
    );

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @param registryAddr Address of the deployed Consent Registry (RIP-002)
    ///        for this chain. MUST be trusted infra for revocation + accounting.
    constructor(address registryAddr) {
        registry = IRecurConsentRegistry(registryAddr);

        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("RecurPullSafeV2")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// -----------------------------------------------------------------------
    /// Public views
    /// -----------------------------------------------------------------------

    /// @notice Return the EIP-712 domain separator used in signature recovery.
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    /// @notice Compute canonical hash ID for this Authorization.
    /// @dev This MUST match RIP-002 derivation so wallets/indexers align.
    ///      Signature is intentionally excluded.
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

    /// -----------------------------------------------------------------------
    /// External entrypoint
    /// -----------------------------------------------------------------------

    /// @notice Execute a permissioned pull under a signed Authorization.
    /// @param auth   The signed Authorization struct.
    /// @param amount Requested amount for this call.
    function pull(
        Authorization calldata auth,
        uint256 amount
    ) external {
        // -------------------------------------------------------------------
        // 1. Derive canonical hash for registry lookups / audit trail
        // -------------------------------------------------------------------
        bytes32 authHash = authHashOf(auth);

        // -------------------------------------------------------------------
        // 2. Global revocation check (grantor can nuke authority at any time)
        // -------------------------------------------------------------------
        require(!registry.isRevoked(authHash), "REVOKED");

        // -------------------------------------------------------------------
        // 3. Caller must be the authorized grantee
        // -------------------------------------------------------------------
        require(msg.sender == auth.grantee, "NOT_AUTHORIZED");

        // -------------------------------------------------------------------
        // 4. Enforce timing guarantees
        // -------------------------------------------------------------------
        require(block.timestamp >= auth.validAfter, "TOO_SOON");
        require(block.timestamp <= auth.validBefore, "EXPIRED");

        // -------------------------------------------------------------------
        // 5. Enforce per-call ceiling
        // -------------------------------------------------------------------
        require(amount <= auth.maxPerPull, "LIMIT");

        // -------------------------------------------------------------------
        // 6. Verify the grantor actually signed this Authorization
        // -------------------------------------------------------------------
        require(
            _verifyGrantorSig(auth, auth.signature),
            "BAD_SIG"
        );

        // -------------------------------------------------------------------
        // 7. Direct, non-custodial transfer from grantor -> grantee
        // -------------------------------------------------------------------
        require(
            IERC20(auth.token).transferFrom(auth.grantor, auth.grantee, amount),
            "TRANSFER_FAIL"
        );

        // -------------------------------------------------------------------
        // 8. Emit local event (useful for explorers / debugging)
        // -------------------------------------------------------------------
        emit PullExecutedDirect(
            authHash,
            auth.token,
            auth.grantor,
            auth.grantee,
            amount
        );

        // -------------------------------------------------------------------
        // 9. Inform registry (RIP-002 accounting / audit trail)
        // -------------------------------------------------------------------
        registry.recordPull(
            authHash,
            auth.token,
            auth.grantor,
            auth.grantee,
            amount
        );
    }

    /// -----------------------------------------------------------------------
    /// Internal: signature verification
    /// -----------------------------------------------------------------------

    /// @dev Rebuild the EIP-712 struct hash for Authorization.
    function _hashAuthorizationStruct(
        Authorization calldata auth
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _AUTH_TYPEHASH,
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

    /// @dev Build full EIP-712 digest = keccak256("\x19\x01", domainSeparator, structHash)
    function _eip712Digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash)
        );
    }

    /// @dev Verify that `auth.grantor` signed `auth` under this contract's EIP-712 domain.
    /// Supports both EOAs (ECDSA) and smart contract wallets (EIP-1271).
    function _verifyGrantorSig(
        Authorization calldata auth,
        bytes calldata signature
    ) internal view returns (bool) {
        bytes32 structHash = _hashAuthorizationStruct(auth);
        bytes32 digest = _eip712Digest(structHash);

        // Smart contract wallet path (EIP-1271)
        if (auth.grantor.code.length != 0) {
            try IEIP1271(auth.grantor).isValidSignature(digest, signature) returns (bytes4 magicVal) {
                return (magicVal == 0x1626ba7e); // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            } catch {
                return false;
            }
        }

        // EOA path (ECDSA)
        if (signature.length != 65) {
            return false;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        // copy signature bytes into memory first to satisfy auditors
        bytes memory sig = signature;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // normalize v
        if (v < 27) {
            v += 27;
        }

        // reject malleable s (EIP-2 style)
        // secp256k1n/2:
        if (
            uint256(s)
                > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
        ) {
            return false;
        }

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) {
            return false;
        }

        return (recovered == auth.grantor);
    }
}
