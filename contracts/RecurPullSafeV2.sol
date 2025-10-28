// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurPullSafeV2
/// @notice RIP-001 permissioned pull executor with RIP-002 registry integration,
///         EIP-712 authorization, and EIP-1271 smart wallet support.
/// @dev
/// CORE IDEA
/// ---------
/// This is a non-custodial pull primitive:
///   - The grantor signs an Authorization off-chain (EIP-712 domain-bound to
///     this contract + this chain).
///   - The grantee calls pull(auth, amount).
///   - We verify:
///        * Consent still live in the Consent Registry (RIP-002).
///        * Time window is valid.
///        * Per-call ceiling (maxPerPull) is not exceeded.
///        * Signature really came from `auth.grantor` (EOA or 1271 wallet).
///        * Caller is exactly `auth.grantee`.
///   - We then transfer ERC20 tokens directly from grantor -> grantee
///     via transferFrom(). This contract NEVER escrows funds.
///   - We emit an event and call registry.recordPull() for audit/analytics
///     and to bind `authHash -> grantor` so only that grantor can revoke later.
///
/// SECURITY PROPERTIES
/// -------------------
/// - Global kill switch: The grantor (and only the grantor, per the hardened
///   RecurConsentRegistry model) can revoke the authHash in the registry. After
///   that, isRevoked(authHash) returns true and pulls revert forever.
/// - No custody: If the grantor doesn't like what's happening, they can instantly
///   drop the ERC20 allowance they gave this contract, even without on-chain
///   revocation.
/// - Hard per-call ceiling: `amount <= auth.maxPerPull`.
/// - Bounded validity window: [validAfter, validBefore].
/// - Signature is domain-separated by chainId and this contract address. You
///   can't replay the same signed Authorization on a fork / clone / other chain.
///
/// WHAT THIS CONTRACT DOES **NOT** DO
/// ----------------------------------
/// - No per-epoch / per-day budgets. (That's RIP-007 PolicyEnforcer and/or
///   FlowChannelHardened rate control.)
/// - No receiver allowlists. Funds always go to auth.grantee, and cannot be
///   rerouted per-call.
/// - No streaming accrual. It's strictly "pull if signed and still allowed".
///
/// INTEGRATION REQUIREMENTS
/// ------------------------
/// - The grantor MUST have approved this contract as a spender for `auth.token`:
///       IERC20(auth.token).approve(address(this), <limit>);
///   Otherwise `transferFrom()` will revert with TRANSFER_FAIL.
/// - The Consent Registry passed to the constructor MUST be trusted infra.
///   In production it should:
///       * bind authHash -> grantor on first recordPull(),
///       * restrict revoke() so only that grantor can revoke,
///       * ideally restrict recordPull() to known executors (like this contract).
///
/// REENTRANCY NOTE
/// ---------------
/// - We make one external call to the ERC20 token (transferFrom),
///   then one external call to the registry (recordPull()).
/// - `recordPull()` in a hardened deployment should be a trusted registry that
///   does not call back into this contract. With that assumption, a explicit
///   reentrancy guard isn't strictly required here.
/// - If you plug in an untrusted registry, you are doing it wrong.

/// @notice Minimal ERC-20 interface for pull-based transfers.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Light interface to the Consent Registry (RIP-002).
/// The registry is the global source of truth for revocation and cumulative accounting.
/// In hardened deployments:
///  - recordPull() is only callable by trusted executors,
///  - revoke() is only callable by the canonical grantor bound to that authHash.
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
/// If grantor is a contract wallet, we call isValidSignature(hash, sig)
/// and expect 0x1626ba7e.
interface IEIP1271 {
    function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4 magicValue);
}

contract RecurPullSafeV2 {
    /// -----------------------------------------------------------------------
    /// Authorization struct
    /// -----------------------------------------------------------------------

    /// @notice Off-chain signed grant of consent.
    /// @dev
    /// - `grantee` is BOTH (1) who may call pull() and (2) who receives funds.
    /// - There is no per-call override of receiver here. If you need to route
    ///   to arbitrary receivers, use FlowChannelHardened instead.
    struct Authorization {
        address grantor;      // wallet giving consent / paying funds
        address grantee;      // wallet/agent allowed to pull AND the receiver of funds
        address token;        // ERC-20 being pulled
        uint256 maxPerPull;   // hard ceiling for a single pull() call
        uint256 validAfter;   // earliest timestamp allowed
        uint256 validBefore;  // latest timestamp allowed
        bytes32 nonce;        // unique salt (prevents collision / replay across grants)
        bytes   signature;    // EIP-712 / 1271 signature by grantor over *this* scope
    }

    /// -----------------------------------------------------------------------
    /// Immutable storage
    /// -----------------------------------------------------------------------

    /// @notice Consent / revocation / accounting registry for this domain (RIP-002).
    IRecurConsentRegistry public immutable registry;

    /// @notice EIP-712 domain separator, bound to this chain and this contract.
    bytes32 private immutable _DOMAIN_SEPARATOR;

    /// @dev keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    /// @dev keccak256("Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 private constant _AUTH_TYPEHASH =
        keccak256(
            "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    /// @notice Emitted after a successful pull() and transferFrom().
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

    /// @notice Compute canonical authHash for this Authorization.
    /// @dev
    /// - Signature is excluded.
    /// - This MUST line up with how the Consent Registry (RIP-002) identifies
    ///   an Authorization so that:
    ///     - registry.isRevoked(authHash) acts as the global kill switch
    ///     - registry.recordPull() binds this authHash to the grantor
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
    /// @param auth   The signed Authorization struct (grant terms).
    /// @param amount Requested amount for this call.
    ///
    /// @dev Reverts if:
    ///   - authHash is revoked in the Consent Registry,
    ///   - msg.sender != auth.grantee,
    ///   - block.timestamp outside [validAfter, validBefore],
    ///   - amount > maxPerPull,
    ///   - signature is not valid for `auth.grantor`,
    ///   - transferFrom(grantor -> grantee) fails (eg no allowance).
    ///
    /// Side effects on success:
    ///   - Direct non-custodial ERC20 transfer from grantor to grantee.
    ///   - Emit PullExecutedDirect for indexers / auditors.
    ///   - registry.recordPull(...) is called so:
    ///        * totalPulled[authHash] is incremented,
    ///        * ownerOfAuth[authHash] in the registry is set to `grantor`
    ///          if this is the first ever pull (so only that grantor can
    ///          revoke from then on).
    function pull(
        Authorization calldata auth,
        uint256 amount
    ) external {
        // 1. Canonical hash for registry lookups / audit trail
        bytes32 authHash = authHashOf(auth);

        // 2. Global revocation check (grantor can nuke authority in registry)
        require(!registry.isRevoked(authHash), "REVOKED");

        // 3. Caller must be the authorized grantee AND receiver of funds
        require(msg.sender == auth.grantee, "NOT_AUTHORIZED");

        // 4. Enforce timing guarantees
        require(block.timestamp >= auth.validAfter, "TOO_SOON");
        require(block.timestamp <= auth.validBefore, "EXPIRED");

        // 5. Enforce per-call ceiling
        require(amount <= auth.maxPerPull, "LIMIT");
        require(amount > 0, "AMOUNT_0");

        // 6. Verify the grantor actually signed this Authorization
        require(_verifyGrantorSig(auth, auth.signature), "BAD_SIG");

        // 7. Direct, non-custodial transfer grantor -> grantee
        //    NOTE: This requires ERC20 allowance from grantor to this contract.
        require(
            IERC20(auth.token).transferFrom(auth.grantor, auth.grantee, amount),
            "TRANSFER_FAIL"
        );

        // 8. Emit local event (useful for explorers / debugging / monitoring)
        emit PullExecutedDirect(
            authHash,
            auth.token,
            auth.grantor,
            auth.grantee,
            amount
        );

        // 9. Inform registry (RIP-002 accounting / audit trail / revoke binding)
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

    /// @dev Build structHash = keccak256(abi.encode(_AUTH_TYPEHASH, ...))
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

    /// @dev EIP-712 digest = keccak256("\x19\x01", domainSeparator, structHash)
    function _eip712Digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash)
        );
    }

    /// @dev Verify that `auth.grantor` signed `auth` under this contract's domain.
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
                // bytes4(keccak256("isValidSignature(bytes32,bytes)")) == 0x1626ba7e
                return (magicVal == 0x1626ba7e);
            } catch {
                return false;
            }
        }

        // EOA path (ECDSA, low-s enforced)
        if (signature.length != 65) {
            return false;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        // copy signature into memory first (auditors prefer no direct calldata load)
        bytes memory sig = signature;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // normalize v: allow {0,1} or {27,28}
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return false;
        }

        // reject malleable s (EIP-2 style): s must be in lower half
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
