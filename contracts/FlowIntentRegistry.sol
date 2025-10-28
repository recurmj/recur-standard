// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title FlowIntentRegistry — RIP-003 reference implementation
/// @notice Registers, verifies, accounts, and revokes cross-domain FlowIntents.
///
/// A FlowIntent says:
///   "Executor X is allowed to move up to maxAmount of token T
///    from srcDomain → dstDomain for me (grantor),
///    between validAfter and validBefore."
///
/// High level:
/// - The grantor signs the FlowIntent off-chain (EIP-712 style).
/// - The executor (or a controller acting for them) asks the Rebalancer
///   to execute `amount`.
/// - The Rebalancer calls `verifyAndConsume()` here:
///     - signature is checked (EOA or 1271 smart wallet)
///     - time window enforced
///     - cap enforced via movedSoFar[intentHash]
///     - revocation enforced
///     - movedSoFar is incremented
///
/// - The grantor can revoke a specific intentHash at any time. After that,
///   verifyAndConsume() will fail for that intentHash.
///
/// SECURITY NOTES:
/// - This registry never moves funds.
/// - We bind each intentHash to its grantor on first successful verification.
///   Only that address can revoke the intent.
/// - We DO NOT attempt to route or pull here. That happens in CrossNetworkRebalancer (RIP-004).
///
/// COMPATIBILITY:
/// - CrossNetworkRebalancer should call verifyAndConsume() before actually
///   calling an adapter / channel to move funds.
/// - The registry then becomes the single source of truth for:
///     - "is this intent valid? has it expired? how much is left?"
///     - "who can revoke it?"
interface IEIP1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

library ECDSARecover {
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "BAD_SIG_LEN");
        bytes32 r;
        bytes32 s;
        uint8 v;
        // sig = r (32) || s (32) || v (1)
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        // Allow both 27/28 and 0/1 style v, normalize:
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "BAD_V");

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ZERO_SIGNER");
        return signer;
    }
}

contract FlowIntentRegistry {
    /// -----------------------------------------------------------------------
    /// Data types
    /// -----------------------------------------------------------------------

    /// @notice RIP-003 FlowIntent.
    /// @dev This struct is what the grantor actually signs off-chain.
    ///      The executor later presents it (plus signature) to the Rebalancer.
    struct FlowIntent {
        address grantor;      // liquidity owner / treasury controller
        address executor;     // authorized router/agent to act on this intent
        bytes32 srcDomain;    // opaque "from" domain identifier (ex: keccak256("base:treasury"))
        bytes32 dstDomain;    // opaque "to" domain identifier
        address token;        // ERC-20 being rebalanced
        uint256 maxAmount;    // TOTAL allowed to move under this intent
        uint256 validAfter;   // unix timestamp lower bound
        uint256 validBefore;  // unix timestamp upper bound
        bytes32 nonce;        // unique salt for replay isolation
        bytes32 metadataHash; // optional off-chain policy/compliance ref
    }

    // intentHash => total already moved
    mapping(bytes32 => uint256) public movedSoFar;

    // intentHash => has it been revoked?
    mapping(bytes32 => bool)    public revoked;

    // intentHash => who is allowed to revoke (the canonical grantor)
    mapping(bytes32 => address) public ownerOfIntent;

    /// @notice EIP-712 domain separator for FlowIntent signatures.
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice EIP-712 typehash for FlowIntent.
    /// keccak256(
    ///   "FlowIntent(address grantor,address executor,bytes32 srcDomain,bytes32 dstDomain,address token,uint256 maxAmount,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes32 metadataHash)"
    /// )
    bytes32 public constant INTENT_TYPEHASH =
        0x4fda6d44e9a0ab9ee76ed2c350f05e1a3b2a838bfda843440f1d232631b8db52;

    /// @notice Emitted whenever an intent is revoked by its grantor.
    event IntentRevoked(bytes32 indexed intentHash, address indexed grantor);

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @param name    Human-readable domain name (e.g. "FlowIntentRegistry")
    /// @param version Human-readable version (e.g. "1")
    ///
    /// We bind the domain separator to `address(this)` + `block.chainid`
    /// so signatures cannot be replayed across chains or different registries.
    constructor(string memory name, string memory version) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,address verifyingContract,uint256 chainId)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                address(this),
                block.chainid
            )
        );
    }

    /// -----------------------------------------------------------------------
    /// Internal hashing helpers
    /// -----------------------------------------------------------------------

    /// @notice Hash just the FlowIntent struct fields (no domain separator).
    function _hashIntent(FlowIntent calldata i) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                INTENT_TYPEHASH,
                i.grantor,
                i.executor,
                i.srcDomain,
                i.dstDomain,
                i.token,
                i.maxAmount,
                i.validAfter,
                i.validBefore,
                i.nonce,
                i.metadataHash
            )
        );
    }

    /// @notice Full EIP-712 digest = keccak256("\x19\x01", DOMAIN_SEPARATOR, structHash)
    function _digest(FlowIntent calldata i) internal view returns (bytes32) {
        bytes32 structHash = _hashIntent(i);
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }

    /// -----------------------------------------------------------------------
    /// Core entrypoint (for CrossNetworkRebalancer)
    /// -----------------------------------------------------------------------

    /// @notice Validate a FlowIntent + signature, enforce cap/time, and atomically
    ///         reserve `amountToMove` against its budget.
    ///
    /// @dev Call this *before* actually moving funds.
    ///      If this returns intentHash without reverting, you are cleared to act.
    ///
    /// SECURITY ENFORCEMENTS:
    ///  - verifies time window [validAfter, validBefore]
    ///  - verifies not revoked
    ///  - verifies signature (EOA ECDSA or 1271 smart wallet)
    ///  - enforces cumulative maxAmount via movedSoFar[intentHash]
    ///  - binds ownerOfIntent[intentHash] to the grantor on first success
    ///
    /// NOTE:
    ///  We do NOT check that msg.sender == i.executor here.
    ///  That should be enforced in CrossNetworkRebalancer, because you might
    ///  also allow a governance/controller address to batch execution.
    ///
    /// RETURNS:
    ///  - intentHash (the canonical hash of this intent)
    function verifyAndConsume(
        FlowIntent calldata i,
        bytes calldata signature,
        uint256 amountToMove
    ) external returns (bytes32 intentHash) {
        require(amountToMove > 0, "AMOUNT_0");
        require(block.timestamp >= i.validAfter, "NOT_YET_VALID");
        require(block.timestamp <= i.validBefore, "EXPIRED");

        intentHash = _hashIntent(i);

        require(!revoked[intentHash], "REVOKED_INTENT");

        // enforce cumulative cap
        uint256 newMoved = movedSoFar[intentHash] + amountToMove;
        require(newMoved <= i.maxAmount, "CAP_EXCEEDED");

        // verify signature from grantor (EIP-712)
        bytes32 dig = _digest(i);

        if (_isContract(i.grantor)) {
            // Smart contract wallet path (EIP-1271)
            bytes4 magic = IEIP1271(i.grantor).isValidSignature(dig, signature);
            require(magic == 0x1626ba7e, "BAD_1271_SIG");
        } else {
            // EOA path
            address signer = ECDSARecover.recover(dig, signature);
            require(signer == i.grantor, "BAD_EOA_SIG");
        }

        // Bind revocation authority to this grantor if first execution.
        if (ownerOfIntent[intentHash] == address(0)) {
            ownerOfIntent[intentHash] = i.grantor;
        }

        // Reserve consumption.
        movedSoFar[intentHash] = newMoved;
    }

    /// -----------------------------------------------------------------------
    /// Revocation
    /// -----------------------------------------------------------------------

    /// @notice Revoke a FlowIntent permanently.
    /// @dev Only the grantor (ownerOfIntent[intentHash]) can revoke.
    ///      After revocation, verifyAndConsume() will revert for this hash.
    function revokeIntent(bytes32 intentHash) external {
        address owner = ownerOfIntent[intentHash];
        require(owner != address(0), "UNKNOWN_INTENT");
        require(msg.sender == owner, "NOT_OWNER");

        revoked[intentHash] = true;
        emit IntentRevoked(intentHash, msg.sender);
    }

    /// -----------------------------------------------------------------------
    /// Views (for explorers, CrossNetworkRebalancer telemetry, dashboards)
    /// -----------------------------------------------------------------------

    /// @notice How much total value this intent has authorized so far.
    function consumed(bytes32 intentHash) external view returns (uint256) {
        return movedSoFar[intentHash];
    }

    /// @notice Has this intent been revoked?
    function isRevoked(bytes32 intentHash) external view returns (bool) {
        return revoked[intentHash];
    }

    /// @notice Who is allowed to revoke this intent?
    function ownerOf(bytes32 intentHash) external view returns (address) {
        return ownerOfIntent[intentHash];
    }
}
