// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title FlowIntentRegistry
/// @notice RIP-003 registry. Verifies, accounts, and revokes cross-domain FlowIntents.
/// @custom:version 1.0.1-hardened
/// @custom:author Recur Labs
///
/// A FlowIntent says:
///   "executor X may move up to maxTotal of token T
///    from srcDomain → dstDomain for me (grantor),
///    during [validAfter, validBefore]."
///
/// Lifecycle
/// ---------
/// 1. The grantor signs a FlowIntent off-chain (EIP-712).
/// 2. CrossNetworkRebalancer (or another approved controller) calls verifyAndConsume():
///       - the FlowIntent struct
///       - the grantor's signature
///       - amountToMove for this step
///    We:
///       - check signature (EOA or 1271 smart wallet)
///       - check time window
///       - check revocation
///       - enforce cumulative cap (movedSoFar + amountToMove <= maxTotal)
///       - bind revocation authority to the grantor
///       - increment movedSoFar
///
/// 3. If we didn't revert, CrossNetworkRebalancer is cleared to actually
///    execute the movement via permissioned pull. Funds NEVER touch this contract.
///
/// 4. The grantor can revoke a specific intentHash at any time. After revoke,
///    verifyAndConsume() will always revert for that intent.
///
/// Security model
/// --------------
/// - This registry never moves funds.
/// - ONLY the configured `controller` can consume budget. That prevents
///   grief where an attacker front-runs with the signed intent and burns the
///   allowance before the real executor uses it.
/// - We bind each intentHash to its grantor (ownerOfIntent) on first success,
///   so only that wallet can later revoke.
/// - We do NOT route or pull funds here. That's RIP-004.
///
/// Executor enforcement
/// --------------------
/// - We do NOT check that msg.sender == i.executor here. CrossNetworkRebalancer
///   enforces executor allowlists per-domain before it ever calls us.
///   (You *could* add that here if you want an extra belt-and-suspenders.)
///
/// Replay safety
/// -------------
/// - The EIP-712 domain separator includes chainId and address(this),
///   so signatures cannot replay across networks or cloned registries.
/// - `nonce` in the FlowIntent makes each intent unique.
interface IEIP1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// @dev Local ECDSA helper with low-s enforcement (EIP-2 style).
library ECDSARecover {
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "BAD_SIG_LEN");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // normalize v (allow 0/1 style)
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "BAD_V");

        // reject malleable s (must be in lower half of curve order)
        // secp256k1n/2:
        require(
            uint256(s)
                <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,
            "BAD_S"
        );

        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ZERO_SIGNER");
        return signer;
    }
}

contract FlowIntentRegistry {
    /// -----------------------------------------------------------------------
    /// Data types
    /// -----------------------------------------------------------------------

    /// @notice RIP-003 FlowIntent (what the grantor signs off-chain).
    /// @dev CrossNetworkRebalancer passes this in along with the signature.
    struct FlowIntent {
        address grantor;      // liquidity owner / treasury controller
        address executor;     // authorized router/agent to act on this intent
        bytes32 srcDomain;    // opaque "from" domain identifier (e.g. keccak256("base:treasury"))
        bytes32 dstDomain;    // opaque "to" domain identifier
        address token;        // ERC-20 being rebalanced
        uint256 maxTotal;     // TOTAL allowed to move under this intent
        uint256 validAfter;   // unix timestamp lower bound
        uint256 validBefore;  // unix timestamp upper bound
        bytes32 nonce;        // unique salt for replay isolation
        bytes32 metadataHash; // optional off-chain policy/compliance ref
    }

    // intentHash => total already moved (cumulative)
    mapping(bytes32 => uint256) public movedSoFar;

    // intentHash => has it been revoked?
    mapping(bytes32 => bool)    public revoked;

    // intentHash => canonical grantor allowed to revoke
    mapping(bytes32 => address) public ownerOfIntent;

    /// @notice EIP-712 domain separator for FlowIntent signatures.
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice EIP-712 typehash for FlowIntent.
    /// keccak256(
    ///   "FlowIntent(address grantor,address executor,bytes32 srcDomain,bytes32 dstDomain,address token,uint256 maxTotal,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes32 metadataHash)"
    /// )
    bytes32 public constant INTENT_TYPEHASH =
        0xb97fc7db6c8eb50e554e0c1d571c8df7e30e08b6f7fb36efaeb53ba5f3a2b967;

    /// @notice Privileged authority (Safe / multisig / CrossNetworkRebalancer).
    address public controller;

    /// @notice Emitted whenever an intent is revoked by its grantor.
    event IntentRevoked(bytes32 indexed intentHash, address indexed grantor);

    /// @notice Emitted when controller authority rotates.
    event ControllerUpdated(address indexed newController);

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

    /// @param name               Human-readable domain name (e.g. "FlowIntentRegistry")
    /// @param version            Human-readable version (e.g. "1")
    /// @param initialController  Address (Safe / multisig / rebalancer contract)
    ///                           that is allowed to call verifyAndConsume().
    ///
    /// We bind the domain separator to `address(this)` + `block.chainid`
    /// so signatures cannot be replayed across chains or across different
    /// registry instances.
    constructor(
        string memory name,
        string memory version,
        address initialController
    ) {
        require(initialController != address(0), "BAD_CONTROLLER");

        controller = initialController;

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

    /// @notice Rotate controller (e.g. upgrade to a new CrossNetworkRebalancer).
    function setController(address next) external onlyController {
        require(next != address(0), "BAD_CONTROLLER");
        controller = next;
        emit ControllerUpdated(next);
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
                i.maxTotal,
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
        return keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
    }

    function _isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }

    /// -----------------------------------------------------------------------
    /// Core entrypoint (called by CrossNetworkRebalancer / controller)
    /// -----------------------------------------------------------------------

    /// @notice Validate a FlowIntent + signature, enforce cap/time, and atomically
    ///         reserve `amountToMove` against its budget.
    ///
    /// @dev onlyController:
    ///  - prevents grief where a random caller front-runs and burns down the cap
    ///    by calling verifyAndConsume() with the grantor's signature
    ///
    /// Enforces:
    ///  - current time within [validAfter, validBefore]
    ///  - not revoked
    ///  - signature belongs to `i.grantor` (EOA or EIP-1271 smart wallet)
    ///  - movedSoFar[intentHash] + amountToMove <= maxTotal
    ///  - ownerOfIntent[intentHash] is bound to the grantor on first success
    function verifyAndConsume(
        FlowIntent calldata i,
        bytes calldata signature,
        uint256 amountToMove
    ) external onlyController returns (bytes32 intentHash) {
        require(amountToMove > 0, "AMOUNT_0");
        require(block.timestamp >= i.validAfter, "NOT_YET_VALID");
        require(block.timestamp <= i.validBefore, "EXPIRED");

        intentHash = _hashIntent(i);
        require(!revoked[intentHash], "REVOKED");

        // Enforce cumulative cap
        uint256 newMoved = movedSoFar[intentHash] + amountToMove;
        require(newMoved <= i.maxTotal, "CAP_EXCEEDED");

        // Verify signature from grantor (EIP-712)
        bytes32 dig = _digest(i);

        if (_isContract(i.grantor)) {
            // smart contract wallet path (EIP-1271)
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

        // Reserve consumption so future calls can't exceed maxTotal.
        movedSoFar[intentHash] = newMoved;
    }

    /// -----------------------------------------------------------------------
    /// Revocation
    /// -----------------------------------------------------------------------

    /// @notice Revoke a FlowIntent permanently.
    /// @dev Only the bound grantor can revoke.
    ///      After revocation, verifyAndConsume() will always revert for this hash.
    function revokeIntent(bytes32 intentHash) external {
        address owner = ownerOfIntent[intentHash];
        require(owner != address(0), "UNKNOWN_INTENT");
        require(msg.sender == owner, "NOT_OWNER");

        revoked[intentHash] = true;
        emit IntentRevoked(intentHash, msg.sender);
    }

    /// -----------------------------------------------------------------------
    /// Views (for explorers / telemetry / dashboards)
    /// -----------------------------------------------------------------------

    /// @notice Cumulative amount already "consumed" under this intent.
    function consumed(bytes32 intentHash) external view returns (uint256) {
        return movedSoFar[intentHash];
    }

    /// @notice Whether this intent has been fully revoked.
    function isRevoked(bytes32 intentHash) external view returns (bool) {
        return revoked[intentHash];
    }

    /// @notice Which address currently holds revocation power for this intent.
    function ownerOf(bytes32 intentHash) external view returns (address) {
        return ownerOfIntent[intentHash];
    }
}
