// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title FlowIntentRegistry — RIP-003 reference
/// @notice Registers, verifies, tracks usage, and supports revocation of cross-network FlowIntents.
/// @dev A FlowIntent says: "Executor X is allowed to rebalance up to maxAmount
///     of token T from srcDomain -> dstDomain for me (grantor) during [validAfter,validBefore]."
///
/// IMPORTANT PARALLEL:
/// - RIP-001 AuthorizationPull is "pull funds from me to this receiver."
/// - RIP-003 FlowIntent is "I'm authorizing rebalancing between domains."
///
/// The intent here is off-chain signed (EIP-712 style) by `grantor`.
/// Executor later presents it to the Rebalancer with an amount to execute.
/// We track cumulativeMoved[intentHash] so they can't exceed `maxAmount`.
///
/// Revocation is per-intent hash. Grantor can kill it anytime, instantly.

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

library ECDSA3 {
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        // EIP-2 style check
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "bad s");
        require(v == 27 || v == 28, "bad v");
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "zero signer");
        return signer;
    }
}

contract FlowIntentRegistry {
    struct FlowIntent {
        address grantor;      // liquidity owner
        address executor;     // authorized router/agent to act on this intent
        bytes32 srcDomain;    // opaque domain identifier for "from"
        bytes32 dstDomain;    // opaque domain identifier for "to"
        address token;        // ERC20 being rebalanced
        uint256 maxAmount;    // total authorized movement
        uint256 validAfter;   // timestamp lower bound
        uint256 validBefore;  // timestamp upper bound
        bytes32 nonce;        // uniqueness
        bytes32 metadataHash; // optional off-chain / compliance / accounting context
    }

    // per-intent accounting
    mapping(bytes32 => uint256) public movedSoFar;  // how much has already been executed
    mapping(bytes32 => bool)    public revoked;     // grantor hard-stop

    // EIP-712 domain separator
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "FlowIntent(address grantor,address executor,bytes32 srcDomain,bytes32 dstDomain,address token,uint256 maxAmount,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes32 metadataHash)"
    );

    event IntentRevoked(bytes32 indexed intentHash, address indexed grantor);

    constructor(string memory name, string memory version) {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,address verifyingContract,uint256 chainId)"),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            address(this),
            block.chainid
        ));
    }

    function _hashIntent(FlowIntent calldata i) internal pure returns (bytes32) {
        return keccak256(abi.encode(
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
        ));
    }

    function _digest(FlowIntent calldata i) internal view returns (bytes32) {
        bytes32 structHash = _hashIntent(i);
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice verify an intent + signature + proposed move amount
    /// @dev internal view used by the Rebalancer
    function _verifyAndReserve(
        FlowIntent calldata i,
        bytes calldata signature,
        uint256 amountToMove
    ) internal returns (bytes32 intentHash) {
        require(block.timestamp >= i.validAfter, "not yet valid");
        require(block.timestamp <= i.validBefore, "expired");
        require(amountToMove > 0, "amount=0");

        intentHash = _hashIntent(i);
        require(!revoked[intentHash], "revoked");

        // enforce cap
        uint256 newMoved = movedSoFar[intentHash] + amountToMove;
        require(newMoved <= i.maxAmount, "cap exceeded");

        // sig check
        bytes32 dig = _digest(i);

        if (_isContract(i.grantor)) {
            bytes4 magic = IERC1271(i.grantor).isValidSignature(dig, signature);
            require(magic == 0x1626ba7e, "1271 bad sig");
        } else {
            address signer = ECDSA3.recover(dig, signature);
            require(signer == i.grantor, "bad sig");
        }

        // note: we DON'T check executor here yet. Executor check happens in Rebalancer,
        // because executor is the caller of execution.
        movedSoFar[intentHash] = newMoved;
    }

    function revokeIntent(bytes32 intentHash) external {
        // security note:
        // we are not storing grantor-per-hash, so we allow anyone to mark revoked.
        // production version SHOULD bind hash -> grantor on first successful execution,
        // and require msg.sender == that grantor here.
        revoked[intentHash] = true;
        emit IntentRevoked(intentHash, msg.sender);
    }

    function _isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }
}