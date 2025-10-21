// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurPullSafeV2 — permissioned-pull with caps, revocation, 1271, and optional permit
/// @notice Reference implementation for RIP-001 (consented continuity), hardened for pilots.

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IERC20Permit {
    function permit(
        address owner, address spender,
        uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

library ECDSA {
    function toEthSignedMessageHash(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }
    function recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert BadSigLength();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert BadSigV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert EcrecoverFailed();
        return signer;
    }
    error BadSigLength();
    error BadSigV();
    error EcrecoverFailed();
}

contract RecurPullSafeV2 {
    /*//////////////////////////////////////////////////////////////
                                    EIP-712
    //////////////////////////////////////////////////////////////*/

    string public constant NAME    = "RecurPull";
    string public constant VERSION = "1";

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant _EIP712DOMAIN_TYPEHASH =
        0xd87cd6e3c6d2a4e2f0e3d3a7a9a2a0d9a5dc8b9d4f7b67d3b3a8f0e8b2b9d3f4;

    // keccak256("Authorization(address grantor,address grantee,address token,uint256 maxAmount,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant AUTHORIZATION_TYPEHASH =
        keccak256(
            "Authorization(address grantor,address grantee,address token,uint256 maxAmount,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    struct Authorization {
        address grantor;    // payer
        address grantee;    // puller (must be msg.sender)
        address token;      // ERC-20
        uint256 maxAmount;  // cumulative cap across all pulls under this auth
        uint256 validAfter;   // inclusive
        uint256 validBefore;  // exclusive
        bytes32 nonce;      // unique per authorization
    }

    /*//////////////////////////////////////////////////////////////
                         STATE & REENTRANCY
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => bool)    public revoked;  // authHash => revoked?
    mapping(bytes32 => uint256) public spent;    // authHash => cumulative amount

    uint256 private _lock; // 0 = unlocked, 1 = locked
    modifier nonReentrant() {
        require(_lock == 0, "REENTRANCY");
        _lock = 1;
        _;
        _lock = 0;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Pulled(bytes32 indexed authHash, address indexed grantor, address indexed grantee, address token, uint256 amount, uint256 spentTotal);
    event RevokedAuth(bytes32 indexed authHash, address indexed grantor);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotGrantee();
    error Revoked();
    error NotYetValid();
    error Expired();
    error OverCap();
    error InvalidSignature();
    error ZeroAddress();
    error ZeroAmount();
    error PermitInsufficient();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _CACHED_CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function domainSeparator() public view returns (bytes32) {
        return block.chainid == _CACHED_CHAIN_ID ? DOMAIN_SEPARATOR : _buildDomainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                           USER-FACING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pull tokens under a signed authorization (EOA or 1271). Grantor must have approved this contract.
    function pull(
        Authorization calldata auth,
        uint256 amount,
        bytes calldata signature
    ) external nonReentrant {
        _pull(auth, amount, signature, false, "");
    }

    /// @notice Pull tokens and set allowance via EIP-2612 permit in the same call (if token supports it).
    /// @dev     `permitData` ABI: (uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
    function pullWithPermit(
        Authorization calldata auth,
        uint256 amount,
        bytes calldata signature,
        bytes calldata permitData
    ) external nonReentrant {
        _pull(auth, amount, signature, true, permitData);
    }

    /// @notice Revoke a previously issued authorization. Caller must be the grantor.
    function revoke(Authorization calldata auth) external {
        if (msg.sender != auth.grantor) revert InvalidSignature(); // authority check
        bytes32 h = authHash(auth);
        revoked[h] = true;
        emit RevokedAuth(h, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL: CORE LOGIC
    //////////////////////////////////////////////////////////////*/

    function _pull(
        Authorization calldata auth,
        uint256 amount,
        bytes calldata signature,
        bool usePermit,
        bytes calldata permitData
    ) internal {
        if (amount == 0) revert ZeroAmount();
        if (auth.grantor == address(0) || auth.grantee == address(0) || auth.token == address(0)) revert ZeroAddress();
        if (msg.sender != auth.grantee) revert NotGrantee();
        if (block.timestamp < auth.validAfter) revert NotYetValid();
        if (block.timestamp >= auth.validBefore) revert Expired();

        bytes32 h = authHash(auth);
        if (revoked[h]) revert Revoked();

        _verifyAuth(auth, signature);

        uint256 newSpent = spent[h] + amount;
        if (newSpent > auth.maxAmount) revert OverCap();

        if (usePermit) {
            (uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) =
                abi.decode(permitData, (uint256, uint256, uint8, bytes32, bytes32));
            IERC20Permit(auth.token).permit(auth.grantor, address(this), value, deadline, v, r, s);
            if (value < amount) revert PermitInsufficient();
        }

        require(IERC20(auth.token).transferFrom(auth.grantor, auth.grantee, amount), "transferFrom fail");

        spent[h] = newSpent;
        emit Pulled(h, auth.grantor, auth.grantee, auth.token, amount, newSpent);
    }

    function _verifyAuth(Authorization calldata auth, bytes calldata signature) internal view {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), authHash(auth)));
        if (_isContract(auth.grantor)) {
            if (IERC1271(auth.grantor).isValidSignature(digest, signature) != 0x1626ba7e) revert InvalidSignature();
        } else {
            if (ECDSA.recover(digest, signature) != auth.grantor) revert InvalidSignature();
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function authHash(Authorization calldata auth) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                AUTHORIZATION_TYPEHASH,
                auth.grantor,
                auth.grantee,
                auth.token,
                auth.maxAmount,
                auth.validAfter,
                auth.validBefore,
                auth.nonce
            )
        );
    }

    function remaining(Authorization calldata auth) external view returns (uint256) {
        bytes32 h = authHash(auth);
        if (revoked[h]) return 0;
        uint256 cap = auth.maxAmount;
        uint256 used = spent[h];
        return used >= cap ? 0 : (cap - used);
    }

    function _isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }
}
