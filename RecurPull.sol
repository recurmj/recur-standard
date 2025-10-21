// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurPull — minimal permissioned-pull primitive (RIP-001)
/// @notice Executes a transfer when a signed Authorization is valid and not revoked.
interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

library AuthLib {
    struct Authorization {
        address grantor;     // who gives consent
        address grantee;     // who may call pull()
        address token;       // ERC-20 being moved
        address to;          // receiver of funds
        uint256 amount;      // max amount per pull (or fixed)
        uint256 start;       // unix start
        uint256 expiry;      // unix expiry
        bytes32 scope;       // app-specific scope / id
        bytes32 nonce;       // unique value
    }

    // EIP-712 typehash for Authorization
    bytes32 internal constant AUTH_TYPEHASH = keccak256(
        "Authorization(address grantor,address grantee,address token,address to,uint256 amount,uint256 start,uint256 expiry,bytes32 scope,bytes32 nonce)"
    );

    function hash(Authorization memory a) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            AUTH_TYPEHASH,
            a.grantor, a.grantee, a.token, a.to,
            a.amount, a.start, a.expiry, a.scope, a.nonce
        ));
    }
}

contract RecurPull {
    using AuthLib for AuthLib.Authorization;

    /// @dev mapping of revocation hash => revoked
    mapping(bytes32 => bool) public revoked;

    /// @notice Grantor can precompute and publish a revocation hash; if true, pull() fails.
    function revoke(bytes32 authHash) external {
        // simple model: the authHash encodes grantor; in practice you may store authHash => grantor and check msg.sender
        revoked[authHash] = true;
        emit Revoked(authHash, msg.sender);
    }

    /// @notice Pull funds if signed Authorization is valid.
    /// @param a Authorization payload (struct fields)
    /// @param v,r,s ECDSA signature of EIP-712 hash by `a.grantor`
    /// @param amount amount to pull (<= a.amount)
    function pull(
        AuthLib.Authorization calldata a,
        uint8 v, bytes32 r, bytes32 s,
        uint256 amount
    ) external {
        require(msg.sender == a.grantee, "not grantee");
        require(block.timestamp >= a.start && block.timestamp <= a.expiry, "outside window");
        require(amount <= a.amount, "over amount");

        bytes32 digest = _toTypedDataHash(a.hash());
        address signer = ecrecover(digest, v, r, s);
        require(signer == a.grantor, "bad sig");

        require(!revoked[a.hash()], "revoked");

        require(IERC20(a.token).transferFrom(a.grantor, a.to, amount), "transfer failed");
        emit Pulled(a.grantor, a.grantee, a.token, a.to, amount, a.scope, a.nonce);
    }

    // --- EIP-712 domain (minimal, you can lift into a base with name/version/chainId) ---
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private immutable _DOMAIN_SEPARATOR;

    constructor() {
        _DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes("RecurPull")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function domainSeparator() public view returns (bytes32) { return _DOMAIN_SEPARATOR; }

    function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    event Pulled(address indexed grantor, address indexed grantee, address indexed token, address to, uint256 amount, bytes32 scope, bytes32 nonce);
    event Revoked(bytes32 indexed authHash, address indexed by);
}
