// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title RecurPull (RIP-001 reference)
 * @notice Minimal permissioned-pull primitive for ERC-20 balances.
 *         A Grantor signs an Authorization off-chain. A Grantee calls pull()
 *         with the signed payload. Grantor can revoke at any time.
 */
interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "ECDSA: bad v");
        return ecrecover(hash, v, r, s);
    }
}

contract RecurPull {
    using ECDSA for bytes32;

    struct Authorization {
        address grantor;
        address grantee;
        address token;
        address to;
        uint256 maxAmount;
        uint256 totalCap;
        uint64  validAfter;
        uint64  validBefore;
        bytes32 nonce;
    }

    mapping(bytes32 => uint256) public spent;
    mapping(bytes32 => bool) public revoked;

    event Pulled(bytes32 indexed authHash, address indexed grantor, address indexed grantee, uint256 amount);
    event Revoked(bytes32 indexed authHash, address indexed by);

    function authHash(Authorization calldata a) public pure returns (bytes32) {
        return keccak256(abi.encode(
            a.grantor, a.grantee, a.token, a.to,
            a.maxAmount, a.totalCap, a.validAfter, a.validBefore, a.nonce
        ));
    }

    function revoke(bytes32 hash) external {
        require(!revoked[hash], "Already revoked");
        revoked[hash] = true;
        emit Revoked(hash, msg.sender);
    }

    function pull(Authorization calldata a, uint256 amount, bytes calldata signature) external {
        require(block.timestamp >= a.validAfter && block.timestamp < a.validBefore, "Not valid");
        require(msg.sender == a.grantee, "Only grantee");
        require(amount > 0 && amount <= a.maxAmount, "Bad amount");

        bytes32 h = authHash(a);
        require(!revoked[h], "Revoked");
        address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(h), signature);
        require(signer == a.grantor, "Bad signature");

        if (a.totalCap > 0) {
            uint256 newSpent = spent[h] + amount;
            require(newSpent <= a.totalCap, "Cap exceeded");
            spent[h] = newSpent;
        }

        require(IERC20(a.token).transferFrom(a.grantor, a.to, amount), "Transfer failed");
        emit Pulled(h, a.grantor, a.grantee, amount);
    }
}
