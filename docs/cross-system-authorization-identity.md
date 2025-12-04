# Cross-System Authorization Identity  
### Formal Companion to RIP-009

**Status:** Informational  
**Author:** Recur Labs  
**Created:** 2025  
**Requires:** RIP-001, RIP-002, EIP-712  

---

## 1. Overview

The **Cross-System Authorization Identity** defines the structural condition under which two independent systems will reach the same verdict ("valid" or "invalid") when verifying a signed RIP-001 Authorization.

RIP-009 expresses this rule:

> Two systems verify an Authorization identically  
> **iff** they reconstruct the same `(domainSeparator, structHash)` pair.

This document formalizes that invariant.  
It does **not** introduce new primitives; it describes the identity condition inherent to EIP-712 structured data hashing.

---

## 2. Canonical Authorization Schema (From RIP-001)

RIP-001 defines the Authorization object:

~~~solidity
struct Authorization {
    address grantor;
    address grantee;
    address token;
    uint256 maxPerPull;
    uint256 validAfter;
    uint256 validBefore;
    bytes32 nonce;
    bytes   signature;
}
~~~

The typehash is:

~~~solidity
bytes32 constant AUTH_TYPEHASH = keccak256(
    "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
);
~~~

The **structHash** is:

~~~solidity
structHash = keccak256(
    abi.encode(
        AUTH_TYPEHASH,
        grantor,
        grantee,
        token,
        maxPerPull,
        validAfter,
        validBefore,
        nonce
    )
);
~~~

Any system deriving this hash must follow *exactly* the same encoding rules.

---

## 3. Domain Separator (EIP-712)

Each verification environment constructs a domain separator:

~~~solidity
bytes32 EIP712_DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,address verifyingContract,uint256 chainId)"
);

domainSeparator = keccak256(
    abi.encode(
        EIP712_DOMAIN_TYPEHASH,
        keccak256(bytes(name)),
        keccak256(bytes(version)),
        verifyingContract,
        chainId
    )
);
~~~

**RIP-009 requires only that systems wishing to interoperate produce the same `domainSeparator`.**  
It does **not** mandate how domains must be chosen; it only defines what happens when they match.

---

## 4. Authorization Digest

RIP-001 and RIP-009 use the EIP-712 digest:

~~~solidity
digest = keccak256(
    abi.encodePacked(
        "\x19\x01",
        domainSeparator,
        structHash
    )
);
~~~

This digest is the **authorization identity** for the Authorization within that domain.

---

## 5. The Cross-System Authorization Identity

### 5.1 Definition

Let two systems A and B compute:

- `domainSeparator_A`, `domainSeparator_B`  
- `structHash_A(Auth)`, `structHash_B(Auth)`

They share an **authorization identity** *iff*:

~~~text
domainSeparator_A == domainSeparator_B
structHash_A(Auth) == structHash_B(Auth)
~~~

Equivalently, their EIP-712 digest is identical:

~~~text
digest_A(Auth) == digest_B(Auth)
~~~

---

### 5.2 Consequence: Signature Equivalence

ECDSA validity depends only on:

- the message (`digest`)
- the signature bytes (`v, r, s`)
- the public key (implicitly recovered)

Therefore, if:

~~~text
digest_A == digest_B
~~~

then:

~~~text
Verify_A(digest, sig) == Verify_B(digest, sig)
~~~

This is the **Cross-System Authorization Identity**.

No consensus, state, or chain-local metadata affects this outcome.

---

## 6. Relationship to RIP-009

RIP-009 standardizes:

- **how** systems must reconstruct the Authorization  
- **how** they must compute `structHash` and `domainSeparator`  
- **how** to perform verification deterministically  

The Cross-System Authorization Identity explains **why** RIP-009 works:

> If two systems compute the same inputs, they must compute the same verdict.

RIP-009 does **not** enforce domain policies — it defines the invariant that holds *when domain policies align*.

---

## 7. Boundary Conditions

The identity holds if:

- EIP-712 encoding is canonical and identical  
- hashing uses keccak256  
- both systems use secp256k1 ECDSA  
- the Authorization object matches byte-for-byte  
- `domainSeparator` matches exactly  

The identity fails if:

- domain parameters differ  
- Authorization fields differ  
- field ordering changes  
- encoding rules diverge  
- signature bytes are malformed  

---

## 8. Examples

### Example 1: Same domain, same struct → same verdict

Two systems implement the same executor contract address and chainId:

~~~text
domainSeparator_A = domainSeparator_B
structHash_A = structHash_B
digest_A = digest_B
signature validity matches
~~~

### Example 2: Different domain → different verdict

If chainId, version, verifyingContract, or name differ:

~~~text
domainSeparator_A != domainSeparator_B
digest_A != digest_B
signature validity differs
~~~

This is expected and correct.

---

## 9. Summary

The Cross-System Authorization Identity states:

> **Signature verification for a RIP-001 Authorization is identical across systems  
> when and only when they reconstruct the same `(domainSeparator, structHash)` pair.**

This invariant is not a new primitive — it is the structural implication of EIP-712’s deterministic hashing.

RIP-009 operationalizes this identity for cross-network authorization verification.

---

## 10. License

© 2025 Recur Labs — Released under CC BY 4.0.
