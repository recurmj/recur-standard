# Formal Definition of κ₍c₎  
### A Coordination Invariant for Authorization Verification  
*by Mats Heming Julner*  

**Version 1.0**  

---

## 1. Overview

κ₍c₎ denotes the **coordination invariant** that determines when two independent execution environments produce **identical authorization identity** for a given signed object.

This invariant enables **portable, custody-independent authorization** across heterogeneous systems.

κ₍c₎ is **not**:

- a physical constant  
- a universal law of computation  
- a cryptographic breakthrough  

It is a **structural property** of a class of computational environments that implement:

1. deterministic hashing  
2. canonical structured-data encoding  
3. digital signature verification  

---

## 2. Computational Environment Model

Let an execution environment be defined as:

~~~text
E = (H_E, S_E, V_E, enc_E)
~~~

Where:

- `H_E : bytes → bytes32` — deterministic hashing  
- `S_E : (bytes32, signature, address) → bool` — signature verification  
- `enc_E : A → bytes` — canonical structured-data encoder  
- `V_E : (D(E), H(A), sig) → {true, false}` — full authorization verifier  

Two environments **E₁** and **E₂** are **coordination-equivalent** if:

~~~text
enc₁(A) = enc₂(A)
H₁(x) = H₂(x)      for all bytes x
S₁ = S₂            identical verification semantics
~~~

κ₍c₎ applies only to coordination-equivalent environments.

---

## 3. Authorization Object

Let the authorization object be the tuple:

~~~text
A = (
    grantor,
    grantee,
    token,
    maxAmount,
    validAfter,
    validBefore,
    nonce
)
~~~

Define its **struct hash**:

~~~text
structHash(A) = H( enc(A) )
~~~

Define the **domain separator** of environment `E`:

~~~text
D(E) = H( enc( Domain(E) ) )
~~~

(as in EIP-712).

---

## 4. Consent Digest

Define the **consent digest** of authorization object `A` in environment `E`:

~~~text
C(E, A) = H( 0x1901 || D(E) || structHash(A) )
~~~

`C(E, A)` is the **identity** of `A` inside `E`.

---

## 5. The κ₍c₎ Invariant

κ₍c₎ specifies when two environments interpret an authorization object as **identical**.

### Formal Definition

Authorization object `A` satisfies κ₍c₎ across `E₁` and `E₂` **iff**:

~~~text
C(E₁, A) = C(E₂, A)
~~~

Expanding:

~~~text
H(0x1901 || D(E₁) || structHash(A))
=
H(0x1901 || D(E₂) || structHash(A))
~~~

Since `H` is collision-resistant, this equality holds **iff**:

~~~text
D(E₁) = D(E₂)
structHash(A) identical in both environments
~~~

### Interpretation

If these conditions hold, any valid signature over `C(E₁, A)` also verifies over `C(E₂, A)`.

Thus:

~~~text
κ₍c₎ =
    "Authorization identity is preserved
     when (domainSeparator, structHash) are preserved."
~~~

---

## 6. Consequence: Portable Authorization

Given:

- a signature `sig`
- a grantor address `g`

If:

~~~text
C(E₁, A) = C(E₂, A)
~~~

Then:

~~~text
V(E₁, A, sig) = V(E₂, A, sig)
~~~

Therefore, authorization:

- survives cross-chain  
- survives cross-client  
- survives custody changes  
- survives execution-boundary changes  
- remains valid without shared state or bridges  

This enables **pull-based value flow** across heterogeneous systems.

---

## 7. Scope & Limitations

κ₍c₎ applies only when:

- encoding is canonical  
- hashing is deterministic  
- domain separators match  
- signature scheme is identical  
- the authorization object is byte-identical  

Outside these conditions, κ₍c₎ does not apply.

---

## 8. Relation to RIP-001 / RIP-002

RIP-001 and RIP-002 define the canonical authorization object A, encoding rules,
and minimal verification logic. RIP-009 defines the cross-system observation and
verification context in which κ₍c₎ is applied. κ₍c₎ is the invariant that enables
these specifications to operate consistently across heterogeneous environments.



---
