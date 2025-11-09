# Cross-Chain Permissioned Pull (PPO Continuity Demo)

*Proves a single consent object can exist, verify, and move value across chains.*

This demo shows how a **single Permissioned Pull Object (PPO)** — a signed authorization — can be recognized on multiple chains with the **same hash, same owner, same consent.**

You will:
✔ Deploy Registry + PullSafe on Chain A  
✔ Create & sign a PPO (Authorization struct)  
✔ Execute a pull on Chain A  
✔ Deploy the same contracts on Chain B  
✔ Register (`observe`) the same authHash on Chain B  
✔ *(Optional)* pull on Chain B using the same signed consent  

This demonstrates the core principle of **consented continuity** from RIP-002 — that consent, not liquidity, is the transferable layer.

---

## 🌐 0. Environment

⚠️ Requires Foundry ≥ 1.4.3 and `cast` in PATH.

Copy `.env.example`:

~~~
cp .env.example .env
set -a; source .env; set +a
~~~

In .env, configure:

~~~
# Chain A = Ethereum Sepolia
RPC_A=https://sepolia.infura.io/v3/KEY
# Chain B = Base Sepolia
RPC_B=https://sepolia.base.org

PRIVATE_KEY=0xYOUR_TEST_KEY

# Token on each chain
TOKEN_A=0xdd13E55209Fd76AfE204dBda4007C227904f0a81   # Sepolia WETH mock
TOKEN_B=0x4200000000000000000000000000000000000006  # Base Sepolia WETH

# PPO fields (same for both chains)
MAX_PER_PULL=1000000000000000
VALID_AFTER=1762353314
VALID_BEFORE=1762439714
NONCE=0xa9dd5f5e04d05bf6ad269c8cd20f9a1700c9072ec...
~~~

Quickly check both chains:

~~~
cast chain-id --rpc-url $RPC_A
cast chain-id --rpc-url $RPC_B
~~~

---

### 1. Deploy Registry + PullSafe on Chain A

~~~
./scripts/1_deploy_chainA.sh
~~~

Saves:
~~~
REGISTRY_A=0x...
PULLSAFE_A=0x...
~~~

---

### 2. Approve token → Sign PPO → Pull on Chain A

~~~
./scripts/2_sign_and_pull_chainA.sh
~~~

You will now have:

- `AUTH_HASH=0x...` **← the global consent identifier**

- A successful pull transaction on Chain A

This confirms the PPO is valid and produces the canonical `authHash` you will later re-observe.

---

### 3. Deploy on Chain B

Both deployments can use the same wallet; roles remain identical across chains.

~~~
./scripts/3_deploy_chainB.sh
~~~

Outputs:

~~~
REGISTRY_B=0x...
PULLSAFE_B=0x...
~~~


Trust executor:

~~~
cast send $REGISTRY_B "setTrustedExecutor(address,bool)" $PULLSAFE_B true \
  --rpc-url $RPC_B --private-key $PRIVATE_KEY
~~~

---

### 4. Register (Observe) the Same Consent on Chain B

Two possible approaches depending on your Registry version:

Use **A)** if your Registry only needs the hash to verify existence.
Use **B)** if you want full signature proof stored on-chain (stronger attestation).

**A) Hash-only mode:**

~~~
cast send $REGISTRY_B "observe(bytes32,address)" $AUTH_HASH $GRANTOR \
  --rpc-url $RPC_B --private-key $PRIVATE_KEY
~~~

**B) Full Authorization + Signature:**

~~~
cast send $REGISTRY_B \
  "observe((address,address,address,uint256,uint256,uint256,bytes32),bytes)" \
  "($GRANTOR,$GRANTEE,$TOKEN_A,$MAX_PER_PULL,$VALID_AFTER,$VALID_BEFORE,$NONCE)" \
  $SIG_A \
  --rpc-url $RPC_B --private-key $PRIVATE_KEY
~~~

Verification to show the event emission:

~~~
cast logs --from-block latest --rpc-url $RPC_B | grep AuthorizationObserved
~~~

Check registry:

~~~
cast call $REGISTRY_B "ownerOf(bytes32)(address)" $AUTH_HASH --rpc-url $RPC_B
~~~

Expected result = grantor address.

---

### 5. *(Optional)* Execute Pull on Chain B

Only possible if:

- You also `approve()` TOKEN_B to PullSafe_B

- You re-sign the PPO for **Chain B’s domain** (chainId differs)

- Or: you design domain to exclude chainId (advanced case)

Executing a pull on B proves continuity of **intent**, not shared liquidity — the consent layer now bridges trust, not tokens.

---

### ✅ Result

You have proven:
✔ The same permissioned pull **exists & is recognized across chains**
✔ No bridge, no liquidity wrapping; just shared consent
✔ One PPO → multi-chain continuity

---

### 🛑 Security Disclaimer

- Use test keys / RPCs only

- This is a prototype, not audited

- Never publish your real private key

---

**Next:** Mirror revocation, mirror partial-cap usage, or chain-to-chain liquidity pull.

— **Recur Labs**  
*Recur v1 — Defining the permissioned-pull standard for digital value.*
