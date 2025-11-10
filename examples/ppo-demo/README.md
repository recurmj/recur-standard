# PPO Demo — Permissioned Pull Object (Recur Standard)

*The minimal reproducible demo proving value can move by consent, not push.*

This is the **minimal reproducible demo** of a Permissioned Pull Object (PPO): the core primitive defined in RIP-001
and extended under RIP-002. It proves how value can move from one wallet to another **without a push transaction,** using signed and revocable consent.

It shows:

✅ Deploying the **Consent Registry** and **PullSafeV2**  
✅ Approving an ERC-20 token (like WETH)  
✅ Creating + signing a PPO (Authorization struct) with your wallet  
✅ Pulling value from grantor → grantee *without push*  
✅ Fully permissioned, revocable, and cryptographically enforced  

---

⚠️ All scripts assume Linux/macOS + Foundry ≥ 1.4.0. Tested on Sepolia and Base Sepolia.

## 0. Prerequisites

You need:

- Foundry installed (`forge`, `cast`)
- Node 18+ (optional but useful)
- A wallet private key with test ETH
- RPC URL for Sepolia (or Base Sepolia)

---

### 1. Clone & install

~~~
git clone https://github.com/recurmj/recur-standard.git
cd recur-standard/examples/ppo-demo
forge install   # installs deps if not done globally
~~~

---

### 2. Configure environment

Copy the example file:

~~~
cp .env.example .env
~~~

Then edit .env:

~~~
# RPC URL (Sepolia for example)
RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY

# Private Key (test wallet only!)
PRIVATE_KEY=0xyourprivatekey

# ERC-20 token to pull (Sepolia WETH test address example)
TOKEN_ADDRESS=0xdd13E55209Fd76AfE204dBda4007C227904f0a81

# PPO fields
MAX_PER_PULL=1000000000000000      # 0.001 ETH
VALID_AFTER=1762353314             # epoch start
VALID_BEFORE=1762439714            # epoch end
GRANTOR=0xYourGrantorAddress
GRANTEE=0xYourGranteeAddress
NONCE=0xa9dd5f5e04d05b...
~~~

Activate in terminal:

~~~
set -a; source .env; set +a
~~~

---

### 3. Deploy contracts

The deploy script uses your .env private key as **controller** (grantee) by default. You can later grant separate permissions for another grantor wallet.

~~~
./scripts/deploy_registry_and_pullsafe.sh
~~~

It outputs:

~~~
REGISTRY=0x...
PULLSAFE=0x...
~~~

---

### 4. Approve token allowance

Grant PullSafe permission to pull up to some limit:

~~~
./scripts/approve_token.sh
~~~

---

### 5. Sign the Authorization (PPO)

The signature uses EIP-712 typed data and is portable across chains.
This single signature is your *consent* object.

This creates & signs the structured data:

~~~
./scripts/sign_authorization.sh
~~~

Outputs:

~~~
STRUCT_HASH=0x...
DIGEST=0x...
SIG=0x...
AUTH_HASH=0x...
~~~

---

### 6. Execute the pull

~~~
./scripts/pull_once.sh 0.0005   # amount in ETH (≤ MAX_PER_PULL)
~~~

Check Etherscan — funds moved by *pull*, not push.

Confirm token balance increase after pull:

~~~
cast call $TOKEN_ADDRESS "balanceOf(address)(uint256)" $GRANTEE
~~~

---

### 7. Revoke (optional)

~~~
cast send $REGISTRY "revoke(bytes32)" $AUTH_HASH \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY
~~~

---

✅ You’ve just executed the first live Recur PPO.

Next steps (optional):

- Make grantee a *different address*

- Try on Base Sepolia

- Try registering the same authHash on another chain’s Registry (observe)

- Explore cross-chain continuity

---

📜 This demo respects RIP-001 and RIP-002 and uses the frozen v1 contracts.
🔒 Use only test keys + tokens. Never mainnet without audits.

You’ve just executed the first live Recur PPO — the foundation of the permissioned-pull standard.
Everything above runs in under 15 minutes with test ETH.

— **Recur Labs**  
*Defining the permissioned-pull standard for digital value.*
