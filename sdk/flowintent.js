// sdk/flowIntent.js

import { keccak256, toUtf8Bytes } from "ethers";

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// Deterministic domain ID helper.
// You should use this to produce the bytes32 IDs that all on-chain logic expects.
// Example:
//   const src = domainId("base:treasury");
//   const dst = domainId("ethereum:settlement");
export function domainId(humanReadable) {
  return keccak256(toUtf8Bytes(humanReadable));
}

// Nonce helper: if caller doesn't pass a nonce, we generate a bytes32 nonce.
// You can also pass your own (must already be 0x-prefixed 32-byte hex).
function ensureBytes32Nonce(nonce) {
  if (nonce) return nonce;
  // super simple uniqueness seed: timestamp + random
  const seed = `${Date.now()}::${Math.random()}`;
  return keccak256(toUtf8Bytes(seed)); // returns 0x...32 bytes
}

// -----------------------------------------------------------------------------
// FlowIntent builder
// -----------------------------------------------------------------------------

// A Flow Intent declares cross-domain rebalancing rights.
// Grantor authorizes an executor to move up to maxAmount of `token`
// from sourceDomain -> destDomain, until validBefore.
//
// STRUCT SHAPE (must match FlowIntentRegistry + CrossNetworkRebalancer):
// {
//   grantor:      address
//   executor:     address
//   sourceDomain: bytes32
//   destDomain:   bytes32
//   token:        address
//   maxAmount:    uint256
//   validBefore:  uint256 (unix seconds)
//   nonce:        bytes32
// }
//
// NOTE: We intentionally do NOT include "signature" here. That's attached
// after signing, and ultimately submitted in executeFlowIntent().
export function buildFlowIntent({
  grantor,
  executor,
  token,
  sourceDomain,
  destDomain,
  maxAmount,
  validBefore,
  nonce,
}) {
  return {
    grantor,
    executor,
    token,
    sourceDomain, // MUST be bytes32 (use domainId("base:treasury") etc.)
    destDomain,   // MUST be bytes32
    maxAmount,
    validBefore,
    nonce: ensureBytes32Nonce(nonce),
  };
}

// -----------------------------------------------------------------------------
// EIP-712 type data for signing
// -----------------------------------------------------------------------------

// This MUST exactly match the Solidity struct that gets hashed and verified in
// FlowIntentRegistry.verifyAndConsume().
//
// VERY IMPORTANT:
// - sourceDomain/destDomain are bytes32
// - nonce is bytes32
// - We do NOT sign "validAfter" here because this minimal SDK version matches
//   the reduced-intent form (validBefore-only) that your current frontend
//   UX is building. If/when you add validAfter or metadataHash to the contract,
//   you'll have to add them BOTH to this type AND to the struct hash or
//   signature recovery will break.
export const FLOW_INTENT_TYPES = {
  FlowIntent: [
    { name: "grantor",      type: "address" },
    { name: "executor",     type: "address" },
    { name: "token",        type: "address" },
    { name: "sourceDomain", type: "bytes32" },
    { name: "destDomain",   type: "bytes32" },
    { name: "maxAmount",    type: "uint256" },
    { name: "validBefore",  type: "uint256" },
    { name: "nonce",        type: "bytes32" },
  ],
};

// -----------------------------------------------------------------------------
// Signer helper
// -----------------------------------------------------------------------------

// signFlowIntent()
// Produces an EIP-712 signature from the GRANTOR over the FlowIntent.
//
// signer:              ethers.Signer for the grantor wallet
// verifyingContract:   address of CrossNetworkRebalancer (the contract that
//                      ultimately consumes these intents on this chain)
// intent:              object from buildFlowIntent()
//
// Returns:
// {
//   intent: <the struct that was signed (without signature)>,
//   signature: 0x....
// }
//
// You then send { ...intent, signature } + amount to executeFlowIntent() on-chain.
export async function signFlowIntent(signer, verifyingContract, intent) {
  const chainId =
    (await signer.getChainId?.()) ??
    (await signer.provider.getNetwork()).chainId;

  const domain = {
    name: "CrossNetworkRebalancer",
    version: "1",
    chainId,
    verifyingContract,
  };

  const { nonce, ...rest } = intent;
  const finalizedIntent = { ...intent, nonce }; // make sure nonce is bytes32

  const signature = await signer._signTypedData(
    domain,
    FLOW_INTENT_TYPES,
    finalizedIntent
  );

  return {
    intent: finalizedIntent,
    signature,
  };
}

// -----------------------------------------------------------------------------
// submitFlowIntent()
// Optional convenience helper to actually call the on-chain rebalancer.
//
// rebalancerContract: ethers.Contract bound to CrossNetworkRebalancer
// signed: result of signFlowIntent()
// amount: how much to move in this step
//
// NOTE: CrossNetworkRebalancer also needs the PPO/channel authHash etc. in the
// final struct. Frontend / ops will build that wrapper object before calling
// executeFlowIntent() directly. This helper is kept minimal on purpose.
export async function submitFlowIntent({
  rebalancerContract,
  signed,
  amount,
}) {
  // CrossNetworkRebalancer.executeFlowIntent() in production expects a
  // "FlowIntentFull"-style struct that includes authHash + signature + etc.
  // That wrapper composition is app-specific, so this is a placeholder.
  return rebalancerContract.executeFlowIntent(
    {
      ...signed.intent,
      signature: signed.signature,
      // caller must still attach authHash etc. before this will succeed on-chain
    },
    amount
  );
}
