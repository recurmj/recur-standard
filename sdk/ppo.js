// sdk/ppo.js
// Minimal helpers for RIP-001 (Permissioned Pull Object / PPO)
// This produces the exact struct that RecurPullSafeV2 expects on-chain.

export function buildPPO({
  grantor,
  grantee,
  token,
  maxPerPull,    // max allowed per pull() call
  validAfter,    // earliest usable timestamp (unix seconds)
  validBefore,   // latest usable timestamp (unix seconds)
  nonce,         // unique salt to prevent replay collisions
}) {
  return {
    grantor,
    grantee,
    token,
    maxPerPull,
    validAfter,
    validBefore,
    nonce,
  };
}

export const PPO_TYPES = {
  PermissionedPullObject: [
    { name: "grantor",     type: "address" },
    { name: "grantee",     type: "address" },
    { name: "token",       type: "address" },
    { name: "maxPerPull",  type: "uint256" },
    { name: "validAfter",  type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce",       type: "uint256" },
  ],
};

// EIP-712 signing helper.
// signer: ethers.Signer that controls the grantor wallet
// verifyingContract: address of the deployed RecurPullSafeV2 on this chain
export async function signPPO(signer, verifyingContract, ppo) {
  const chainId =
    (await signer.getChainId?.()) ??
    (await signer.provider.getNetwork()).chainId;

  const domain = {
    name: "RecurPullSafeV2",
    version: "1",
    chainId,
    verifyingContract,
  };

  const signature = await signer._signTypedData(domain, PPO_TYPES, ppo);

  // Return a "signedPPO" object ready to submit to pull()
  // RecurPullSafeV2.pull() will:
  //   - recompute this struct hash
  //   - verify this signature matches ppo.grantor
  //   - enforce timing + per-call cap + revocation
  return {
    ...ppo,
    signature,
  };
}
