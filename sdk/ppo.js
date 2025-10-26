// Minimal helpers for RIP-001 (Permissioned Pull Object / PPO)

export function buildPPO({
  grantor,
  grantee,
  token,
  receiver,     // where funds should land
  maxAmount,    // total authorized
  validAfter,   // earliest usable timestamp
  validBefore,  // latest usable timestamp
  nonce,
}) {
  return {
    grantor,
    grantee,
    token,
    receiver,
    maxAmount,
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
    { name: "receiver",    type: "address" },
    { name: "maxAmount",   type: "uint256" },
    { name: "validAfter",  type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce",       type: "uint256" },
  ],
};

// EIP-712 signing helper
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
  return signature;
}
