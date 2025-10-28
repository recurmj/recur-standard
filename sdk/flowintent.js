// sdk/flowIntent.js

// A Flow Intent declares cross-domain rebalancing rights.
// Grantor authorizes an executor to shift liquidity from sourceDomain -> destDomain.

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
    sourceDomain,
    destDomain,
    maxAmount,
    validBefore,
    nonce,
  };
}

export const FLOW_INTENT_TYPES = {
  FlowIntent: [
    { name: "grantor",      type: "address" },
    { name: "executor",     type: "address" },
    { name: "token",        type: "address" },
    { name: "sourceDomain", type: "string"  },
    { name: "destDomain",   type: "string"  },
    { name: "maxAmount",    type: "uint256" },
    { name: "validBefore",  type: "uint256" },
    { name: "nonce",        type: "uint256" },
  ],
};

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

  const sig = await signer._signTypedData(domain, FLOW_INTENT_TYPES, intent);
  return sig;
}

// optional helper to send to on-chain rebalancer contract
export async function submitFlowIntent({
  rebalancerContract,
  signedIntent,
  amount,
}) {
  return rebalancerContract.executeFlowIntent(signedIntent, amount);
}
