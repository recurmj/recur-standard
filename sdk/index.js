// Minimal helpers to compose/sign Authorization payloads (browser or Node)
export function composeAuthorization({
  grantor, grantee, token, to, amount, start, expiry, scope, nonce
}) {
  return { grantor, grantee, token, to, amount, start, expiry, scope, nonce };
}

export const AUTH_TYPES = {
  Authorization: [
    { name: "grantor", type: "address" },
    { name: "grantee", type: "address" },
    { name: "token",   type: "address" },
    { name: "to",      type: "address" },
    { name: "amount",  type: "uint256" },
    { name: "start",   type: "uint256" },
    { name: "expiry",  type: "uint256" },
    { name: "scope",   type: "bytes32" },
    { name: "nonce",   type: "bytes32" }
  ]
};

// sign with EIP-712 via ethers.js signer._signTypedData
export async function signAuthorization(signer, verifyingContract, auth) {
  const domain = {
    name: "RecurPull",
    version: "1",
    chainId: await signer.getChainId?.() ?? (await signer.provider.getNetwork()).chainId,
    verifyingContract
  };
  const signature = await signer._signTypedData(domain, AUTH_TYPES, auth);
  return signature;
}
