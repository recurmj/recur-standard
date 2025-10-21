/**
 * Recur SDK (minimal) – helpers to encode and sign RIP-001 Authorization.
 * This is intentionally tiny; production apps should prefer EIP-712.
 */
export function hashAuthorization(a) {
  const enc = JSON.stringify({
    grantor:a.grantor, grantee:a.grantee, token:a.token, to:a.to,
    maxAmount:String(a.maxAmount), totalCap:String(a.totalCap),
    validAfter:a.validAfter, validBefore:a.validBefore, nonce:a.nonce
  });
  return globalThis.keccak256(enc); // supply your own keccak util
}

export async function signAuthorization(wallet, a) {
  const h = hashAuthorization(a);
  return await wallet.signMessage({ raw: h });
}

export async function callPull(contract, a, amount, signature) {
  return await contract.write.pull([a, amount, signature]);
}
