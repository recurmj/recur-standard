// sdk/pull.js
// pullContract: ethers.Contract bound to RecurPullSafeV2 on-chain
// registryContract: ethers.Contract bound to RecurConsentRegistry on-chain
// signedPPO: the Permissioned Pull Object (PPO) fields + { signature }
//            (same shape as RecurPullSafeV2.Authorization)

export function canExecuteNow(signedPPO, requestedAmount, nowSec = undefined) {
  const nowTs = nowSec ?? Math.floor(Date.now() / 1000);

  const tooEarly = nowTs < Number(signedPPO.validAfter);
  const tooLate  = nowTs > Number(signedPPO.validBefore);
  const tooMuch  = BigInt(requestedAmount) > BigInt(signedPPO.maxPerPull);

  if (tooEarly) return { ok: false, reason: "too early" };
  if (tooLate)  return { ok: false, reason: "expired" };
  if (tooMuch)  return { ok: false, reason: "exceeds maxPerPull" };

  return { ok: true };
}

// Optional preflight before calling pull()
// Checks time window, per-call limit, and revocation state in the Consent Registry.
export async function verifyBeforePull({
  registryContract,
  authHash,        // must be authHashOf(signedPPO) from RecurPullSafeV2
  signedPPO,
  requestedAmount,
}) {
  const timingCheck = canExecuteNow(signedPPO, requestedAmount);
  if (!timingCheck.ok) return timingCheck;

  const revoked = await registryContract.isRevoked(authHash);
  if (revoked) return { ok: false, reason: "revoked" };

  return { ok: true };
}

// Execute pull() on-chain from the grantee side.
// IMPORTANT: pullContract must be connected with a signer whose address
//            equals signedPPO.grantee, or RecurPullSafeV2 will revert "NOT_AUTHORIZED".
// The pull contract itself will re-check signature, registry state, timing, and cap.
export async function executePull({
  pullContract,
  signedPPO,
  requestedAmount,
}) {
  return pullContract.pull(signedPPO, requestedAmount);
}
