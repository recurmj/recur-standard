// sdk/registry.js
// registryContract is an ethers.Contract bound to RecurConsentRegistry on-chain

// Check if a PPO (by its authHash) has been revoked
export async function isRevoked(registryContract, authHash) {
  return registryContract.isRevoked(authHash);
}

// Get total amount pulled under this authHash so far
export async function pulledTotal(registryContract, authHash) {
  return registryContract.pulledTotal(authHash);
}

// Get configured soft cap (if tracked by this registry)
export async function capOf(registryContract, authHash) {
  return registryContract.capOf(authHash);
}

// Grantor calls this to revoke consent for a PPO
export async function revoke(registryContract, authHash, overrides = {}) {
  // This will emit AuthorizationRevoked in the registry
  return registryContract.revoke(authHash, overrides);
}