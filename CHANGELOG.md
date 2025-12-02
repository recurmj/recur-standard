# Changelog — v1.1 (December 2025)

## Updated

## - RIP-001: Permissioned Pull

  - Patched race condition on `ownerOfAuth` in `RecurConsentRegistry.sol`

  - Improved EIP-712 enforcement and signature verification

  - Added SafeERC20 wrappers for transferFrom()

## - RIP-002: Consent Registry

  - Updated SDK & contract consistency (validAfter, metadataHash)

  - Added reentrancy guards on critical functions

  - Minor gas optimizations

## Status

- All critical/high audit issues resolved

- Medium/low issues documented for future improvements

- v1.1 ready for pilot deployment
