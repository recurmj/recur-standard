// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title EVMPPOAdapter — Domain adapter using RecurPullSafeV2
/// @notice Source adapter for domains where movement is executed via discrete PPO pulls
///         instead of a streaming channel.
/// @dev This assumes the grantor has already signed an Authorization for the grantee (which will be this adapter
///      or the CrossNetworkRebalancer), and that RecurPullSafeV2 will verify signature, cap, etc.
///      The adapter never touches funds; it just calls pull() on RecurPullSafeV2.
interface IRecurPullSafeV2 {
    struct Authorization {
        address grantor;
        address grantee;
        address token;
        address receiver;
        uint256 maxAmount;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }

    function pull(Authorization calldata a, bytes calldata signature, uint256 amount) external;
}

contract EVMPPOAdapter {
    IRecurPullSafeV2 public recurPull;

    // We pin a specific Authorization template hash in production to prevent replay with wrong params.
    // For simplicity here we leave that open and rely on upstream to pass correct Authorization.
    constructor(address recurPullAddr) {
        recurPull = IRecurPullSafeV2(recurPullAddr);
    }

    /// @notice Execute a single authorized pull on behalf of CrossNetworkRebalancer.
    /// @param a The signed Authorization from the grantor (the PPO object).
    /// @param signature The grantor's signature.
    /// @param finalReceiver Where funds should end up.
    /// @param amount Amount to move now.
    ///
    /// We override a.receiver at call time by passing finalReceiver in place of a.receiver
    /// is NOT possible directly because `a` is part of the signature.
    /// So: in a PPO adapter path, finalReceiver MUST match a.receiver.
    function executeAuthorizedPullPPO(
        IRecurPullSafeV2.Authorization calldata a,
        bytes calldata signature,
        address finalReceiver,
        uint256 amount
    ) external {
        require(finalReceiver == a.receiver, "receiver mismatch");
        recurPull.pull(a, signature, amount);
    }
}