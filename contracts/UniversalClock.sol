// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title UniversalClock — RIP-006 time slicing reference (final)
/// @notice Provides canonical epoch indexing for flow and policy accounting.
/// @dev
/// - Chain-local, deterministic, non-upgradable.
/// - Multi-chain coordination happens off-chain using signed epoch claims.
/// - Used by FlowChannelHardened, PolicyEnforcer, and routers for consistent time windows.
///
/// Example:
///   epochLength = 60  →  each epoch = 60 seconds.
///   genesisTimestamp = deploy time.
///   currentEpoch() → index since genesis (0,1,2,...)
///
/// @custom:version 1.0.0
/// @custom:author  Recur Labs
contract UniversalClock {
    /// -----------------------------------------------------------------------
    /// Immutable parameters
    /// -----------------------------------------------------------------------
    uint64 public immutable epochLength;      // seconds per epoch
    uint64 public immutable genesisTimestamp; // deployment timestamp

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------
    /// @param _epochLength Duration of one epoch in seconds (e.g. 1, 12, 60, 3600).
    ///        Shorter epochs = finer granularity for streaming or budget resets.
    constructor(uint64 _epochLength) {
        require(_epochLength > 0, "EPOCH_ZERO");
        epochLength = _epochLength;
        genesisTimestamp = uint64(block.timestamp);
    }

    /// -----------------------------------------------------------------------
    /// Views
    /// -----------------------------------------------------------------------

    /// @notice Current epoch index since genesis.
    /// @dev Index 0 starts at deployment time; increments every epochLength seconds.
    function currentEpoch() public view returns (uint64) {
        unchecked {
            return uint64((block.timestamp - genesisTimestamp) / epochLength);
        }
    }

    /// @notice Start timestamp of a given epoch.
    /// @param epochId Epoch index to query.
    function epochStart(uint64 epochId) external view returns (uint64) {
        return genesisTimestamp + (epochId * epochLength);
    }

    /// @notice Seconds remaining until next epoch boundary.
    /// @dev Useful for off-chain tick schedulers or testing.
    function secondsUntilNextEpoch() external view returns (uint64) {
        uint64 nowTs = uint64(block.timestamp);
        uint64 next = ((nowTs - genesisTimestamp) / epochLength + 1) * epochLength + genesisTimestamp;
        return next > nowTs ? next - nowTs : 0;
    }
}
