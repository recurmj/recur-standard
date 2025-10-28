// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title UniversalClock — RIP-006 time slicing reference
/// @notice Provides canonical epoch indexing for flow accounting.
/// @dev Minimal reference. In production, this might incorporate L2 block hashes,
///      finality signals, etc. This is intentionally chain-local; multi-chain
///      coordination happens off-chain using signed epoch claims and can be settled.
contract UniversalClock {
    // epochLength in seconds (e.g. 1 second, 12 seconds, etc.)
    uint64 public immutable epochLength;
    uint64 public immutable genesisTimestamp;

    constructor(uint64 _epochLength) {
        require(_epochLength > 0, "epoch=0");
        epochLength = _epochLength;
        genesisTimestamp = uint64(block.timestamp);
    }

    /// @notice Returns the current epoch index since genesis.
    function currentEpoch() public view returns (uint64) {
        unchecked {
            return uint64((block.timestamp - genesisTimestamp) / epochLength);
        }
    }

    /// @notice Returns the start timestamp of a given epoch.
    function epochStart(uint64 epochId) external view returns (uint64) {
        return genesisTimestamp + (epochId * epochLength);
    }
}