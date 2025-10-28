// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title RecurConsentRegistry
/// @notice RIP-002 Consent / Revocation Registry for permissioned-pull (RIP-001).
///
/// @dev
/// This contract is the canonical index for:
///   - whether a given Permissioned Pull Object (PPO / Authorization) is still valid,
///   - how much value has actually been pulled under it so far,
///   - optional soft caps / budgets for reporting,
///   - canonical events that wallets / auditors / explorers can consume.
///
/// SECURITY MODEL:
/// - We bind each `authHash` to an `owner` (the grantor) the first time we ever
///   see a real pull recorded for that authHash. After that, ONLY that owner
///   can revoke() future use of the authHash.
/// - `recordPull()` is **restricted to trusted executors** (e.g. RecurPullSafeV2,
///   CrossNetworkRebalancer, etc.). Governance (controller) manages that allowlist.
///   This prevents griefers from spoofing pulls, stealing ownership, or polluting totals.
///
/// - This registry never moves funds; it only records state.
///
/// NOTE ABOUT observe():
/// - observe() is advisory / cosmetic. It can be spoofed. Downstream wallets MUST
///   NOT treat observe() as proof of consent.
contract RecurConsentRegistry {
    /// -----------------------------------------------------------------------
    /// Storage
    /// -----------------------------------------------------------------------

    // authHash => has this Authorization been revoked?
    mapping(bytes32 => bool) public revoked;

    // authHash => cumulative amount pulled so far (accounting / audit trail)
    mapping(bytes32 => uint256) public totalPulled;

    // OPTIONAL: advertised soft cap / budget for UI & compliance dashboards.
    // This is not enforced here.
    mapping(bytes32 => uint256) public capOfAuth;

    // authHash => canonical grantor (the party who gave consent)
    //
    // We set this once, the FIRST time recordPull() is called for that authHash.
    // After set, only this address may revoke() or setCap() for that authHash.
    mapping(bytes32 => address) public ownerOfAuth;

    // controller (Safe / governance multisig) that curates `trustedExecutor`.
    address public controller;

    // executor address => allowed to call recordPull()
    mapping(address => bool) public trustedExecutor;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    /// @notice Emitted when a pull succeeds under a still-valid Authorization.
    /// @dev Indexers can reconstruct flow history and running totals per authHash.
    /// Topics:
    ///   authHash (idx 1), token (idx 2), grantor (idx 3)
    event PullExecuted(
        bytes32 indexed authHash,
        address indexed token,
        address indexed grantor,
        address grantee,
        uint256 amount,
        uint256 cumulative // totalPulled[authHash] after this pull
    );

    /// @notice Emitted when a grantor revokes an Authorization.
    /// @dev After this, compliant executors MUST refuse further pulls for this authHash.
    event AuthorizationRevoked(
        bytes32 indexed authHash,
        address indexed grantor,
        uint256 timestamp
    );

    /// @notice Emitted when a soft cap (budget) is set or updated.
    /// @dev Off-chain risk / compliance tooling can diff old/new.
    event AuthorizationBudgetUpdated(
        bytes32 indexed authHash,
        uint256 oldCap,
        uint256 newCap
    );

    /// @notice Optional discovery hook (advisory only).
    event AuthorizationObserved(
        bytes32 indexed authHash,
        address indexed grantor,
        address indexed grantee,
        address token
    );

    event ControllerUpdated(address indexed newController);
    event ExecutorTrusted(address indexed executor, bool trusted);

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    modifier onlyController() {
        require(msg.sender == controller, "NOT_CONTROLLER");
        _;
    }

    modifier onlyTrustedExecutor() {
        require(trustedExecutor[msg.sender], "NOT_TRUSTED_EXECUTOR");
        _;
    }

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    constructor(address initialController) {
        require(initialController != address(0), "BAD_CONTROLLER");
        controller = initialController;
    }

    /// @notice Governance rotates controller (multisig / Safe).
    function setController(address next) external onlyController {
        require(next != address(0), "BAD_CONTROLLER");
        controller = next;
        emit ControllerUpdated(next);
    }

    /// @notice Governance updates which executors are allowed to call recordPull().
    function setTrustedExecutor(address exec, bool allowed) external onlyController {
        trustedExecutor[exec] = allowed;
        emit ExecutorTrusted(exec, allowed);
    }

    /// -----------------------------------------------------------------------
    /// Write functions
    /// -----------------------------------------------------------------------

    /// @notice Grantor revokes consent for this authHash.
    /// @dev
    ///  - Only the bound grantor (ownerOfAuth[authHash]) may revoke.
    ///  - If the authHash has never been used (no recordPull() yet), there is
    ///    no ownerOfAuth[authHash] and this will revert with UNKNOWN_AUTH.
    ///  - After revocation, any compliant pull() MUST revert for this authHash.
    function revoke(bytes32 authHash) external {
        address owner = ownerOfAuth[authHash];
        require(owner != address(0), "UNKNOWN_AUTH");
        require(msg.sender == owner, "NOT_GRANTOR");

        revoked[authHash] = true;

        emit AuthorizationRevoked({
            authHash:  authHash,
            grantor:   msg.sender,
            timestamp: block.timestamp
        });
    }

    /// @notice Optional discovery hook so UIs / indexers can surface "this consent may exist".
    /// @dev
    ///  - ADVISORY ONLY. Anyone can call this.
    ///  - Does NOT prove validity, does NOT assign ownership, does NOT imply pullability.
    function observe(
        bytes32 authHash,
        address grantor,
        address grantee,
        address token
    ) external {
        emit AuthorizationObserved({
            authHash: authHash,
            grantor:  grantor,
            grantee:  grantee,
            token:    token
        });
    }

    /// @notice Record a successful pull for accounting / audit trail.
    /// @dev
    ///  - ONLY callable by trusted executors.
    ///  - MUST be called only *after* the actual ERC-20 transferFrom()
    ///    (grantor -> grantee) has succeeded in the executor contract.
    ///
    /// Effects:
    ///  - Increments totalPulled[authHash].
    ///  - If first-ever pull for `authHash`, permanently binds that hash to `grantor`
    ///    as ownerOfAuth[authHash], which controls future revoke() and setCap().
    ///
    /// Emits PullExecuted(authHash, token, grantor, grantee, amount, cumulative).
    function recordPull(
        bytes32 authHash,
        address token,
        address grantor,
        address grantee,
        uint256 amount
    ) external onlyTrustedExecutor {
        // Bind the canonical owner (grantor) on first use.
        if (ownerOfAuth[authHash] == address(0)) {
            ownerOfAuth[authHash] = grantor;
        }

        uint256 newTotal = totalPulled[authHash] + amount;
        totalPulled[authHash] = newTotal;

        emit PullExecuted({
            authHash:   authHash,
            token:      token,
            grantor:    grantor,
            grantee:    grantee,
            amount:     amount,
            cumulative: newTotal
        });
    }

    /// @notice Set or update an advertised budget / soft cap for analytics & UI.
    /// @dev
    ///  - NOT enforced here.
    ///  - Only the canonical grantor (ownerOfAuth[authHash]) can set / update.
    ///  - Downstream systems can use this as "declared exposure ceiling."
    function setCap(bytes32 authHash, uint256 newCap) external {
        address owner = ownerOfAuth[authHash];
        require(owner != address(0), "UNKNOWN_AUTH");
        require(msg.sender == owner, "NOT_GRANTOR");

        uint256 oldCap = capOfAuth[authHash];
        capOfAuth[authHash] = newCap;

        emit AuthorizationBudgetUpdated({
            authHash: authHash,
            oldCap:   oldCap,
            newCap:   newCap
        });
    }

    /// -----------------------------------------------------------------------
    /// Read functions
    /// -----------------------------------------------------------------------

    /// @notice True if this authHash has been revoked.
    /// @dev Execution contracts MUST check this before honoring a pull.
    function isRevoked(bytes32 authHash) external view returns (bool) {
        return revoked[authHash];
    }

    /// @notice Total cumulative amount recorded as pulled under this authHash.
    /// @dev Indexers / auditors can use this for exposure reporting.
    function pulledTotal(bytes32 authHash) external view returns (uint256) {
        return totalPulled[authHash];
    }

    /// @notice Advisory soft cap / budget for this authHash (0 if unset).
    function capOf(bytes32 authHash) external view returns (uint256) {
        return capOfAuth[authHash];
    }

    /// @notice Which address currently controls this authHash's revocation rights.
    /// @dev Will be zero address until the first successful recordPull() by a trusted executor.
    function ownerOf(bytes32 authHash) external view returns (address) {
        return ownerOfAuth[authHash];
    }
}
