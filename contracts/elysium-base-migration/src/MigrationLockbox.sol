// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20Lockbox {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @notice Irrevocably locks the existing Elysium PHNTMOP token for a Base migration.
/// @dev This contract intentionally has no administrative withdrawal or upgrade path.
contract MigrationLockbox {
    error ZeroAddress();
    error ZeroAmount();
    error TokenTransferFailed();
    error InsufficientLockedBalance(uint256 expected, uint256 actual);
    error Reentrancy();

    event DepositLocked(
        bytes32 indexed depositId,
        uint256 indexed nonce,
        address indexed depositor,
        address baseRecipient,
        uint256 amount
    );

    IERC20Lockbox public immutable token;
    uint256 public nextNonce;
    uint256 public totalLocked;
    uint256 private entered;

    constructor(address token_) {
        if (token_ == address(0)) revert ZeroAddress();
        token = IERC20Lockbox(token_);
    }

    modifier nonReentrant() {
        if (entered != 0) revert Reentrancy();
        entered = 1;
        _;
        entered = 0;
    }

    /// @notice Lock exact Elysium PHNTMOP and bind the deposit to a Base recipient.
    /// @return depositId Unique evidence identifier for off-chain Safe verification.
    function deposit(uint256 amount, address baseRecipient) external nonReentrant returns (bytes32 depositId) {
        if (amount == 0) revert ZeroAmount();
        if (baseRecipient == address(0)) revert ZeroAddress();

        // Commit accounting before the external token call; any failed transfer reverts it.
        uint256 nonce = nextNonce;
        nextNonce = nonce + 1;
        uint256 lockedAfter = totalLocked + amount;
        totalLocked = lockedAfter;

        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        uint256 actualLocked = token.balanceOf(address(this));
        if (actualLocked < lockedAfter) revert InsufficientLockedBalance(lockedAfter, actualLocked);

        depositId = keccak256(abi.encode(block.chainid, address(this), nonce, msg.sender, baseRecipient, amount));
        emit DepositLocked(depositId, nonce, msg.sender, baseRecipient, amount);
    }
}
