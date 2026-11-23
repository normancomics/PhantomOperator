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
    error UnexpectedReceivedAmount(uint256 expected, uint256 received);

    event DepositLocked(
        bytes32 indexed depositId,
        uint256 indexed nonce,
        address indexed depositor,
        address baseRecipient,
        uint256 amount
    );

    IERC20Lockbox public immutable token;
    uint256 public nextNonce;

    constructor(address token_) {
        if (token_ == address(0)) revert ZeroAddress();
        token = IERC20Lockbox(token_);
    }

    /// @notice Lock exact Elysium PHNTMOP and bind the deposit to a Base recipient.
    /// @return depositId Unique evidence identifier for off-chain Safe verification.
    function deposit(uint256 amount, address baseRecipient) external returns (bytes32 depositId) {
        if (amount == 0) revert ZeroAmount();
        if (baseRecipient == address(0)) revert ZeroAddress();

        uint256 balanceBefore = token.balanceOf(address(this));
        _safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        if (received != amount) revert UnexpectedReceivedAmount(amount, received);

        uint256 nonce = nextNonce++;
        depositId = keccak256(abi.encode(block.chainid, address(this), nonce, msg.sender, baseRecipient, amount));
        emit DepositLocked(depositId, nonce, msg.sender, baseRecipient, amount);
    }

    function _safeTransferFrom(address from, address to, uint256 amount) private {
        (bool success, bytes memory returndata) =
            address(token).call(abi.encodeWithSelector(IERC20Lockbox.transferFrom.selector, from, to, amount));
        if (!success || (returndata.length != 0 && !abi.decode(returndata, (bool)))) {
            revert TokenTransferFailed();
        }
    }
}
