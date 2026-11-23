// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Base representation of Elysium PHNTMOP for a one-way, lockbox-backed migration.
/// @dev The migrationSafe should be a separately deployed 2-of-3 Safe. This token cannot
/// verify Elysium state itself; every mint must be publicly reconciled to a lockbox deposit.
contract BasePhntmop {
    error ZeroAddress();
    error ZeroAmount();
    error Unauthorized();
    error MigrationIsClosed();
    error AlreadyProcessed(bytes32 depositId);
    error SupplyCapExceeded(uint256 requestedSupply, uint256 cap);
    error InsufficientBalance();
    error InsufficientAllowance();

    string public constant name = "Phantom Operator";
    string public constant symbol = "PHNTMOP";
    uint8 public constant decimals = 18;
    uint256 public constant MAX_SUPPLY = 1_000_000_000e18;

    address public immutable migrationSafe;
    bool public migrationClosed;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => bool) public processedDeposit;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event MigrationMinted(bytes32 indexed elysiumDepositId, address indexed recipient, uint256 amount);
    event MigrationClosed(uint256 finalTotalSupply);

    constructor(address migrationSafe_) {
        if (migrationSafe_ == address(0)) revert ZeroAddress();
        migrationSafe = migrationSafe_;
    }

    modifier onlyMigrationSafe() {
        if (msg.sender != migrationSafe) revert Unauthorized();
        _;
    }

    /// @notice Mint against one confirmed Elysium lockbox deposit.
    /// @dev The Safe's signers must verify the Elysium event and reconciliation data first.
    function mintForDeposit(bytes32 elysiumDepositId, address recipient, uint256 amount) external onlyMigrationSafe {
        if (migrationClosed) revert MigrationIsClosed();
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (processedDeposit[elysiumDepositId]) revert AlreadyProcessed(elysiumDepositId);
        uint256 requestedSupply = totalSupply + amount;
        if (requestedSupply > MAX_SUPPLY) revert SupplyCapExceeded(requestedSupply, MAX_SUPPLY);

        processedDeposit[elysiumDepositId] = true;
        totalSupply = requestedSupply;
        balanceOf[recipient] += amount;
        emit Transfer(address(0), recipient, amount);
        emit MigrationMinted(elysiumDepositId, recipient, amount);
    }

    /// @notice Permanently close migration minting after the migration window and final reconciliation.
    /// @dev One-way action callable only by the 2-of-3 migration Safe; cannot be reopened.
    function closeMigration() external onlyMigrationSafe {
        if (migrationClosed) revert MigrationIsClosed();
        migrationClosed = true;
        emit MigrationClosed(totalSupply);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
        uint256 approved = allowance[sender][msg.sender];
        if (approved != type(uint256).max) {
            if (approved < amount) revert InsufficientAllowance();
            allowance[sender][msg.sender] = approved - amount;
            emit Approval(sender, msg.sender, allowance[sender][msg.sender]);
        }
        _transfer(sender, recipient, amount);
        return true;
    }

    function _transfer(address sender, address recipient, uint256 amount) private {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 senderBalance = balanceOf[sender];
        if (senderBalance < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[sender] = senderBalance - amount;
            balanceOf[recipient] += amount;
        }
        emit Transfer(sender, recipient, amount);
    }
}
