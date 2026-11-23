// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MigrationLockbox, IERC20Lockbox} from "../src/MigrationLockbox.sol";
import {BasePhntmop} from "../src/BasePhntmop.sol";

interface Vm {
    function prank(address caller) external;
}

contract MockElysiumPhntmop is IERC20Lockbox {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 approved = allowance[from][msg.sender];
        require(approved >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        allowance[from][msg.sender] = approved - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MigrationTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);

    MockElysiumPhntmop private source;
    MigrationLockbox private lockbox;
    BasePhntmop private baseToken;

    function setUp() public {
        source = new MockElysiumPhntmop();
        lockbox = new MigrationLockbox(address(source));
        // This test contract models the future 2-of-3 Safe call boundary.
        baseToken = new BasePhntmop(address(this));
        source.mint(ALICE, 1_000_000e18);
    }

    function testDepositLocksExactTokens() public {
        uint256 amount = 123e18;
        vm.prank(ALICE);
        source.approve(address(lockbox), amount);
        vm.prank(ALICE);
        bytes32 depositId = lockbox.deposit(amount, BOB);

        require(depositId != bytes32(0), "missing deposit id");
        require(source.balanceOf(address(lockbox)) == amount, "lockbox balance mismatch");
        require(lockbox.totalLocked() == amount, "lockbox accounting mismatch");
        require(source.balanceOf(ALICE) == 1_000_000e18 - amount, "sender balance mismatch");
    }

    function testOnlyMigrationSafeCanMint() public {
        bytes32 id = keccak256("elysium-deposit");
        vm.prank(ALICE);
        (bool ok,) = address(baseToken).call(abi.encodeWithSelector(baseToken.mintForDeposit.selector, id, ALICE, 1e18));
        require(!ok, "non-safe mint succeeded");
        require(baseToken.totalSupply() == 0, "supply changed");
    }

    function testCannotProcessDepositTwice() public {
        bytes32 id = keccak256("elysium-deposit");
        baseToken.mintForDeposit(id, BOB, 25e18);
        (bool ok,) = address(baseToken).call(abi.encodeWithSelector(baseToken.mintForDeposit.selector, id, BOB, 25e18));
        require(!ok, "duplicate mint succeeded");
        require(baseToken.totalSupply() == 25e18, "supply changed after replay");
    }

    function testCannotExceedOriginalSupplyCap() public {
        baseToken.mintForDeposit(keccak256("max"), BOB, baseToken.MAX_SUPPLY());
        (bool ok,) = address(baseToken)
            .call(abi.encodeWithSelector(baseToken.mintForDeposit.selector, keccak256("overflow"), BOB, 1));
        require(!ok, "cap bypassed");
        require(baseToken.totalSupply() == baseToken.MAX_SUPPLY(), "cap changed");
    }

    function testFuzzDepositAccounting(uint96 rawAmount) public {
        uint256 amount = (uint256(rawAmount) % 1_000_000e18) + 1;
        vm.prank(ALICE);
        source.approve(address(lockbox), amount);
        vm.prank(ALICE);
        lockbox.deposit(amount, BOB);
        require(source.balanceOf(address(lockbox)) == amount, "locked amount mismatch");
        require(lockbox.totalLocked() == amount, "accounted amount mismatch");
    }
}
