// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MigrationLockbox, IERC20Lockbox} from "../src/MigrationLockbox.sol";
import {BasePhntmop} from "../src/BasePhntmop.sol";

interface Vm {
    function prank(address caller) external;
    function etch(address target, bytes calldata newRuntimeBytecode) external;
    function store(address target, bytes32 slot, bytes32 value) external;
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

contract FeeOnTransferToken is IERC20Lockbox {
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
        uint256 fee = amount / 100;
        balanceOf[from] -= amount;
        balanceOf[to] += (amount - fee);
        return true;
    }
}

contract FalseReturnToken is IERC20Lockbox {
    mapping(address => uint256) public balanceOf;

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}

contract ReentrantCallbackToken is IERC20Lockbox {
    mapping(address => uint256) public balanceOf;
    MigrationLockbox public targetLockbox;
    bool public attackArmed;

    function setTarget(MigrationLockbox lockbox_, bool armed_) external {
        targetLockbox = lockbox_;
        attackArmed = armed_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        if (attackArmed) {
            attackArmed = false;
            targetLockbox.deposit(1e18, to);
        }
        return true;
    }
}

/// @notice Minimal 2-of-3 multisig harness matching the owner-specified Safe signer boundary.
contract MockTwoOfThreeSafe {
    address public immutable signer1;
    address public immutable signer2;
    address public immutable signer3;

    mapping(bytes32 => mapping(address => bool)) public approvedBy;
    mapping(bytes32 => uint256) public approvalCount;
    mapping(bytes32 => bool) public executed;

    constructor(address s1, address s2, address s3) {
        signer1 = s1;
        signer2 = s2;
        signer3 = s3;
    }

    function isSigner(address account) public view returns (bool) {
        return account == signer1 || account == signer2 || account == signer3;
    }

    function approveAction(bytes32 actionId) external {
        require(isSigner(msg.sender), "not signer");
        require(!approvedBy[actionId][msg.sender], "already approved");
        approvedBy[actionId][msg.sender] = true;
        approvalCount[actionId] += 1;
    }

    function executeMint(BasePhntmop token, bytes32 depositId, address recipient, uint256 amount) external {
        bytes32 actionId = keccak256(abi.encode("MINT", address(token), depositId, recipient, amount));
        require(!executed[actionId], "already executed");
        require(approvalCount[actionId] >= 2, "need 2 of 3 approvals");
        executed[actionId] = true;
        token.mintForDeposit(depositId, recipient, amount);
    }

    function executeClose(BasePhntmop token, uint256 nonce) external {
        bytes32 actionId = keccak256(abi.encode("CLOSE", address(token), nonce));
        require(!executed[actionId], "already executed");
        require(approvalCount[actionId] >= 2, "need 2 of 3 approvals");
        executed[actionId] = true;
        token.closeMigration();
    }
}

interface IElysiumRuntimeToken {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function rewardHook() external view returns (address);
}

contract MigrationTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);

    address private constant SIGNER_1 = 0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6;
    address private constant SIGNER_2 = 0x050f74E4591F9897FdB311C8150c07dFFfbEf5e1;
    address private constant SIGNER_3 = 0x3d95D4A6DbaE0Cd0643a82b13A13b08921D6ADf7;
    address private constant ELYSIUM_PHNTMOP = 0x3156C23C07a88Eb91049DfA97106823E8e418BA3;

    bytes private constant ELYSIUM_PHNTMOP_RUNTIME =
        hex"608060405234801561000f575f80fd5b50600436106100b1575f3560e01c806344214ecf1161006e57806344214ecf1461013257806370a082311461017157806377a4d5591461019957806395d89b41146101a1578063a9059cbb146101a9578063dd62ed3e146101bc575f80fd5b806306fdde03146100b5578063095ea7b3146100d357806318160ddd146100f657806323b872dd14610108578063313ce5671461011b5780633c130d901461012a575b5f80fd5b6100bd6101f4565b6040516100ca91906106fb565b60405180910390f35b6100e66100e136600461074b565b610284565b60405190151581526020016100ca565b6002545b6040519081526020016100ca565b6100e6610116366004610773565b61029d565b604051601281526020016100ca565b6100bd6102c0565b6101597f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b0390911681526020016100ca565b6100fa61017f3660046107ac565b6001600160a01b03165f9081526020819052604090205490565b6100bd6102cf565b6100bd61035b565b6100e66101b736600461074b565b61036a565b6100fa6101ca3660046107cc565b6001600160a01b039182165f90815260016020908152604080832093909416825291909152205490565b606060038054610203906107fd565b80601f016020809104026020016040519081016040528092919081815260200182805461022f906107fd565b801561027a5780601f106102515761010080835404028352916020019161027a565b820191905f5260205f20905b81548152906001019060200180831161025d57829003601f168201915b5050505050905090565b5f33610291818585610377565b60019150505b92915050565b5f336102aa858285610389565b6102b585858561040a565b506001949350505050565b606060058054610203906107fd565b600580546102dc906107fd565b80601f0160208091040260200160405190810160405280929190818152602001828054610308906107fd565b80156103535780601f1061032a57610100808354040283529160200191610353565b820191905f5260205f20905b81548152906001019060200180831161033657829003601f168201915b505050505081565b606060048054610203906107fd565b5f3361029181858561040a565b6103848383836001610467565b505050565b6001600160a01b038381165f908152600160209081526040808320938616835292905220545f1981101561040457818110156103f657604051637dc7a0d960e11b81526001600160a01b038416600482015260248101829052604481018390526064015b60405180910390fd5b61040484848484035f610467565b50505050565b6001600160a01b03831661043357604051634b637e8f60e11b81525f60048201526024016103ed565b6001600160a01b03821661045c5760405163ec442f0560e01b81525f60048201526024016103ed565b610384838383610539565b6001600160a01b0384166104905760405163e602df0560e01b81525f60048201526024016103ed565b6001600160a01b0383166104b957604051634a1406b160e11b81525f60048201526024016103ed565b6001600160a01b038085165f908152600160209081526040808320938716835292905220829055801561040457826001600160a01b0316846001600160a01b03167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9258460405161052b91815260200190565b60405180910390a350505050565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b038116156105cf57604051634a39314960e01b81526001600160a01b038581166004830152848116602483015260448201849052821690634a393149906064015f604051808303815f87803b1580156105b8575f80fd5b505af11580156105ca573d5f803e3d5ffd5b505050505b6104048484846001600160a01b0383166105ff578060025f8282546105f49190610835565b9091555061066f9050565b6001600160a01b0383165f90815260208190526040902054818110156106515760405163391434e360e21b81526001600160a01b038516600482015260248101829052604481018390526064016103ed565b6001600160a01b0384165f9081526020819052604090209082900390555b6001600160a01b03821661068b576002805482900390556106a9565b6001600160a01b0382165f9081526020819052604090208054820190555b816001600160a01b0316836001600160a01b03167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516106ee91815260200190565b60405180910390a3505050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f83011684010191505092915050565b80356001600160a01b0381168114610746575f80fd5b919050565b5f806040838503121561075c575f80fd5b61076583610730565b946020939093013593505050565b5f805f60608486031215610785575f80fd5b61078e84610730565b925061079c60208501610730565b9150604084013590509250925092565b5f602082840312156107bc575f80fd5b6107c582610730565b9392505050565b5f80604083850312156107dd575f80fd5b6107e683610730565b91506107f460208401610730565b90509250929050565b600181811c9082168061081157607f821691505b60208210810361082f57634e487b7160e01b5f52602260045260245ffd5b50919050565b8082018082111561029757634e487b7160e01b5f52601160045260245ffdfea264697066735822122061691590e211e233dea6883d8ba8e8b51065e90a750e221faacd9ea64c857e4764736f6c63430008190033";

    MockElysiumPhntmop private source;
    MigrationLockbox private lockbox;
    BasePhntmop private baseToken;

    function setUp() public {
        source = new MockElysiumPhntmop();
        lockbox = new MigrationLockbox(address(source));
        // This test contract models the future 2-of-3 Safe call boundary in unit tests.
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

    function testRejectsFeeOnTransferToken() public {
        FeeOnTransferToken feeToken = new FeeOnTransferToken();
        MigrationLockbox feeLockbox = new MigrationLockbox(address(feeToken));
        feeToken.mint(ALICE, 1_000e18);

        vm.prank(ALICE);
        feeToken.approve(address(feeLockbox), 100e18);

        vm.prank(ALICE);
        (bool ok,) = address(feeLockbox).call(abi.encodeWithSelector(feeLockbox.deposit.selector, 100e18, BOB));
        require(!ok, "fee-on-transfer deposit unexpectedly succeeded");
        require(feeLockbox.totalLocked() == 0, "totalLocked not rolled back");
    }

    function testRejectsFalseReturnToken() public {
        FalseReturnToken badToken = new FalseReturnToken();
        MigrationLockbox badLockbox = new MigrationLockbox(address(badToken));

        vm.prank(ALICE);
        (bool ok,) = address(badLockbox).call(abi.encodeWithSelector(badLockbox.deposit.selector, 100e18, BOB));
        require(!ok, "false-returning token deposit unexpectedly succeeded");
        require(badLockbox.totalLocked() == 0, "totalLocked not rolled back");
    }

    function testBlocksReentrantTokenCallback() public {
        ReentrantCallbackToken reentrantToken = new ReentrantCallbackToken();
        MigrationLockbox reentrantLockbox = new MigrationLockbox(address(reentrantToken));
        reentrantToken.setTarget(reentrantLockbox, true);
        reentrantToken.mint(ALICE, 100e18);

        vm.prank(ALICE);
        (bool ok,) =
            address(reentrantLockbox).call(abi.encodeWithSelector(reentrantLockbox.deposit.selector, 10e18, BOB));
        require(!ok, "reentrant deposit unexpectedly succeeded");
        require(reentrantLockbox.totalLocked() == 0, "reentrant totalLocked not rolled back");
    }

    function testTwoOfThreeSafeBoundaryAndPermanentClosure() public {
        MockTwoOfThreeSafe safe = new MockTwoOfThreeSafe(SIGNER_1, SIGNER_2, SIGNER_3);
        BasePhntmop safeControlledBase = new BasePhntmop(address(safe));
        bytes32 depositId = keccak256("confirmed-elysium-deposit-1");
        uint256 amount = 500e18;
        bytes32 mintActionId = keccak256(abi.encode("MINT", address(safeControlledBase), depositId, BOB, amount));

        // 1-of-3 approval must fail
        vm.prank(SIGNER_1);
        safe.approveAction(mintActionId);
        (bool okOneSigner,) = address(safe)
            .call(abi.encodeWithSelector(safe.executeMint.selector, safeControlledBase, depositId, BOB, amount));
        require(!okOneSigner, "1-of-3 signer threshold unexpectedly minted");

        // 2-of-3 approval succeeds
        vm.prank(SIGNER_2);
        safe.approveAction(mintActionId);
        safe.executeMint(safeControlledBase, depositId, BOB, amount);
        require(safeControlledBase.balanceOf(BOB) == amount, "2-of-3 mint balance mismatch");

        // Close migration with 2-of-3 approval (SIGNER_2 + SIGNER_3)
        bytes32 closeActionId = keccak256(abi.encode("CLOSE", address(safeControlledBase), uint256(1)));
        vm.prank(SIGNER_2);
        safe.approveAction(closeActionId);
        vm.prank(SIGNER_3);
        safe.approveAction(closeActionId);
        safe.executeClose(safeControlledBase, 1);
        require(safeControlledBase.migrationClosed(), "migration not marked closed");

        // Even with 2-of-3 approvals, minting after permanent closure must fail
        bytes32 postCloseDepositId = keccak256("confirmed-elysium-deposit-2");
        bytes32 postCloseActionId =
            keccak256(abi.encode("MINT", address(safeControlledBase), postCloseDepositId, BOB, amount));
        vm.prank(SIGNER_1);
        safe.approveAction(postCloseActionId);
        vm.prank(SIGNER_3);
        safe.approveAction(postCloseActionId);
        (bool okAfterClose,) = address(safe)
            .call(
                abi.encodeWithSelector(safe.executeMint.selector, safeControlledBase, postCloseDepositId, BOB, amount)
            );
        require(!okAfterClose, "mint succeeded after permanent migration closure");
    }

    function testExactElysiumPhntmopRuntimeBytecodeDeposit() public {
        vm.etch(ELYSIUM_PHNTMOP, ELYSIUM_PHNTMOP_RUNTIME);
        IElysiumRuntimeToken liveToken = IElysiumRuntimeToken(ELYSIUM_PHNTMOP);

        // Slot 2 is totalSupply in standard OpenZeppelin ERC-20 layout; slot 0 is balanceOf mapping.
        vm.store(ELYSIUM_PHNTMOP, bytes32(uint256(2)), bytes32(uint256(1_000_000_000e18)));
        bytes32 aliceBalanceSlot = keccak256(abi.encode(ALICE, uint256(0)));
        vm.store(ELYSIUM_PHNTMOP, aliceBalanceSlot, bytes32(uint256(25_000e18)));

        require(liveToken.rewardHook() == address(0), "live bytecode rewardHook not zero");
        require(liveToken.totalSupply() == 1_000_000_000e18, "live bytecode totalSupply mismatch");
        require(liveToken.balanceOf(ALICE) == 25_000e18, "live bytecode Alice balance mismatch");

        MigrationLockbox liveLockbox = new MigrationLockbox(ELYSIUM_PHNTMOP);
        vm.prank(ALICE);
        require(liveToken.approve(address(liveLockbox), 10_000e18), "live bytecode approve failed");

        vm.prank(ALICE);
        bytes32 depositId = liveLockbox.deposit(10_000e18, BOB);

        require(depositId != bytes32(0), "live depositId zero");
        require(liveToken.balanceOf(address(liveLockbox)) == 10_000e18, "live lockbox balance mismatch");
        require(liveLockbox.totalLocked() == 10_000e18, "live lockbox totalLocked mismatch");
        require(liveToken.balanceOf(ALICE) == 15_000e18, "live Alice remaining balance mismatch");
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
