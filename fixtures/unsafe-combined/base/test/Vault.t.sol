// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Vault} from "../src/Vault.sol";

contract VaultTest {
    Vault internal vault;

    receive() external payable {}

    function setUp() public {
        vault = new Vault();
        vault.initialize(address(this));
    }

    function test_DepositCredits() public {
        vault.deposit{value: 1 ether}();
        require(vault.balances(address(this)) == 1 ether, "balance");
    }

    function test_OwnerCanPause() public {
        vault.setPaused(true);
        require(vault.paused(), "paused");
    }

    function testFuzz_DepositWithdraw(uint96 amount) public {
        if (amount == 0 || amount > address(this).balance) return;
        vault.deposit{value: amount}();
        vault.withdraw(amount);
        require(vault.balances(address(this)) == 0, "residual");
    }

    function invariant_TotalWithinBalance() public view {
        require(vault.totalDeposits() <= address(vault).balance, "insolvent");
    }
}
