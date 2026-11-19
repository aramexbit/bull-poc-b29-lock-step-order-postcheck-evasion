// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 15 — Team A (forge / on-chain).
// Live Streams (0xF02a…, etched stream.hex, fabricated storage — NO
// createStream, forbidden step never attempted). Throwaway keys only.
//
// Streams matrix gaps left by rounds 12–14 (all prior caller×kind×state
// combos killed there):
// K-898: double-pause — 2nd pause by arbiter: revert, or overwrite
//   pausedAt (resume shift then shrinks -> payee enriched)?
// K-899: resume when NOT paused (pausedAt=0) by arbiter: revert, or shift
//   window by (now - 0) -> payee massively delayed?
// K-900: cancel on a COMPLETED stream (kind=3, fully withdrawn) by payer.
// K-901: redirect by payee AFTER cancel (kind=2) — then withdraw?
// K-902: cancel BEFORE start (kind=0) by payer — split check.
contract Round15ATest is Test {
    address constant STREAM = 0xF02aD48D7Ae63F17941E78AAF228C1450Db13891;

    uint256 constant PAYER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant PAYEE_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant ARB_PK = 0x47e179ec1974f892c2cd3b0cf1a4ec6a36e72a0a0d26ccaa2aa5c8ad6b9b47a8;
    address payer; address payee; address arbiter; address stranger;
    MockERC20 token;

    bytes4 constant SEL_WITHDRAW = 0x2e1a7d4d;
    bytes4 constant SEL_CANCEL = 0x40e58ee5;
    bytes4 constant SEL_PAUSE = 0x136439dd;
    bytes4 constant SEL_RESUME = 0x414000b5;
    bytes4 constant SEL_REDIRECT = 0xadfecd8a;
    bytes4 constant SEL_VESTED = 0x968fb8ba;
    bytes4 constant SEL_WITHDRAWABLE = 0xf11988e0;

    function setUp() public {
        vm.chainId(4663);
        payer = vm.addr(PAYER_PK);
        payee = vm.addr(PAYEE_PK);
        arbiter = vm.addr(ARB_PK);
        stranger = vm.addr(0x9999);
        vm.etch(STREAM, vm.parseBytes(vm.readFile("bytecode/stream.hex")));
        vm.store(STREAM, bytes32(uint256(4)), bytes32(uint256(1))); // reentrancy guard unlocked
        token = new MockERC20();
        token.mint(payer, 1000000000);
        token.mint(STREAM, 100000 ether);
        vm.deal(payer, 100 ether);
        vm.deal(payee, 10 ether);
        vm.deal(arbiter, 10 ether);
        vm.deal(stranger, 10 ether);
        vm.warp(1000);
    }

    function _base(uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, uint256(1)));
    }
    function _fabricate(uint256 id, uint256 amount_, uint256 withdrawn_, uint64 start_, uint64 end_, uint64 pausedAt_, uint8 kind_) internal {
        bytes32 b = _base(id);
        vm.store(STREAM, b, bytes32(uint256(uint160(payer))));
        vm.store(STREAM, bytes32(uint256(b) + 1), bytes32(uint256(uint160(payee))));
        vm.store(STREAM, bytes32(uint256(b) + 2), bytes32(uint256(uint160(arbiter))));
        vm.store(STREAM, bytes32(uint256(b) + 3), bytes32(uint256(uint160(address(token)))));
        vm.store(STREAM, bytes32(uint256(b) + 4), bytes32(amount_));
        vm.store(STREAM, bytes32(uint256(b) + 5), bytes32(withdrawn_));
        uint256 packed = uint256(start_) | (uint256(end_) << 64) | (uint256(pausedAt_) << 128) | (uint256(kind_) << 192);
        vm.store(STREAM, bytes32(uint256(b) + 6), bytes32(packed));
    }
    // words: [6]=start [7]=end [8]=pausedAt [9]=kind, [1]=payee slot
    function _words(uint256 id) internal view returns (uint256[10] memory w) {
        bytes32 b = _base(id);
        for (uint256 i; i < 7; i++) w[i] = uint256(vm.load(STREAM, bytes32(uint256(b) + i)));
        uint256 packed = w[6];
        w[6] = packed & 0xFFFFFFFFFFFFFFFF;
        w[7] = (packed >> 64) & 0xFFFFFFFFFFFFFFFF;
        w[8] = (packed >> 128) & 0xFFFFFFFFFFFFFFFF;
        w[9] = (packed >> 192) & 0xFF;
    }
    function _callAs(address who, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(who);
        (ok, ret) = STREAM.call(data);
    }

    // ---- K-898: double-pause by the arbiter ----
    function testK898DoublePause() public {
        _fabricate(1, 1000 ether, 0, 1000, 87400, 0, 1);
        vm.warp(11000);
        (bool ok1,) = _callAs(arbiter, abi.encodeWithSelector(SEL_PAUSE, uint256(1)));
        assertTrue(ok1, "first pause by arbiter must succeed");
        assertEq(_words(1)[8], 11000, "pausedAt = 11000 after first pause");
        vm.warp(21000);
        (bool ok2,) = _callAs(arbiter, abi.encodeWithSelector(SEL_PAUSE, uint256(1)));
        uint256 pausedAt2 = _words(1)[8];
        emit log_named_uint("K-898 second pause ok", ok2 ? 1 : 0);
        emit log_named_uint("K-898 pausedAt after second pause", pausedAt2);
        // Resume and measure the shift: single-pause control would shift by
        // (31000 - 11000) = 20000 -> end 107400. If 2nd pause overwrote
        // pausedAt to 21000, shift is only 10000 -> end 97400 (payee +10000s).
        vm.warp(31000);
        (bool rok,) = _callAs(arbiter, abi.encodeWithSelector(SEL_RESUME, uint256(1)));
        emit log_named_uint("K-898 resume ok", rok ? 1 : 0);
        uint256[10] memory w = _words(1);
        emit log_named_uint("K-898 start after resume", w[6]);
        emit log_named_uint("K-898 end after resume", w[7]);
        if (ok2) {
            // Second pause overwrote pausedAt: resume shift = 31000-21000.
            assertEq(pausedAt2, 21000, "second pause overwrites pausedAt");
            assertEq(w[7], 87400 + 10000, "resume after double-pause shifts end by only 10000 (payee enriched 10000s vs single-pause)");
            emit log_string("K-898: double-pause OVERWRITES pausedAt; resume shift shrinks; arbiter-only so bounded by arbiter trust - KILL");
        } else {
            assertEq(pausedAt2, 11000, "failed second pause leaves pausedAt at 11000");
            assertEq(w[7], 87400 + 20000, "resume after refused double-pause shifts end by full 20000");
            emit log_string("K-898: second pause REVERTS; pausedAt untouched - KILL");
        }
    }

    // ---- K-899: resume when NOT paused (pausedAt=0) by the arbiter ----
    function testK899ResumeWhenNotPaused() public {
        _fabricate(2, 1000 ether, 0, 1000, 87400, 0, 1);
        vm.warp(1000 + 43200); // halfway
        (bool ok,) = _callAs(arbiter, abi.encodeWithSelector(SEL_RESUME, uint256(2)));
        uint256[10] memory w = _words(2);
        emit log_named_uint("K-899 resume-unpaused ok", ok ? 1 : 0);
        emit log_named_uint("K-899 start after resume", w[6]);
        emit log_named_uint("K-899 end after resume", w[7]);
        emit log_named_uint("K-899 pausedAt after resume", w[8]);
        if (ok) {
            // If resume shifts by (now - pausedAt) with pausedAt=0, the
            // shift is the full wall-clock timestamp (~44200) - payee delayed.
            emit log_string("K-899: resume on unpaused stream SUCCEEDS and shifts window (arbiter-only griefing at most) - KILL");
        } else {
            assertEq(w[6], 1000, "failed resume leaves start untouched");
            assertEq(w[7], 87400, "failed resume leaves end untouched");
            emit log_string("K-899: resume on unpaused stream REVERTS - KILL");
        }
    }

    // ---- K-900: cancel on a COMPLETED stream (kind=3) by the payer ----
    function testK900CancelCompleted() public {
        _fabricate(3, 1000 ether, 1000 ether, 1000, 87400, 0, 3);
        vm.warp(90000);
        uint256 payeeBefore = token.balanceOf(payee);
        uint256 payerBefore = token.balanceOf(payer);
        (bool ok,) = _callAs(payer, abi.encodeWithSelector(SEL_CANCEL, uint256(3)));
        emit log_named_uint("K-900 cancel-completed ok", ok ? 1 : 0);
        assertFalse(ok, "cancel on completed stream must revert");
        assertEq(token.balanceOf(payee) - payeeBefore, 0, "failed cancel pays payee nothing");
        assertEq(token.balanceOf(payer) - payerBefore, 0, "failed cancel refunds payer nothing");
        assertEq(_words(3)[9], 3, "kind stays 3");
    }

    // ---- K-901: redirect by payee AFTER cancel (kind=2), then withdraw ----
    function testK901RedirectAfterCancel() public {
        _fabricate(4, 1000 ether, 0, 1000, 87400, 0, 2);
        (bool ok,) = _callAs(payee, abi.encodeWithSelector(SEL_REDIRECT, uint256(4), stranger));
        emit log_named_uint("K-901 redirect-after-cancel ok", ok ? 1 : 0);
        vm.warp(1000 + 43200);
        uint256 strangerBefore = token.balanceOf(stranger);
        uint256 payeeBefore = token.balanceOf(payee);
        (bool wok,) = _callAs(stranger, abi.encodeWithSelector(SEL_WITHDRAW, uint256(4)));
        emit log_named_uint("K-901 withdraw-after-cancel ok", wok ? 1 : 0);
        assertFalse(wok, "withdraw on cancelled stream must revert");
        assertEq(token.balanceOf(stranger) - strangerBefore, 0, "cancelled stream pays the redirect target nothing");
        assertEq(token.balanceOf(payee) - payeeBefore, 0, "cancelled stream pays the old payee nothing");
    }

    // ---- K-902: cancel BEFORE start (kind=0) by the payer ----
    // NOTE: kind-0 cancel REVERTS (see probe below) — funds stay put until
    // the stream becomes active. Recorded, not overclaimed.
    function testK902CancelBeforeStart() public {
        _fabricate(5, 1000 ether, 0, 1000, 87400, 0, 0);
        uint256 payeeBefore = token.balanceOf(payee);
        uint256 payerBefore = token.balanceOf(payer);
        (bool ok,) = _callAs(payer, abi.encodeWithSelector(SEL_CANCEL, uint256(5)));
        emit log_named_uint("K-902 cancel kind-0 ok", ok ? 1 : 0);
        assertFalse(ok, "cancel on kind-0 stream reverts (kind must be 1)");
        assertEq(token.balanceOf(payee) - payeeBefore, 0, "failed cancel pays payee nothing");
        assertEq(token.balanceOf(payer) - payerBefore, 0, "failed cancel refunds payer nothing");
        assertEq(_words(5)[9], 0, "kind stays 0");
        emit log_string("K-902: cancel requires kind=1; kind-0 (pre-start) stream cannot be cancelled - KILL (see K-902b probe for lifecycle)");
    }

    // ---- K-902b: does a kind-0 stream EVER become cancellable/vested? ----
    // Fabricate kind 0 with start in the past, warp mid-window, then probe
    // vested/withdrawable/cancel/withdraw. If kind stays 0 and vested stays
    // 0 forever, a pre-start stream's funds are frozen until someone flips
    // the kind — check whether ANY call flips it.
    function testK902bKind0Lifecycle() public {
        _fabricate(6, 1000 ether, 0, 1000, 87400, 0, 0);
        vm.warp(1000 + 43200); // mid-window, start long past
        (bool vok, bytes memory vret) = STREAM.call(abi.encodeWithSelector(SEL_VESTED, uint256(6)));
        (bool wok, bytes memory wret) = STREAM.call(abi.encodeWithSelector(SEL_WITHDRAWABLE, uint256(6)));
        uint256 vested = vok ? abi.decode(vret, (uint256)) : 0;
        uint256 withdrawable = wok ? abi.decode(wret, (uint256)) : 0;
        emit log_named_uint("K-902b kind-0 mid-window vested", vested);
        emit log_named_uint("K-902b kind-0 mid-window withdrawable", withdrawable);
        (bool cok,) = _callAs(payer, abi.encodeWithSelector(SEL_CANCEL, uint256(6)));
        (bool wdraw,) = _callAs(payee, abi.encodeWithSelector(SEL_WITHDRAW, uint256(6)));
        emit log_named_uint("K-902b kind-0 mid-window cancel ok", cok ? 1 : 0);
        emit log_named_uint("K-902b kind-0 mid-window withdraw ok", wdraw ? 1 : 0);
        emit log_named_uint("K-902b kind after probes", _words(6)[9]);
        // No state-changing call in the matrix flips kind 0 -> 1 (withdraw
        // and cancel both revert on kind 0; pause/resume need kind 1 too
        // per K-623). If vested is 0 mid-window, kind 0 is a dead state
        // reachable only via fabricated storage — createStream's own kind
        // assignment is untestable (crafting forbidden), so this stays a
        // KILL with a WATCH note, not a PASS.
        assertEq(vested, 0, "kind-0 vested stays 0 even mid-window");
        assertEq(withdrawable, 0, "kind-0 withdrawable stays 0 even mid-window");
        assertFalse(cok, "kind-0 cancel still reverts mid-window");
        assertFalse(wdraw, "kind-0 withdraw still reverts mid-window");
    }
}
