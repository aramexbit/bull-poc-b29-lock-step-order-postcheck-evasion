# PoC for Bull.family bug bounty report B-29

## SDK `lock()` parses only the LAST step's receipt — a malicious server swaps the step order so the vesting post-check never runs and a fully vested lock is created

**Report B-29** (K-897). SDK under test: `sdk-live.mjs` — the Bull SDK live
19 Nov 2026, sha256 `3c1319e17023e76598413cbaa031e350180cd7d62102619141f82d1b575ef243`,
34,788 bytes (`https://www.bull.family/sdk/bull.mjs`).

### The bug

`lock()` has two halves that don't meet. Its post-transaction check verifies
the vesting schedule (token/beneficiary/amount/cliff/end/step) — but only
against the receipt of the LAST step it sent. The loop overwrites `rc` on
every iteration, then `parseEventLogs(rc.logs)` runs once on the last receipt
only:

```js
// lock(): for each step -> rc = await #send(...)
// after the loop:
const logs = parseEventLogs({ abi: [...LockCreated...], logs: rc.logs });
```

`deal()`, in the same file, parses EVERY receipt inside its loop. `lock()`
does not.

The attack needs a compromised/malicious API server (the SDK's own
documented threat model). The victim calls `lock()` for 500 tokens with
cliff 90 days / duration 365 days. The server returns
`[approve(500), createLock(backdated start = now-455d), approve(500)]`.
The lock is created fully vested, but `lock()` throws
`"LockCreated event not found."` (the last receipt is an `approve`, which
has no `LockCreated` event) and the post-checks NEVER run. The victim sees
an error, assumes nothing happened — while the beneficiary can claim the
full 500 at once. Single call, no retry.

This is NOT B-26: B-26's lock is the LAST step, so its post-check runs and
the backdated start passes a *relative* comparison (the check itself is the
hole). Here the check never runs at all, because the bad step is NOT last.
B-26's requested fix (compare start against an absolute bound) would NOT
catch this — the fix here is different: parse every receipt (like `deal()`
already does). (Dedupe risk, stated honestly: HIGH vs B-26 — same loss
shape, different mechanism.)

### Measured (fresh Anvil, live escrow v3 bytecode; independently re-run by the round-15 coordinator)

```
K-897 P1 EXPLOITED: SINGLE call, NO retry: lock() threw "LockCreated event
  not found." while lock #4 sat fully vested; beneficiary claimed all 500
  at once (asked cliff 90d / duration 365d)
C0 control OK: honest lock startAt exact — victim -500 exactly; locks 0->1;
  claimable 0; lockId 1 returned
K-873 MECHANISM GREEN: 2/2 (startAt +1s: lock() throws post-tx, lock mined
  for the named beneficiary; retry mines a second lock, -500 again) —
  K-873 is KILLED as a report (error is explicit and names the schedule
  mismatch; funds go to the caller-named beneficiary, not an attacker;
  weaker variant of the B-18 family), recorded here as the mechanism
  reference, not a claim
EXPLOITED: 1 (K-897) | K-873 MECHANISM GREEN: 2/2 | CONTROLS OK: 1/1 (C0)
```

Forge leg (`chain/test/Round15A.t.sol`, 6/6): streams access-control matrix
via fabricated storage — double-pause, resume-when-not-paused, cancel
completed, redirect-after-cancel, cancel kind-0 all revert (all KILL;
kind-0 is a dead state under fabricated storage only).

### Run

```sh
anvil --port 8547 --chain-id 4663   # fresh Anvil per run
npm install
node run-poc.mjs
```

Local Anvil only, mock server, no real funds, no mainnet, no Bull
infrastructure. Uses Anvil's public throwaway keys only.
