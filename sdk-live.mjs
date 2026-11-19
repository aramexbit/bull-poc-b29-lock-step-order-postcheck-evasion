// Bull SDK. Atomic escrow settlement between any two parties on Robinhood Chain. No account, no API key.
//
//   import { Bull } from "./bull.mjs";            // needs `viem` installed (npm i viem)
//   const bull = new Bull({ walletClient, publicClient });
//   const dealId = await bull.open({ seller, sellToken, sellAmount: "1000", payAsset: "eth", payAmount: "0.25" }); // buyer
//   await bull.fund(dealId);                      // buyer pays, then the seller runs bull.fund(dealId) from their wallet
//   await bull.waitSettled(dealId);
//
// `walletClient` and `publicClient` are standard viem clients on Robinhood Chain (chain id 4663).

import { parseEventLogs, parseAbi, parseEther, parseUnits, erc20Abi, recoverMessageAddress, decodeFunctionData, encodeAbiParameters, encodeFunctionData, keccak256, toHex } from "viem";

// Safety: the API server is not trusted with your wallet. Every transaction it returns is checked before it is sent, and the
// consent message is checked against what YOU asked for before it is signed. Only these contracts can ever receive a transaction.
const DEFAULT_BASE = "https://www.bull.family";
const ESCROWS = ["0xd961ca37e339e14e0d3478383a252e218fe7aa4a"]; // the current escrow (v3, fees buy and burn BULL). Older escrows are not used by the SDK.
const FEE_SIGNER = "0x585770c10434fa6d434b6b27316354f9d1688bd0"; // signs receipts
const AGREEMENT = "0x84c6d5daf99bc65ed3a1d26ca88ffa834d143999";
const ZERO = "0x0000000000000000000000000000000000000000";
const USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168";
const low = (x) => String(x || "").toLowerCase();
const bad = (m) => { throw new Error("Bull SDK safety check failed: " + m); };

const AGR_ABI = parseAbi(["event AgreementCreated(uint256 indexed id, address indexed payer, address indexed payee, address asset, uint256 amount, uint64 expiry, bytes32 termsHash)"]);
const LOCK_ABI = parseAbi(["event LockCreated(uint256 indexed id, address indexed token, address indexed beneficiary, address creator, uint256 amount, uint64 start, uint64 cliff, uint64 end, uint64 step)"]);

// The only functions the SDK ever sends to a Bull contract. Everything else is refused, and the arguments are checked against what you asked for.
const FN_ABI = parseAbi([
  "function createDeal((address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline) p,(uint16 feeBps,uint64 expiry,bytes sig) q,(uint64 validUntil,bytes sig) c) returns (uint256)",
  "function fundPayment(uint256 id) payable",
  "function fundTokens(uint256 id)",
  "function fundTokensWithPermit(uint256 id,uint256 permitDeadline,uint8 v,bytes32 r,bytes32 s,bytes fundSig)",
  "function cancel(uint256 id)",
  "function createAgreement((address payee,address asset,uint256 amount,uint64 expiry,bytes32 termsHash,(uint8 kind,address target,bytes data,uint256 value)[] conditions) p,(uint256 feeWei,uint64 expiry,bytes sig) q) payable returns (uint256)",
  "function attest(uint256 id,uint256 index)",
  "function object(uint256 id,uint256 index)",
  "function vote(uint256 id,uint256 index)",
  "function release(uint256 id)",
  "function refund(uint256 id)",
]);
const CHAIN_ID = 4663;

const DEALS_ABI = parseAbi(["function deals(uint256) view returns (address buyer,address seller,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline,bool buyerFunded,bool sellerFunded,uint8 status,address sellerPayout,address buyerReceive,uint16 feeBps)"]);
const ABI = parseAbi(["event DealCreated(uint256 indexed id, address indexed buyer, address indexed seller, uint16 feeBps)"]);

export class Bull {
  /** @param {{ walletClient: any, publicClient: any, baseUrl?: string }} o */
  constructor({ walletClient, publicClient, baseUrl = "https://www.bull.family" }) {
    this.w = walletClient;
    this.p = publicClient;
    this.base = baseUrl.replace(/\/$/, "");
    this.tokens = new Set([USDG]); // token contracts you named yourself (approvals are only allowed on these)
    if (this.base !== DEFAULT_BASE) console.warn(`Bull SDK WARNING: using ${this.base} instead of ${DEFAULT_BASE}. Only continue if you run this server yourself.`);
  }

  #note(...tokens) {
    for (const t of tokens) if (/^0x[0-9a-fA-F]{40}$/.test(String(t || ""))) this.tokens.add(low(t));
  }

  get address() {
    return this.w.account.address;
  }

  async #call(path, body) {
    const r = await fetch(this.base + path, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : undefined);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j?.error?.message || j?.error || `Bull API ${r.status}`);
    return j;
  }

  /** Refuses anything that is not (1) a call to a Bull contract, (2) an approval of a token you named, to a Bull contract (or the locker you pinned),
   *  for at most `o.maxApprove`, or (3) a call to the `o.locker` you pinned. ETH value is capped at maxWei. Nothing here is derived from the server's reply. */
  #guard(tx, maxWei = 0n, o = {}) {
    const to = low(tx?.to), data = String(tx?.data || "0x"), value = BigInt(tx?.value || "0");
    if (value > maxWei) bad(`transaction sends ${value} wei, more than the ${maxWei} you agreed to.`);
    if (data.startsWith("0x095ea7b3")) {
      if (!/^0x[0-9a-fA-F]{136}$/.test(data)) bad("the approval calldata has the wrong length.");
      const spender = "0x" + data.slice(34, 74).toLowerCase();
      const amt = BigInt("0x" + data.slice(74, 138));
      if (!this.tokens.has(to)) bad(`approval on ${to}, a token you did not name.`);
      if (!(spender === AGREEMENT || ESCROWS.includes(spender) || (o.locker && spender === low(o.locker)))) bad(`approval to ${spender}, which is not a Bull contract.`);
      if (o.maxApprove === undefined || amt > o.maxApprove) bad(`approval of ${amt}, more than the ${o.maxApprove ?? 0n} this step needs.`);
      return;
    }
    if (to === AGREEMENT || ESCROWS.includes(to)) {
      // Decode the call: it must be a function this step is allowed to call, and (if the step is about one deal or agreement) for exactly that id.
      let fn;
      try { fn = decodeFunctionData({ abi: FN_ABI, data }); } catch { bad("the transaction calls a function the SDK does not know."); }
      if (o.fn && !o.fn.includes(fn.functionName)) bad(`the transaction calls ${fn.functionName}, expected ${o.fn.join(" or ")}.`);
      if (o.id !== undefined && fn.args[0] !== BigInt(o.id)) bad(`the transaction is for id ${fn.args[0]}, not the ${o.id} you asked for.`);
      return fn;
    }
    if (o.locker && to === low(o.locker) && !/^0x(a9059cbb|23b872dd|095ea7b3)/.test(data)) return;
    bad(`the server asked to send a transaction to ${to}, which is not a Bull contract.`);
  }

  /** Reads a deal straight from the escrow (the chain, not the server). */
  async #deal(dealId, escrow = ESCROWS[0]) {
    const r = await this.p.readContract({ address: escrow, abi: DEALS_ABI, functionName: "deals", args: [BigInt(dealId)] });
    return { buyer: r[0], seller: r[1], sellToken: r[2], sellAmount: r[3], payToken: r[4], payAmount: r[5], deadline: r[6], buyerFunded: r[7], sellerFunded: r[8], status: Number(r[9]), sellerPayout: r[10], buyerReceive: r[11], feeBps: Number(r[12]) };
  }

  /** The wallet must be connected to Robinhood Chain, otherwise value would go to Bull's addresses on a chain where nothing lives there. */
  async #chainOk() {
    let id;
    try { id = Number(this.w.chain?.id ?? (await this.w.getChainId())); } catch { bad("could not read the wallet's chain id."); }
    if (id !== CHAIN_ID) bad(`the wallet is on chain ${id}, not Robinhood Chain (${CHAIN_ID}).`);
  }

  async #decimals(token) {
    if (!token || low(token) === "eth" || low(token) === ZERO) return 18;
    if (low(token) === "usdg") return 6;
    try { return Number(await this.p.readContract({ address: token, abi: erc20Abi, functionName: "decimals" })); } catch { bad("could not read the token's decimals."); }
  }

  async #send(tx, maxWei = 0n, o = {}) {
    await this.#chainOk();
    const fn = this.#guard(tx, maxWei, o);
    if (o.check && fn) o.check(fn);
    const hash = await this.w.sendTransaction({ to: tx.to, data: tx.data, value: BigInt(tx.value || "0"), chain: this.w.chain });
    const rc = await this.p.waitForTransactionReceipt({ hash });
    if (rc.status !== "success") throw new Error("Transaction failed: " + hash);
    return rc;
  }

  /** Signed fee quote and the createDeal transaction for an agreed trade. The connected wallet is the buyer. */
  quote({ seller, sellToken, sellAmount, payAsset = "eth", payAmount, sellerPayout, buyerReceive, deadlineHours, sellerSig, validUntil, deadline }) {
    return this.#call("/api/v1/settle", { buyer: this.address, seller, sellToken, sellAmount, payAsset, payAmount, sellerPayout, buyerReceive, deadlineHours, sellerSig, validUntil, deadline });
  }

  /** Seller side, step 1: the connected wallet (the seller) signs the exact deal terms. Give the result to the buyer, who passes it to open().
   *  `buyer` is the buyer's wallet. Returns { sellerSig, validUntil, deadline }: pass all three to the buyer's open(). The signature is EIP-712 and the escrow contract checks it. */
  async consent({ buyer, sellToken, sellAmount, payAsset = "eth", payAmount, sellerPayout, buyerReceive, deadlineHours }) {
    const m = await this.#call("/api/v1/settle", { buyer, seller: this.address, sellToken, sellAmount, payAsset, payAmount, sellerPayout, buyerReceive, deadlineHours, consentOnly: true });
    await this.#checkConsent(m.typedData, { buyer, sellToken, sellAmount, payAsset, payAmount, sellerPayout, buyerReceive, deadlineHours });
    const t = m.typedData;
    const message = Object.fromEntries(Object.entries(t.message).map(([k, v]) => [k, /^\d+$/.test(String(v)) ? BigInt(v) : v]));
    const sellerSig = await this.w.signTypedData({ account: this.w.account, domain: t.domain, types: t.types, primaryType: t.primaryType, message });
    return { sellerSig, validUntil: String(t.message.validUntil), deadline: String(t.message.deadline) }; // the values that were signed, not the server's separate fields
  }

  /** Compares the typed data the server wants signed with the terms you passed. Refuses to sign if anything differs. */
  async #checkConsent(typed, t) {
    if (!typed || typed.primaryType !== "Consent" || !typed.message || !typed.domain) bad("unexpected consent data.");
    const f = Object.fromEntries(Object.entries(typed.message).map(([k, v]) => [k, String(v).toLowerCase()]));
    const me = low(this.address);
    const dec = await this.#decimals(t.sellToken); // refuses when the decimals cannot be read: never guess 18
    if (!["eth", "usdg"].includes(low(t.payAsset))) bad("payAsset must be eth or usdg.");
    const payToken = low(t.payAsset) === "usdg" ? USDG : ZERO;
    const payDec = payToken === ZERO ? 18 : 6;
    const want = {
      seller: me, buyer: low(t.buyer), sellToken: low(t.sellToken), sellAmount: parseUnits(String(t.sellAmount), dec).toString(),
      payToken, payAmount: parseUnits(String(t.payAmount), payDec).toString(), sellerPayout: low(t.sellerPayout || ZERO) /* zero = pay the seller */, buyerReceive: low(t.buyerReceive || ZERO),
    };
    for (const k of Object.keys(want)) if (f[k] !== want[k]) bad(`consent has ${k}=${f[k]}, you asked for ${want[k]}.`);
    const d = typed.domain;
    if (d.name !== "BullEscrow" || String(d.version) !== "3" || Number(d.chainId) !== 4663 || !ESCROWS.includes(low(d.verifyingContract))) bad("consent names an unknown escrow contract.");
    const shape = (typed.types?.Consent || []).map((x) => x.name + ":" + x.type).join(",");
    if (shape !== "buyer:address,seller:address,sellerPayout:address,buyerReceive:address,sellToken:address,sellAmount:uint256,payToken:address,payAmount:uint256,deadline:uint64,validUntil:uint64") bad("consent has an unexpected layout.");
    if (!/^\d+$/.test(String(f.validUntil)) || Number(f.validUntil) < Math.floor(Date.now() / 1000) + 60) bad("consent is already expired or has no validity time.");
    const left = Number(f.deadline) - Math.floor(Date.now() / 1000);
    if (!(left > 600 && left <= 60 * 86400)) bad("consent has an unreasonable deadline.");
    if (Number(f.validUntil) > Number(f.deadline)) bad("consent stays valid longer than the deal deadline.");
    if (t.deadlineHours !== undefined && Math.abs(left - Number(t.deadlineHours) * 3600) > 600) bad("consent has a different deadline than you asked for.");
  }

  /** Buyer: opens the escrow deal. Returns the dealId. The createDeal transaction is decoded and checked BEFORE it is sent. */
  async open(params) {
    this.#note(params.sellToken);
    if (!["eth", "usdg"].includes(low(params.payAsset || "eth"))) bad("payAsset must be eth or usdg.");
    const payToken = low(params.payAsset || "eth") === "usdg" ? USDG : ZERO;
    const sd = await this.#decimals(params.sellToken), pd = payToken === ZERO ? 18 : 6;
    const wantSell = parseUnits(String(params.sellAmount), sd), wantPay = parseUnits(String(params.payAmount), pd);
    const me = low(this.address);
    const q = await this.quote(params);
    const pre = (fn) => {
      if (fn.functionName !== "createDeal") return;
      const [p, qt, c] = fn.args, now = Math.floor(Date.now() / 1000);
      if (low(p.seller) !== low(params.seller) || low(p.sellToken) !== low(params.sellToken) || p.sellAmount !== wantSell || low(p.payToken) !== payToken || p.payAmount !== wantPay)
        bad("the createDeal transaction has other terms (seller, token, amounts) than you asked for.");
      const wantPayout = low(params.sellerPayout || ZERO);
      if (low(p.sellerPayout) !== wantPayout && !(wantPayout === ZERO && low(p.sellerPayout) === low(params.seller))) bad("the createDeal transaction pays the seller's proceeds to another wallet than you asked for.");
      if (low(p.buyerReceive) !== low(params.buyerReceive || ZERO) && !(!params.buyerReceive && low(p.buyerReceive) === me)) bad("the createDeal transaction sends the tokens to a wallet other than yours.");
      if (Number(qt.feeBps) > 250) bad("the createDeal transaction has a fee above 2.5%.");
      const left = Number(p.deadline) - now;
      if (!(left > 600 && left <= 60 * 86400)) bad("the createDeal transaction has an unreasonable deadline.");
      if (Number(c.validUntil) < now) bad("the seller's consent in the transaction has expired.");
    };
    const rc = await this.#send(q.transaction, 0n, { fn: ["createDeal"], check: pre });
    const logs = parseEventLogs({ abi: ABI, logs: rc.logs, eventName: "DealCreated" });
    if (!logs.length) throw new Error("DealCreated event not found.");
    const L = logs[0].args;
    if (low(L.buyer) !== me || low(L.seller) !== low(params.seller)) bad("the deal that was opened has a different buyer or seller than you asked for.");
    if (L.feeBps > 250) bad("the deal has a fee above 2.5%.");
    if (q.feeBps !== undefined && Number(L.feeBps) !== Number(q.feeBps)) bad("the deal has a different fee than the quote you were shown.");
    const d = await this.#deal(L.id);
    if (low(d.buyer) !== me || low(d.seller) !== low(params.seller) || low(d.sellToken) !== low(params.sellToken) || d.sellAmount !== wantSell || low(d.payToken) !== payToken || d.payAmount !== wantPay)
      bad("the deal that was created on chain does not match the terms you asked for. Do NOT fund it; cancel it.");
    if (low(d.buyerReceive) !== low(params.buyerReceive || ZERO) && !(!params.buyerReceive && low(d.buyerReceive) === me)) bad("the deal that was created on chain sends the tokens to another wallet than yours. Do NOT fund it; cancel it.");
    const wp = low(params.sellerPayout || ZERO);
    if (low(d.sellerPayout) !== wp && !(wp === ZERO && low(d.sellerPayout) === low(params.seller))) bad("the deal that was created on chain pays the seller's proceeds elsewhere than you asked for. Do NOT fund it; cancel it.");
    return String(L.id);
  }

  /** Current state of a deal and the next transactions of each side. */
  status(dealId) {
    return this.#call("/api/v1/settle/" + dealId);
  }

  /** Sends every pending step of the connected wallet (buyer: pay, seller: deliver tokens). The swap settles when the second side funds.
   *  What each step may do is limited by the deal read from the chain (never by the server). */
  async fund(dealId) {
    const d = await this.#deal(dealId);
    if (d.status !== 1) bad("the deal is not open.");
    const me = low(this.address), buyer = me === low(d.buyer), seller = me === low(d.seller);
    if (!buyer && !seller) bad("this wallet is neither the buyer nor the seller of the deal.");
    const s = await this.status(dealId);
    const mine = [...s.buyerSteps, ...s.sellerSteps].filter((x) => low(x.from) === me);
    const token = buyer ? d.payToken : d.sellToken;
    if (low(token) !== ZERO) this.tokens.add(low(token));
    const maxWei = buyer && low(d.payToken) === ZERO ? d.payAmount : 0n;
    const maxApprove = buyer ? d.payAmount : d.sellAmount;
    const hashes = [];
    for (const step of mine) hashes.push((await this.#send(step.transaction, maxWei, { maxApprove, fn: ["fundPayment", "fundTokens", "fundTokensWithPermit"], id: dealId })).transactionHash);
    return hashes;
  }

  /** Waits until the swap is settled (or cancelled). */
  async waitSettled(dealId, { timeoutMs = 600000, everyMs = 4000 } = {}) {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const s = await this.status(dealId);
      if (s.status === "settled" || s.status === "cancelled") {
        // Never believe the server about this: read the deal from the chain.
        const d = await this.#deal(dealId);
        if (d.status !== (s.status === "settled" ? 2 : 3)) bad(`the server says the deal is ${s.status}, the chain does not.`);
        return s;
      }
      if (Date.now() > end) throw new Error("Timed out waiting for settlement.");
      await new Promise((r) => setTimeout(r, everyMs));
    }
  }

  /** Signed receipt of a settled deal. Public. */
  async receipt(dealId) {
    const j = await this.#call("/api/v1/receipts/" + dealId);
    const r = j.receipt;
    const message = ["Bull receipt v1", ...Object.entries(r).map(([k, x]) => `${k}:${x}`)].join("\n");
    if (message !== j.message) bad("the receipt text does not match its fields.");
    if (low(await recoverMessageAddress({ message, signature: j.signature })) !== FEE_SIGNER) bad("the receipt is not signed by Bull.");
    if (!ESCROWS.includes(low(r.escrow)) || String(r.dealId) !== String(dealId)) bad("the receipt is for a different escrow or deal.");
    const d = await this.#deal(dealId, r.escrow);
    if (d.status !== 2 || low(d.buyer) !== low(r.buyer) || low(d.seller) !== low(r.seller) || low(d.sellToken) !== low(r.sellToken) || String(d.sellAmount) !== r.sellAmount || low(d.payToken) !== low(r.payToken) || String(d.payAmount) !== r.payAmount)
      bad("the chain does not show this deal as settled with these terms.");
    return j;
  }

  /** Locks tokens with an unlock schedule (cliff, then linear or stepped). Returns the lockId. Days can be fractions.
   *  await bull.lock({ token, amount: "1000000", beneficiary, cliffDays: 90, durationDays: 365, stepDays: 30, locker: "0xVestingContractYouTrust" }) */
  async lock({ token, amount, beneficiary, cliffDays = 0, durationDays, stepDays = 0, startAt, locker }) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(String(locker || ""))) bad("pass { locker }: the vesting contract address you trust. It is never taken from the server.");
    const q = await this.#call("/api/v1/vesting", { locker: this.address, token, amount, beneficiary, cliffDays, durationDays, stepDays, startAt });
    this.#note(token);
    const dec = await this.#decimals(token);
    let rc;
    const hex = (a) => low(a).slice(2).padStart(64, "0");
    for (const step of q.steps) {
      const tx = step.transaction, d = String(tx?.data || "").toLowerCase();
      // Only the approval and the call to the locker you pinned are allowed. A call to any Bull contract (createAgreement, fundPayment, ...) is refused, and the locker call must name the token and the beneficiary you asked for.
      if (low(tx?.to) === low(locker) && !d.startsWith("0x095ea7b3") && !(d.includes(hex(token)) && d.includes(hex(beneficiary))))
        bad("the lock transaction does not name the token and the beneficiary you asked for.");
      rc = await this.#send(tx, 0n, { locker, fn: [], maxApprove: parseUnits(String(amount), dec) });
    }
    const logs = parseEventLogs({ abi: LOCK_ABI, logs: rc.logs, eventName: "LockCreated" });
    if (!logs.length) throw new Error("LockCreated event not found.");
    const L = logs[0].args;
    if (low(L.token) !== low(token) || low(L.beneficiary) !== low(beneficiary) || L.amount !== parseUnits(String(amount), dec)) bad("the lock that was created does not match what you asked for.");
    const near = (got, days) => Math.abs(Number(got) - Number(days || 0) * 86400) <= 3600; // within an hour
    if (!near(L.cliff - L.start, cliffDays) || !near(L.end - L.start, durationDays) || !near(L.step, stepDays) || (Number(startAt) > 0 && Number(L.start) !== Math.floor(Number(startAt))))
      bad("the lock that was created has a different cliff, end or step than the schedule you asked for.");
    return String(L.id);
  }

  /** Schedule and unlocked/claimable amounts of a lock. Public. */
  lockStatus(lockId) {
    return this.#call("/api/v1/vesting/" + lockId);
  }

  /** Claims what has unlocked. Anyone can send it, the tokens always go to the beneficiary. */
  async claim(lockId, opts = {}) {
    const s = await this.lockStatus(lockId);
    if (!s.claimTransaction) throw new Error("Nothing to claim yet.");
    if (!opts.locker || low(opts.locker) !== low(s.claimTransaction.to)) bad("pass { locker } with the vesting contract address you trust; the server's claim goes elsewhere.");
    return (await this.#send(s.claimTransaction, 0n, { locker: opts.locker, fn: [] })).transactionHash;
  }

  /** Programmable escrow: pay `payee` when all conditions are true, refund the payer after expiry. Returns the agreementId.
   *  await bull.agree({ payee, asset: "usdg", amount: "500", terms: "Deliver the report", expiryHours: 72,
   *    conditions: [{ type: "attest", by: "0xArbiterOrAgentB" }, { type: "time_after", afterHours: 1 }] })
   *  Condition types: time_after {at|afterHours}, attest {by}, token_balance_gte {token, holder, min}, call_gte / call_lte {target, data, value}. */
  async agree({ payee, asset = "eth", amount, terms, expiryHours, conditions }) {
    const q = await this.#call("/api/v1/agreements", { payer: this.address, payee, asset, amount, terms, expiryHours, conditions });
    this.#note(asset);
    const dec = await this.#decimals(asset);
    const want = parseUnits(String(amount), dec);
    const cap = this.#agreeCap(asset, amount);
    let rc;
    const assetAddr = String(asset).toLowerCase() === "eth" ? ZERO : (String(asset).toLowerCase() === "usdg" ? USDG : low(asset));
    const expect = Array.isArray(conditions) ? await this.#expectConditions(conditions) : null;
    const wantTerms = terms ? keccak256(toHex(String(terms))) : "0x" + "00".repeat(32);
    const creates = (q.steps || []).filter((x) => String(x?.name) === "createAgreement" || low(x?.transaction?.to) === AGREEMENT).length;
    if (creates !== 1) bad(`the server returned ${creates} createAgreement steps, you asked for exactly one.`);
    const check = (fn) => {
      if (fn.functionName !== "createAgreement") return;
      const p = fn.args[0], now = Math.floor(Date.now() / 1000);
      if (low(p.payee) !== low(payee) || low(p.asset) !== assetAddr || p.amount !== want) bad("the agreement transaction has a different payee, asset or amount than you asked for.");
      if (Number(p.expiry) <= now || (expiryHours !== undefined && Math.abs(Number(p.expiry) - (now + Number(expiryHours) * 3600)) > 900)) bad("the agreement transaction has a different expiry than you asked for.");
      if (low(p.termsHash) !== wantTerms) bad("the agreement transaction commits to other terms than the text you passed (termsHash).");
      if (expect) this.#matchConditions(p.conditions, expect);
    };
    for (const step of q.steps) rc = await this.#send(step.transaction, cap, { maxApprove: want, fn: ["createAgreement"], check });
    const logs = parseEventLogs({ abi: AGR_ABI, logs: rc.logs, eventName: "AgreementCreated" });
    if (!logs.length) throw new Error("AgreementCreated event not found.");
    const L = logs[0].args;
    if (low(L.payer) !== low(this.address) || low(L.payee) !== low(payee)) bad("the agreement that was created has a different payer or payee than you asked for.");
    if (L.amount !== want || low(L.asset) !== (String(asset).toLowerCase() === "eth" ? ZERO : (String(asset).toLowerCase() === "usdg" ? USDG : low(asset)))) bad("the agreement that was created has a different asset or amount than you asked for.");
    if (low(L.termsHash) !== wantTerms) bad("the agreement that was created commits to other terms than the text you passed (termsHash).");
    return String(L.id);
  }

  /** The on-chain conditions (kind, target, data, value) that the conditions you passed must turn into. */
  async #expectConditions(conditions) {
    const now = Math.floor(Date.now() / 1000), out = [];
    for (const c of conditions) {
      const at = (x) => (Number(x.at) > 0 ? { v: BigInt(Math.floor(Number(x.at))), tol: 0 } : { v: BigInt(now + Math.round(Number(x.afterHours) * 3600)), tol: 900 });
      if (c.type === "time_after") out.push({ kind: 0, target: ZERO, ...at(c) });
      else if (c.type === "unless") out.push({ kind: 5, target: low(c.by), ...at(c) });
      else if (c.type === "attest") out.push({ kind: 1, target: low(c.by) });
      else if (c.type === "token_balance_gte") out.push({ kind: 7, target: low(c.token), data: encodeFunctionData({ abi: erc20Abi, functionName: "balanceOf", args: [c.holder] }).toLowerCase(), v: parseUnits(String(c.min), await this.#decimals(c.token)), tol: 0 });
      else if (c.type === "call_gte" || c.type === "call_lte") out.push({ kind: c.type === "call_gte" ? 7 : 8, target: low(c.target), data: low(c.data), v: BigInt(c.value), tol: 0 });
      else if (c.type === "deal_settled") out.push({ kind: 4, target: low(c.escrow || ESCROWS[0]), v: BigInt(c.dealId), tol: 0 });
      else if (c.type === "quorum") out.push({ kind: 6, target: ZERO, data: encodeAbiParameters([{ type: "address[]" }], [c.by]).toLowerCase(), v: BigInt(c.k), tol: 0 });
      else bad(`unknown condition type ${c.type}.`);
    }
    return out;
  }

  /** Every on-chain condition must equal the one you asked for, in order: kind, target, data and value. */
  #matchConditions(got, expect) {
    if (got.length !== expect.length) bad("the agreement transaction has a different number of conditions than you asked for.");
    got.forEach((g, i) => {
      const e = expect[i], v = BigInt(g.value), d = e.v === undefined ? 0n : e.v, tol = BigInt(e.tol || 0);
      if (Number(g.kind) !== e.kind || low(g.target) !== e.target || (e.data !== undefined && low(g.data) !== e.data) || (e.v !== undefined && (v < d - tol || v > d + tol)) || (e.v === undefined && v !== 0n))
        bad(`condition ${i + 1} of the agreement transaction is not the one you asked for.`);
    });
  }

  // Most ETH an agreement transaction may carry: the amount (if paid in ETH) plus a fee allowance.
  #agreeCap(asset, amount, mult = 105n) {
    const fee = parseEther("0.05");
    return String(asset || "eth").toLowerCase() === "eth" ? (parseEther(String(amount)) * mult) / 100n + fee : fee;
  }

  /** Status, every condition (met true/false) and the next transactions. Public. */
  agreement(id) {
    return this.#call("/api/v1/agreements/" + id);
  }

  /** Sends every pending action of the connected wallet on an agreement: attest (confirm), vote (panel) or, with
   *  { object: true }, the objection of an "unless" window. */
  async attest(id, { object = false } = {}) {
    const a = await this.agreement(id);
    const mine = a.conditions.flatMap((c) => c.actions).filter((x) => x.from.toLowerCase() === this.address.toLowerCase() && (object ? x.name === "object" : x.name !== "object"));
    if (!mine.length) throw new Error("Nothing to " + (object ? "object to" : "confirm") + " from this wallet.");
    const hashes = [];
    for (const x of mine) hashes.push((await this.#send(x, 0n, { fn: object ? ["object"] : ["attest", "vote"], id })).transactionHash);
    return hashes;
  }

  /** Objects during an objection window (template "optimistic"): the payee is then not paid automatically. */
  object(id) {
    return this.attest(id, { object: true });
  }

  /** Deal templates and their fields. Public. */
  templates() {
    return this.#call("/api/v1/templates");
  }

  /** One call for a standard deal. Returns the agreement id (an array for "milestones").
   *  await bull.deal("arbiter_escrow", { payee, asset: "usdg", amount: "500", arbiter: "0xArbiter", terms: "Deliver the report" })
   *  Templates: delivery_vs_payment, arbiter_escrow, milestones, optimistic, panel, after_deal, balance_trigger, price_trigger. */
  async deal(template, params) {
    if (template === "delivery_vs_payment") return this.open({ seller: params.seller, sellToken: params.sellToken, sellAmount: params.sellAmount, payAsset: params.payAsset, payAmount: params.payAmount, deadlineHours: params.deadlineHours });
    const q = await this.#call("/api/v1/templates", { ...params, template, payer: this.address });
    this.#note(params.asset);
    const dec = await this.#decimals(params.asset || "eth");
    const total = parseUnits(String(params.amount), dec);
    const cap = this.#agreeCap(params.asset || "eth", params.amount);
    const ids = [];
    let sum = 0n;
    const assetAddr = String(params.asset || "eth").toLowerCase() === "eth" ? ZERO : (String(params.asset).toLowerCase() === "usdg" ? USDG : low(params.asset));
    const n = template === "milestones" ? Math.round(Number(params.milestones)) : 1;
    if (template === "milestones" && !(n >= 2 && n <= 8)) bad("milestones must be 2 to 8.");
    const creates = (q.steps || []).filter((x) => String(x?.name) === "createAgreement" || low(x?.transaction?.to) === AGREEMENT).length;
    if (creates !== n) bad(`the server returned ${creates} createAgreement steps, you asked for ${n}.`);
    // Conditions each template must produce (kind and target). The arbiter / payer / token you passed must be the ones in the transaction.
    const me = low(this.address), arb = low(params.arbiter);
    const shape = {
      arbiter_escrow: [[1, arb]], performance_bond: [[1, arb]], milestones: [[1, arb]], optimistic: [[5, me]], panel: [[6, ZERO]], two_of_three: [[6, ZERO]],
      scheduled_payment: [[0, ZERO]], confirmed_with_cooling: [[1, arb], [5, me]], after_deal: [[4, null]], balance_trigger: [[7, low(params.token)]],
      price_trigger: [[params.op === "lte" ? 8 : 7, low(params.target)]],
    }[template];
    if (!shape && template !== "token_price_trigger") bad(`unknown template ${template}.`);
    const wantTerms = params.terms ? keccak256(toHex(String(params.terms))) : "0x" + "00".repeat(32);
    const hoursMax = Math.max(Number(params.expiryHours) || 72, Number(params.windowHours || 0) + 24, Number(params.afterHours || 0) + 24, template === "milestones" ? (Number(params.stepHours) || 168) * n : 0);
    let seen = 0;
    const check = (fn) => {
      if (fn.functionName !== "createAgreement") return;
      const p = fn.args[0], now = Math.floor(Date.now() / 1000);
      seen++;
      if (low(p.asset) !== assetAddr || (params.payee && low(p.payee) !== low(params.payee))) bad("the agreement transaction has a different payee or asset than you asked for.");
      if (template === "milestones" ? (p.amount > total || p.amount < total / BigInt(n) - BigInt(n) * 10n ** BigInt(Math.max(0, dec - 6))) : p.amount !== total) bad("the agreement transaction has a different amount than you asked for.");
      if (Number(p.expiry) <= now || Number(p.expiry) > now + hoursMax * 3600 + 900) bad("the agreement transaction has an expiry that does not fit the expiryHours you asked for.");
      if (low(p.termsHash) !== wantTerms && !(template === "milestones")) bad("the agreement transaction commits to other terms than the text you passed (termsHash).");
      if (shape) {
        if (p.conditions.length !== shape.length) bad("the agreement transaction has a different number of conditions than the template defines.");
        shape.forEach(([kind, target], i) => { const g = p.conditions[i]; if (Number(g.kind) !== kind || (target !== null && low(g.target) !== target)) bad(`condition ${i + 1} of the agreement transaction is not the one the template defines for the parameters you passed.`); });
        if (template === "price_trigger" && (low(p.conditions[0].data) !== low(params.data) || BigInt(p.conditions[0].value) !== BigInt(params.value))) bad("the price condition has another data or threshold than you asked for.");
        if (template === "after_deal" && p.conditions[0].value !== BigInt(params.dealId)) bad("the deal_settled condition names another deal than you asked for.");
      }
      if (sum + p.amount > total) bad("the agreement transactions would lock more than the amount you asked for.");
      sum += p.amount; // counted BEFORE it is sent
    };
    for (const step of q.steps) {
      const rc = await this.#send(step.transaction, cap, { maxApprove: total, fn: ["createAgreement"], check });
      for (const l of parseEventLogs({ abi: AGR_ABI, logs: rc.logs, eventName: "AgreementCreated" })) ids.push(String(l.args.id));
    }
    if (seen !== n || ids.length !== n) bad(`${ids.length} agreements were created, you asked for ${n}.`);
    if (sum > total || (template === "milestones" ? total - sum > BigInt(n) * 10n ** BigInt(Math.max(0, dec - 6)) : sum !== total)) bad("the agreements that were created do not add up to the amount you asked for.");
    return template === "milestones" ? ids : ids[0];
  }

  /** Pays the payee once every condition is true (anyone can send it). */
  async release(id) {
    const a = await this.agreement(id);
    if (!a.releaseTransaction) throw new Error("Not releasable yet: " + a.conditions.filter((c) => !c.met).map((c) => c.type).join(", "));
    return (await this.#send(a.releaseTransaction, 0n, { fn: ["release"], id })).transactionHash;
  }

  /** After the expiry, sends the funds back to the payer (anyone can send it). */
  async refund(id) {
    const a = await this.agreement(id);
    if (!a.refundTransaction) throw new Error("Not refundable yet.");
    return (await this.#send(a.refundTransaction, 0n, { fn: ["refund"], id })).transactionHash;
  }
}
