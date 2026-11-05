// Offline wallet-page regression. Every provider and signature request is simulated.
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {createHash, webcrypto} from "node:crypto";
import {readFile} from "node:fs/promises";
import vm from "node:vm";

const html = await readFile(new URL("./wallet-steps.html", import.meta.url), "utf8");
const source = html.match(/<script type="module">([\s\S]+)<\/script>/)[1];
const opened = JSON.parse(await readFile(new URL("./container-opened-preflight.json", import.meta.url), "utf8"));
const wallet = "0x91000b484b5d4d5ba888c8a2f5dbdbbbcbf788d2";
const registry = "0xd6efb7adcc9c83dc4924ad56f6a8e4e969b9adb6";
const container = opened.resolvedCircuit.container;
const release = Buffer.from("<html>Offline publication regression fixture</html>");
const hash = "0x" + createHash("sha256").update(release).digest("hex");
const data = execFileSync("cast", ["calldata", "putFile(address,string,string,bytes32,bytes)",
  container, "v1/index.html", "text/html", hash, "0x" + release.toString("hex")], {encoding:"utf8"}).trim();
const prior = BigInt(opened.budget.actualAcquisitionSpendWei);
const gas = 1200000n, gasPrice = 20000001n;
const plan = {...opened, publication:{container, registry, path:"v1/index.html", sha256:hash,
  size:release.length, contentType:"text/html", implementation:opened.siteRegistry.implementation, existingChunks:0},
  walletStep:{stage:"publish", transaction:{from:wallet,to:registry,chainId:"0xc4",value:"0x0",data,
    gas:"0x" + gas.toString(16),gasPrice:"0x" + gasPrice.toString(16),nonce:"0x3"},
    budgetWei:"90000000000000000",previousActualSpendWei:String(prior),futureReservedValueWei:"0",
    maxGasFeeWei:String(gas * gasPrice),maxTotalWithFutureValuesWei:String(prior + gas * gasPrice)}};

async function exercise({mutate = () => {}, occupied = false} = {}) {
  const candidate = structuredClone(plan);
  mutate(candidate);
  const ids = ["providers","connect","plan","review","sign","status","discover","switch"];
  const nodes = Object.fromEntries(ids.map(id => [id, {value:"",textContent:"",append(option) {this.value = option.value;}}]));
  nodes.plan.files = [{size:JSON.stringify(candidate).length,text:async () => JSON.stringify(candidate)}];
  const journal = new Map();
  let sends = 0;
  const provider = {request:async ({method, params}) => {
    if (method === "eth_accounts" || method === "eth_requestAccounts") return [wallet];
    if (method === "eth_chainId") return 196;
    if (method === "eth_getTransactionCount") return params[1] === "pending" ? 3 : "0x03";
    if (method === "eth_blockNumber") return "0x" + (opened.block + 10).toString(16);
    if (method === "eth_getBalance") return "0x" + BigInt(opened.budget.walletBalanceWei).toString(16);
    if (method === "eth_estimateGas") return 1000000;
    if (method === "eth_gasPrice") return Number(gasPrice);
    if (method === "eth_getStorageAt") return opened.siteRegistry.implementation;
    if (method === "eth_call" && params[0].data.startsWith("0x6c609107")) {
      return "0x" + "0".repeat(256) + (occupied ? "1" : "0").padStart(64,"0");
    }
    if (method === "eth_call" && params[0].data === "0x8da5cb5b") return "0x" + wallet.slice(2).padStart(64,"0");
    if (method === "eth_sendTransaction") {sends++;return "0x" + "ab".repeat(32);}
    throw new Error("Unexpected fake RPC " + method);
  }};
  vm.runInNewContext(source, {
    document:{getElementById:id => nodes[id],createElement:() => ({})},
    window:{ethereum:provider,addEventListener() {},dispatchEvent() {}}, Event:class {},
    navigator:{locks:{request:async (key, options, action) => action({})}}, crypto:webcrypto, TextEncoder, TextDecoder,
    localStorage:{getItem:key => journal.get(key),setItem:(key,value) => journal.set(key,value),removeItem:key => journal.delete(key)}
  });
  await nodes.connect.onclick();
  await nodes.plan.onchange();
  if (!nodes.sign.disabled) await nodes.sign.onclick();
  return {sends,status:nodes.status.textContent};
}
assert.equal((await exercise()).sends, 1);
const tampered = await exercise({mutate:p => {p.publication.sha256 = "0x" + "00".repeat(32);}});
assert.equal(tampered.sends, 0);
assert.match(tampered.status, /SHA-256/);
const occupied = await exercise({occupied:true});
assert.equal(occupied.sends, 0);
assert.match(occupied.status, /occupied/);
assert.equal((await exercise({mutate:p => {p.walletStep.previousActualSpendWei = "90000000000000000";}})).sends, 0);
assert.equal((await exercise({mutate:p => {p.walletStep.transaction.to = container;}})).sends, 0);
console.log("PASS: offline publish signing request; altered SHA, occupied path, budget overflow and wrong registry all block signing");
