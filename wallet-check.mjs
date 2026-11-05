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

async function exercise({mutate = () => {}, occupied = false, activation = false, feeChanged = false, alreadyActive = false} = {}) {
  const candidate = structuredClone(activation ? activationPlan : plan);
  mutate(candidate);
  const ids = ["providers","connect","plan","review","sign","status","discover","switch"];
  const nodes = Object.fromEntries(ids.map(id => [id, {value:"",textContent:"",append(option) {this.value = option.value;}}]));
  nodes.plan.files = [{size:JSON.stringify(candidate).length,text:async () => JSON.stringify(candidate)}];
  const journal = new Map();
  let sends = 0;
  const provider = {request:async ({method, params}) => {
    if (method === "eth_accounts" || method === "eth_requestAccounts") return [wallet];
    if (method === "eth_chainId") return 196;
    if (method === "eth_getTransactionCount") return params[1] === "pending" ? Number(BigInt(candidate.walletStep.transaction.nonce)) : candidate.walletStep.transaction.nonce;
    if (method === "eth_blockNumber") return "0x" + (candidate.block + 10).toString(16);
    if (method === "eth_getBalance") return "0x" + BigInt(opened.budget.walletBalanceWei).toString(16);
    if (method === "eth_estimateGas") return activation ? 188121 : 1000000;
    if (method === "eth_gasPrice") return Number(gasPrice);
    if (method === "eth_getStorageAt") return activation ? candidate.binding.implementation : opened.siteRegistry.implementation;
    if (method === "eth_call" && params[0].data.startsWith("0x6c609107")) {
      return "0x" + "0".repeat(256) + (occupied ? "1" : "0").padStart(64,"0");
    }
    if (method === "eth_call" && params[0].data === "0x8cfd3e40") return "0x"+(feeChanged?"1":"0").padStart(64,"0");
    if (method === "eth_call" && (params[0].data.startsWith("0xdcca979e")||params[0].data.startsWith("0xd6b062cd"))) return "0x"+(alreadyActive?"1":"0").padStart(64,"0");
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
const activationPlan = JSON.parse(await readFile(new URL("./wallet-plan-activate.json",import.meta.url),"utf8"));
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

const activationPositive=await exercise({activation:true});
assert.equal(activationPositive.sends,1,activationPositive.status);
assert.equal((await exercise({activation:true,mutate:p=>{p.binding.name="wrong.tape";}})).sends,0);
assert.equal((await exercise({activation:true,mutate:p=>{p.binding.container=registry;}})).sends,0);
assert.equal((await exercise({activation:true,mutate:p=>{p.walletStep.transaction.value="0x1";}})).sends,0);
const feeChanged = await exercise({activation:true,feeChanged:true});
assert.equal(feeChanged.sends,0);assert.match(feeChanged.status,/no longer free/);
const alreadyActive = await exercise({activation:true,alreadyActive:true});
assert.equal(alreadyActive.sends,0);assert.match(alreadyActive.status,/already activated/);
console.log("PASS: offline zero-value activation request; incorrect name/container/value, changed fee and redundant activation blocked");
