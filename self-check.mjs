import assert from "node:assert/strict";
import {digest, encode, policyFields, quoteFields, receiptFields, verify} from "./verify.mjs";

const keypair = () => crypto.subtle.generateKey({name:"ECDSA", namedCurve:"P-256"}, true, ["sign","verify"]);
const buyer = await keypair(), signer = await keypair();
const buyerKey = await crypto.subtle.exportKey("jwk", buyer.publicKey);
const issuer = await crypto.subtle.exportKey("jwk", signer.publicKey);
const sign = async (key, bytes) => Buffer.from(await crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, key, bytes)).toString("hex");
const pack = (domain, keys, data) => encode(domain, keys.map(key => data[key]));
const policy = {chain:"196", container:"0x" + "01".repeat(20), version:"fixture", model:"test-model", input:"1000000", output:"2000000"};
const manifest = {policy, issuer};
const quote = {policyHash:await digest(encode("sumplus-policy-v1", [...policyFields.map(key => policy[key]), issuer.x, issuer.y])),
  nonce:"aa".repeat(32), maxCharge:"250", expires:"100"};
const quoteBytes = pack("sumplus-quote-v1", quoteFields, quote);
const receipt = {quoteHash:await digest(encode("sumplus-bound-quote-v1", [await digest(quoteBytes), buyerKey.x, buyerKey.y])),
  requestHash:"bb".repeat(32), model:"test-model", input:"24", output:"107", cached:"0", charge:"238", completed:"99"};
const buyerSignature = await sign(buyer.privateKey, quoteBytes);
const wrap = async r => ({quote, receipt:r, buyerSignature,
  issuerSignature:await sign(signer.privateKey, pack("sumplus-receipt-v1", receiptFields, r))});
const bundle = await wrap(receipt);
assert.deepEqual(await verify(bundle, manifest, buyerKey), {input:"24",output:"107",chargeNanoUsd:"238"});
await assert.rejects(verify({...bundle,receipt:{...receipt,input:"25"}},manifest,buyerKey), /Invalid issuer signature/);
await assert.rejects(verify(await wrap({...receipt,charge:"239"}),manifest,buyerKey), /Charge mismatch/);
await assert.rejects(verify(await wrap({...receipt,output:"120",charge:"264"}),manifest,buyerKey), /exceeds budget/);
await assert.rejects(verify(await wrap({...receipt,completed:"101"}),manifest,buyerKey), /expired/);
await assert.rejects(verify(await wrap({...receipt,cached:"1"}),manifest,buyerKey), /cache/);
await assert.rejects(verify(bundle,{...manifest,policy:{...policy,input:"2"}},buyerKey), /Unrecognized policy/);
await assert.rejects(verify(bundle,{...manifest,policy:{...policy,chain:"56"}},buyerKey), /Wrong deployment/);
await assert.rejects(verify(bundle,manifest,issuer), /Invalid buyer signature/);
console.log("PASS: valid signed fixture; eight negative controls");
if (process.argv.includes("--write-fixture")) {
  const {mkdir,writeFile} = await import("node:fs/promises");
  const dir = new URL("./fixtures/", import.meta.url);
  await mkdir(dir, {recursive:true});
  for (const [name,value] of Object.entries({manifest, buyer:buyerKey, bundle,
    tampered:{...bundle,receipt:{...receipt,input:"25"}}})) {
    await writeFile(new URL(name + ".json", dir), JSON.stringify(value, null, 2) + "\n");
  }
}
