import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import vm from "node:vm";
import {mkdtemp, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {journalTransport, makeAuthorization, replayStudio, reserveStudio, runStudio} from "./studio.mjs";
import {digest, encode, outcomeReceiptFields, verify} from "./verify.mjs";

async function keys() {
  const pair = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"}, true, ["sign","verify"]);
  return {
    pub:await crypto.subtle.exportKey("jwk", pair.publicKey),
    priv:await crypto.subtle.exportKey("jwk", pair.privateKey)
  };
}

const buyer = await keys(), issuer = await keys();
const manifest = {issuer:issuer.pub, policy:{chain:"196", container:"0x" + "01".repeat(20), version:"mock-v2",
  model:"fixture-model", provider:"fixture-line", activityProvider:"[F]", input:"2000000", output:"3000000",
  maxInput:"32", maxOutput:"8", requestProfile:"studio-text-v1"}};
const cap = "100";
const expiry = String(Math.floor(Date.now() / 1000) + 300);
const authorization = await makeAuthorization(manifest, buyer.priv, cap, expiry);
const key = {id:"test-studio-key", revoked:false, lifetime_requests:3, lifetime_cost_usd:0, lifetime_prompt_tokens:0, lifetime_completion_tokens:0,
  allowance_spent_usd:0, remaining_allowance_usd:0.0000001};
const row = {key_id:key.id, model:manifest.policy.model, provider:manifest.policy.activityProvider, status:"ok",
  stream:false, prompt_tokens:24, completion_tokens:7, cost_usd:0.000000069};
const response = {model:manifest.policy.model, choices:[{message:{content:"OK"},finish_reason:"stop"}],
  usage:{prompt_tokens:24, completion_tokens:7, total_tokens:31, prompt_tokens_details:{cached_tokens:0},completion_tokens_details:{reasoning_tokens:0}}};

function mock(options = {}) {
  const effective = options.manifest ?? manifest;
  let posted = 0;
  let keyReads = 0;
  return {posts:() => posted, request:async (path, body) => {
    if (path === "/v1/me/key") {
      const snapshot = options.key ?? key;
      return {body:{...snapshot,lifetime_requests:snapshot.lifetime_requests + ++keyReads}};
    }
    if (path === "/v1/me/activity?limit=3") return {body:{data:posted ? (options.rows ?? [row]) : []}};
    assert.equal(path, "/v1/chat/completions");
    assert.deepEqual(body, {model:effective.policy.model, messages:[{role:"user",content:"Reply with the single word OK."}],
      max_tokens:Number(effective.policy.maxOutput), stream:false, saferouter:{provider:effective.policy.provider,fallback:false}});
    posted++;
    const payload = options.response ?? response;
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const headers = new Headers({"x-saferouter-call-id":"mock-call", "x-saferouter-response-sha256":await digest(bytes)});
    if (options.badHash) headers.set("x-saferouter-response-sha256", "00".repeat(32));
    if (options.fallback) headers.set("x-saferouter-fallback-from", "another-model");
    return {body:payload, bytes, headers};
  }};
}

const args = {manifest, authorization, buyer:buyer.pub, issuerJwk:issuer.priv, reserve:async () => {}};
const positive = mock();
const bundle = await runStudio({...args, request:positive.request});
const verified = await verify(bundle, manifest, buyer.pub);
assert.equal(verified.chargeNanoUsd, "69");
assert.equal(verified.billedUsd, "6.9e-8");
assert.equal(verified.maxChargeNanoUsd, "100");
assert.equal(positive.posts(), 1);
for (const count of [3,4,1000]) {
  const readOnlyUsed = mock({key:{...key,lifetime_requests:count}});
  const result = await runStudio({...args,request:readOnlyUsed.request});
  assert.equal((await verify(result,manifest,buyer.pub)).chargeNanoUsd,"69");
  assert.equal(readOnlyUsed.posts(),1);
}
assert.doesNotMatch(JSON.stringify(bundle), /mock-call|test-studio-key|Reply with|content|upstream/i);

const allocatedKey = {...key,remaining_allowance_usd:0.01};
const explicit = mock({key:allocatedKey});
const explicitBundle = await runStudio({...args,request:explicit.request,operatorCapNanoUsd:"1000000"});
assert.equal((await verify(explicitBundle,manifest,buyer.pub)).chargeNanoUsd,"69");
assert.equal(explicit.posts(),1);
for (const [operatorCapNanoUsd,allocation] of [[undefined,0.01],["99",0.01],["1000001",0.01],["1000000",0.02]]) {
  const invalid = mock({key:{...key,remaining_allowance_usd:allocation}});
  await assert.rejects(runStudio({...args,request:invalid.request,operatorCapNanoUsd}), /operator cap|unbilled studio key/);
  assert.equal(invalid.posts(),0);
}

const noDispatch = mock();
await assert.rejects(runStudio({...args, authorization:{...authorization,quote:{...authorization.quote,maxCharge:"101"}},
  request:noDispatch.request}), /Invalid buyer signature/);
const expired = await makeAuthorization(manifest, buyer.priv, cap, "1");
await assert.rejects(runStudio({...args, authorization:expired, request:noDispatch.request}), /expired before dispatch/);
await assert.rejects(runStudio({...args, issuerJwk:buyer.priv, request:noDispatch.request}), /signer does not match/);
assert.equal(noDispatch.posts(), 0);
await assert.rejects(makeAuthorization(manifest, buyer.priv, "87", expiry), /ceilings exceed/);
const tampered = {...bundle,receipt:{...bundle.receipt,input:"25"}};
await assert.rejects(verify(tampered, manifest, buyer.pub), /Invalid issuer signature/);
await assert.rejects(verify(bundle,{...manifest,policy:{...manifest.policy,input:"2000001"}},buyer.pub), /Unrecognized policy/);

for (const [options, pattern, postCount] of [
  [{key:{...key,lifetime_cost_usd:0.000001}}, /unbilled studio key/, 0],
  [{key:{...key,lifetime_prompt_tokens:1}}, /unbilled studio key/, 0],
  [{key:{...key,lifetime_completion_tokens:1}}, /unbilled studio key/, 0],
  [{key:{...key,allowance_spent_usd:0.000001}}, /unbilled studio key/, 0],
  [{key:{...key,remaining_allowance_usd:0.00001}}, /unbilled studio key/, 0],
  [{badHash:true}, /response evidence/, 1],
  [{fallback:true}, /response evidence/, 1],
  [{response:{...response,usage:{...response.usage,prompt_tokens_details:{}}}}, /cache/, 1],
  [{response:{...response,usage:{...response.usage,prompt_tokens_details:{cached_tokens:1}}}}, /cache/, 1],
  [{response:{...response,usage:{...response.usage,total_tokens:30}}}, /token usage/, 1],
  [{rows:[row,row]}, /single billed activity/, 1],
  [{rows:[{...row,provider:"unexpected"}]}, /did not match/, 1]
]) {
  const gateway = mock(options);
  await assert.rejects(runStudio({...args, request:gateway.request}), pattern);
  assert.equal(gateway.posts(), postCount);
}

const mismatch = mock({rows:[{...row,cost_usd:0.000000073}]});
const mismatches = [];
await assert.rejects(runStudio({...args, request:mismatch.request, recordMismatch:async evidence => mismatches.push(evidence)}),
  /differs from quoted charge/);
assert.equal(mismatch.posts(), 1);
assert.deepEqual(mismatches, [{quoteHash:bundle.receipt.quoteHash,requestHash:bundle.receipt.requestHash,input:"24",output:"7",
  billedUsd:"7.3e-8",quotedChargeNanoUsd:"69"}]);

const journal = await mkdtemp(join(tmpdir(), "receipt-desk-"));
try {
  const attempt = mock({badHash:true});
  const reserve = reserveStudio(journal);
  await assert.rejects(runStudio({...args, request:attempt.request, reserve}), /response evidence/);
  const afterFailure = mock();
  await assert.rejects(runStudio({...args, request:afterFailure.request, reserve:reserveStudio(journal)}), /already consumed/);
  assert.equal(attempt.posts(), 1);
  assert.equal(afterFailure.posts(), 0);
  const otherAuth = await makeAuthorization(manifest, buyer.priv, cap, expiry);
  const afterNewQuote = mock();
  await assert.rejects(runStudio({...args, authorization:otherAuth, request:afterNewQuote.request, reserve}), /already consumed/);
  assert.equal(afterNewQuote.posts(), 0);
} finally {
  await rm(journal, {recursive:true, force:true});
}

const aliasManifest = {issuer:issuer.pub,policy:{...manifest.policy,model:"deepseek-v4-flash",provider:"cm",
  activityProvider:"C",input:"84000000",output:"168000000",maxInput:"128",maxOutput:"8"}};
const aliasAuthorization = await makeAuthorization(aliasManifest,buyer.priv,"1000000",expiry);
const aliasResponse = {model:"deepseek-v4.1-flash",choices:[{message:{content:""},finish_reason:"length"}],
  usage:{prompt_tokens:37,completion_tokens:8,total_tokens:45,prompt_tokens_details:{cached_tokens:0},
    completion_tokens_details:{reasoning_tokens:8}}};
const aliasRow = {...row,model:"deepseek-v4-flash",provider:"C",prompt_tokens:37,completion_tokens:8,cost_usd:4.452000000000001e-6};
const aliasGateway = mock({manifest:aliasManifest,key:{...key,remaining_allowance_usd:0.01},response:aliasResponse,rows:[aliasRow]});
const aliasBundle = await runStudio({...args,manifest:aliasManifest,authorization:aliasAuthorization,
  request:aliasGateway.request,operatorCapNanoUsd:"1000000"});
const aliasResult = await verify(aliasBundle,aliasManifest,buyer.pub);
assert.equal(aliasResult.chargeNanoUsd,"4452");
assert.equal(aliasResult.requestedModel,"deepseek-v4-flash");
assert.equal(aliasResult.returnedModel,"deepseek-v4.1-flash");
assert.equal(aliasResult.finishReason,"length");
assert.equal(aliasResult.reasoningTokens,"8");
assert.equal(aliasResult.nonReasoningTokens,"0");
assert.deepEqual(aliasBundle.quote,aliasAuthorization.quote);
assert.equal(aliasBundle.buyerSignature,aliasAuthorization.buyerSignature);
for (const change of [{returnedModel:"deepseek-v4.2-flash"},{finishReason:"stop"},{reasoningTokens:"7"},{input:"38"}]) {
  await assert.rejects(verify({...aliasBundle,receipt:{...aliasBundle.receipt,...change}},aliasManifest,buyer.pub),/Invalid issuer signature/);
}
const aliasSigningKey = await crypto.subtle.importKey("jwk",issuer.priv,{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
for (const [change,message] of [[{returnedModel:"unrecognized-model"},/Unsupported returned model alias/],
  [{finishReason:"unknown"},/Unsupported finish reason/],[{reasoningTokens:"9"},/exceed output/]]) {
  const receipt = {...aliasBundle.receipt,...change};
  const issuerSignature = Buffer.from(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},aliasSigningKey,
    encode("sumplus-receipt-v3",outcomeReceiptFields.map(field => receipt[field])))).toString("hex");
  await assert.rejects(verify({...aliasBundle,receipt,issuerSignature},aliasManifest,buyer.pub),message);
}
const unknownAlias = mock({manifest:aliasManifest,key:{...key,remaining_allowance_usd:0.01},
  response:{...aliasResponse,model:"deepseek-v4.2-flash"},rows:[aliasRow]});
await assert.rejects(runStudio({...args,manifest:aliasManifest,authorization:aliasAuthorization,
  request:unknownAlias.request,operatorCapNanoUsd:"1000000"}),/Unsupported returned model alias/);
assert.equal(unknownAlias.posts(),1);

const browserDirectory = await mkdtemp(join(tmpdir(),"receipt-outcome-browser-"));
try {
  const manifestFile = join(browserDirectory,"manifest.json"),htmlFile = join(browserDirectory,"index.html");
  await writeFile(manifestFile,JSON.stringify(aliasManifest));
  execFileSync(process.execPath,[new URL("./build.mjs",import.meta.url).pathname,manifestFile,htmlFile]);
  const {readFile} = await import("node:fs/promises");
  const html = await readFile(htmlFile,"utf8");
  const nodes = {header:{textContent:"SUMPLUS"},"#status":{textContent:""},buyer:{files:[]},bundle:{files:[]},
    form:{addEventListener(type,handler) {this.handler=handler;}}};
  vm.runInNewContext(html.match(/<script type="module">([\s\S]+)<\/script>/)[1],
    {document:{querySelector:name => nodes[name],getElementById:name => nodes[name]},crypto,TextEncoder,Uint8Array});
  const choose = (id,value) => {const text=JSON.stringify(value);nodes[id].files=[{size:text.length,text:async()=>text}];};
  choose("buyer",buyer.pub);choose("bundle",aliasBundle);
  const button={};await nodes.form.handler({preventDefault(){},target:{querySelector:()=>button}});
  assert.match(nodes["#status"].textContent,/Requested and billed model: deepseek-v4-flash/);
  assert.match(nodes["#status"].textContent,/Returned model: deepseek-v4.1-flash/);
  assert.match(nodes["#status"].textContent,/Finish reason: length/);
  assert.match(nodes["#status"].textContent,/Reasoning tokens: 8/);
  assert.match(nodes["#status"].textContent,/Other output tokens: 0/);
  assert.match(nodes["#status"].textContent,/Generation ended at the output limit/);
  choose("bundle",{...aliasBundle,receipt:{...aliasBundle.receipt,finishReason:"stop"}});
  await nodes.form.handler({preventDefault(){},target:{querySelector:()=>button}});
  assert.match(nodes["#status"].textContent,/Invalid issuer signature/);
  assert.equal(button.disabled,false);
} finally {await rm(browserDirectory,{recursive:true,force:true});}
console.log("PASS: exact CM alias, signed returned model/finish/reasoning metadata, tamper controls and generated-page browser stub");

const captured = await mkdtemp(join(tmpdir(),"receipt-capture-"));
try {
  const prefix = "cd".repeat(12);
  const started = Math.floor(Date.now()/1000);
  const contextPath = join(captured,"context.json");
  await writeFile(contextPath,JSON.stringify({manifest,authorization,buyer:buyer.pub,capturePrefix:prefix,started}),{mode:0o600});
  const capture = journalTransport(captured,prefix);
  const source = mock();
  const recordedRequest = async (path,body) => {
    const raw = await source.request(path,body);
    const bytes = raw.bytes ?? new TextEncoder().encode(JSON.stringify(raw.body));
    const headers = new Headers(raw.headers);
    headers.set("authorization","secret-header-must-not-persist");
    headers.set("set-cookie","secret-cookie-must-not-persist");
    const result = await capture(path,body,async () => new Response(bytes,{status:200,headers}));
    return {body:JSON.parse(new TextDecoder().decode(result.bytes)),bytes:result.bytes,headers:result.response.headers};
  };
  const liveMock = await runStudio({...args,request:recordedRequest});
  const replayed = await replayStudio(contextPath,issuer.priv);
  assert.equal((await verify(replayed,manifest,buyer.pub)).chargeNanoUsd,"69");
  assert.equal(replayed.receipt.quoteHash,liveMock.receipt.quoteHash);
  assert.equal(source.posts(),1);
  const {readdir,readFile,stat} = await import("node:fs/promises");
  const files = await readdir(captured);
  for (const file of files) {
    assert.equal((await stat(join(captured,file))).mode & 0o777,0o600);
    assert.doesNotMatch(await readFile(join(captured,file),"utf8"),/secret-header-must-not-persist|secret-cookie-must-not-persist/);
  }
  // Both post-call observations are persisted even if later receipt validation fails.
  assert.equal(files.filter(file => file.endsWith(".bin")).length,5);
  await writeFile(join(captured,"capture-"+prefix+"-003.bin"),"changed bytes",{mode:0o600});
  await assert.rejects(replayStudio(contextPath,issuer.priv),/capture bytes changed/);
  const failedCapture = journalTransport(captured,"ef".repeat(12));
  let attempts = 0;
  await assert.rejects(failedCapture("/v1/chat/completions",{},async () => {attempts++;throw new Error("simulated timeout");}),/simulated timeout/);
  assert.equal(attempts,1);
  const timeoutRecord = JSON.parse(await readFile(join(captured,"capture-"+"ef".repeat(12)+"-001.json"),"utf8"));
  assert.equal(timeoutRecord.complete,false);
} finally {
  await rm(captured,{recursive:true,force:true});
}
console.log("PASS: private raw capture and original-quote offline replay; headers redacted, tampering rejected, timeout attempted once");

if (process.argv.includes("--write-fixture")) {
  for (const [name,value] of Object.entries({manifest, buyer:buyer.pub, bundle, tampered, authorization})) {
    await writeFile(new URL("./fixtures/studio-" + name + ".json", import.meta.url), JSON.stringify(value, null, 2) + "\n");
  }
}
console.log("PASS: studio reconciliation plus 21 negative assertions and GET-counter regressions, with guarded dispatch counts and private mismatch evidence");
