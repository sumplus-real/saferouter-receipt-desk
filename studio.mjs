import {randomBytes} from "node:crypto";
import {mkdir, open, readFile, stat, writeFile} from "node:fs/promises";
import {dirname, join} from "node:path";
import {pathToFileURL} from "node:url";
import {
  billedNanoUsd, digest, encode, livePolicyFields, outcomeReceiptFields, quoteCharge, quoteFields,
  validateLivePolicy, validateOutcome, validateReturnedModel, verify, verifyLiveQuote
} from "./verify.mjs";

const ROUTER = "https://router.sumplus.xyz";
const seconds = () => Math.floor(Date.now() / 1000);
const order = (object, names) => names.map(name => object[name]);
const requireThat = (condition, reason) => { if (!condition) throw new Error(reason); };
const isCount = value => Number.isSafeInteger(value) && value >= 0;
const ecdsa = {name:"ECDSA", namedCurve:"P-256"};
const sign = async (key, bytes) => Buffer.from(await crypto.subtle.sign(
  {name:"ECDSA", hash:"SHA-256"}, key, bytes)).toString("hex");
const json = async path => JSON.parse(await readFile(path, "utf8"));
const createJson = (path, value) => writeFile(path, JSON.stringify(value, null, 2) + "\n", {flag:"wx", mode:0o600});

async function privateFile(path, encoding = "utf8") {
  const mode = (await stat(path)).mode;
  requireThat((mode & 0o077) === 0, "Private file must be accessible only to its owner");
  return readFile(path, encoding);
}

function publicPart({kty, crv, x, y}) {
  return {kty, crv, x, y};
}

async function privateKey(jwk, publicKey) {
  requireThat(JSON.stringify(publicPart(jwk)) === JSON.stringify(publicPart(publicKey)),
    "Private signer does not match public key");
  return crypto.subtle.importKey("jwk", jwk, ecdsa, false, ["sign"]);
}

export async function makeAuthorization(manifest, buyerJwk, maxCharge, expires) {
  const {policy, issuer} = manifest;
  validateLivePolicy(policy);
  const buyer = publicPart(buyerJwk);
  const quote = {
    policyHash:await digest(encode("sumplus-policy-v2", [...order(policy, livePolicyFields), issuer.x, issuer.y])),
    nonce:randomBytes(32).toString("hex"), maxCharge, expires
  };
  const buyerSignature = await sign(await privateKey(buyerJwk, buyer),
    encode("sumplus-quote-v2", order(quote, quoteFields)));
  await verifyLiveQuote(quote, buyerSignature, manifest, buyer);
  return {quote, buyerSignature};
}

export function usageFrom(response, policy) {
  const {usage, model, choices} = response;
  validateReturnedModel(policy, model);
  requireThat(Array.isArray(choices) && choices.length === 1 &&
    typeof choices[0]?.message?.content === "string" && !choices[0].message.tool_calls,
  "Unexpected model or response type");
  const input = usage?.prompt_tokens;
  const output = usage?.completion_tokens;
  requireThat(isCount(input) && input > 0 && isCount(output) && output > 0 && usage.total_tokens === input + output &&
    input <= Number(policy.maxInput) && output <= Number(policy.maxOutput), "Missing or unsupported token usage");
  const explicitCache = [usage.prompt_tokens_details?.cached_tokens, usage.cache_read_input_tokens,
    usage.prompt_cache_hit_tokens].filter(value => value !== undefined);
  requireThat(explicitCache.length > 0 && explicitCache.every(value => value === 0) &&
    (usage.cache_creation_input_tokens === undefined || usage.cache_creation_input_tokens === 0) &&
    (usage.prompt_cache_miss_tokens === undefined || usage.prompt_cache_miss_tokens === input) &&
    [usage.prompt_tokens_details?.audio_tokens, usage.completion_tokens_details?.audio_tokens]
      .every(value => value === undefined || value === 0), "Unsupported or unknown cache or audio usage");
  const reasoning = usage.completion_tokens_details?.reasoning_tokens;
  requireThat(isCount(reasoning), "Missing or unsupported reasoning token usage");
  const finishReason = choices[0].finish_reason;
  validateOutcome(finishReason, String(reasoning), String(output));
  return {input:String(input), output:String(output), returnedModel:model, finishReason, reasoningTokens:String(reasoning)};
}

async function checkStudioKey(request, policy, quote, operatorCapNanoUsd) {
  let allocationCeilingNanoUsd = BigInt(quote.maxCharge);
  if (operatorCapNanoUsd !== undefined) {
    requireThat(typeof operatorCapNanoUsd === "string" && /^[1-9][0-9]{0,6}$/.test(operatorCapNanoUsd) &&
      BigInt(operatorCapNanoUsd) <= 1000000n && BigInt(quote.maxCharge) <= BigInt(operatorCapNanoUsd),
    "Expected an explicit operator cap up to 1000000 nano-USD covering the signed quote");
    requireThat(policy.maxOutput === "8" && BigInt(policy.maxInput) <= 128n,
      "Operator-authorized studio profile requires at most 128 input tokens and exactly 8 maximum output tokens");
    // The UI allocates at least $0.01. This allocation is separate from the authorized one-call quote.
    allocationCeilingNanoUsd = 10000000n;
  }
  const {body:key} = await request("/v1/me/key");
  requireThat(typeof key.id === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(key.id) && key.revoked === false &&
    // Authenticated GETs increment lifetime_requests. Settlement counters identify prior calls.
    isCount(key.lifetime_requests) && key.lifetime_cost_usd === 0 && key.lifetime_prompt_tokens === 0 &&
    key.lifetime_completion_tokens === 0 && key.allowance_spent_usd === 0 &&
    typeof key.remaining_allowance_usd === "number" &&
    key.remaining_allowance_usd > 0 && key.remaining_allowance_usd * 1e9 <= Number(allocationCeilingNanoUsd) &&
    key.remaining_allowance_usd * 1e9 >= Number(quoteCharge(policy, policy.maxInput, policy.maxOutput)),
  "Expected an unbilled studio key with zero token usage and a sufficient allowance within the authorized allocation");
  const {body:before} = await request("/v1/me/activity?limit=3");
  requireThat(Array.isArray(before.data) && before.data.length === 0, "Expected empty studio key activity");

  return key;
}

export async function runStudio({manifest, authorization, buyer, issuerJwk, request, reserve, recordMismatch, operatorCapNanoUsd, now = seconds}) {
  const {quote, buyerSignature} = authorization;
  const quoteHash = await verifyLiveQuote(quote, buyerSignature, manifest, buyer);
  const signer = await privateKey(issuerJwk, manifest.issuer);
  requireThat(Number(quote.expires) > now(), "Quote expired before dispatch");
  const {policy} = manifest;
  const key = await checkStudioKey(request, policy, quote, operatorCapNanoUsd);

  // Claims are durable and intentionally survive errors and process restarts.
  await reserve(key.id, quote.nonce);
  requireThat(Number(quote.expires) > now(), "Quote expired before dispatch");
  let response, callError;
  try { response = await request("/v1/chat/completions", {
    model:policy.model,
    messages:[{role:"user", content:"Reply with the single word OK."}],
    max_tokens:Number(policy.maxOutput), stream:false,
    saferouter:{provider:policy.provider, fallback:false}
  }); } catch (error) { callError = error; }
  const completed = String(now());
  // Preserve post-call billing observations even when the response is malformed or times out.
  const [afterActivity] = await Promise.allSettled([
    request("/v1/me/activity?limit=3"),request("/v1/me/key")
  ]);
  if (callError) throw callError;
  const callId = response.headers.get("x-saferouter-call-id");
  const responseHash = response.headers.get("x-saferouter-response-sha256");
  requireThat(callId && /^[A-Za-z0-9_-]{1,128}$/.test(callId) && responseHash &&
    responseHash === await digest(response.bytes) && !response.headers.has("x-saferouter-fallback-from") &&
    !response.headers.has("x-saferouter-fallback-to"), "SafeRouter response evidence is missing or inconsistent");
  const {input, output, returnedModel, finishReason, reasoningTokens} = usageFrom(response.body, policy);
  requireThat(afterActivity.status === "fulfilled", "Post-call activity could not be read; consult the private capture");
  const {body:after} = afterActivity.value;
  requireThat(Array.isArray(after.data) && after.data.length === 1, "Could not isolate a single billed activity");
  const [row] = after.data;
  requireThat(row.key_id === key.id && row.model === policy.model && row.provider === policy.activityProvider &&
    row.status === "ok" && row.stream === false && (row.attempt === undefined || row.attempt === 1) &&
    row.prompt_tokens === Number(input) && row.completion_tokens === Number(output) && typeof row.cost_usd === "number",
  "Billed activity did not match the controlled call");
  const billedUsd = String(row.cost_usd);
  const charge = quoteCharge(policy, input, output).toString();
  const requestHash = await digest(encode("sumplus-request-v2", [quote.nonce, callId, responseHash]));
  let matched = false;
  try { matched = billedNanoUsd(billedUsd).toString() === charge; } catch { /* Preserve invalid amount as mismatch evidence. */ }
  if (!matched) {
    await recordMismatch?.({quoteHash, requestHash, input, output, billedUsd, quotedChargeNanoUsd:charge});
    throw new Error("SafeRouter billed amount differs from quoted charge; receipt withheld");
  }
  const receipt = {quoteHash, requestHash,
    model:policy.model, input, output, cached:"0", charge, completed, billedUsd, returnedModel, finishReason, reasoningTokens};
  const bundle = {quote, buyerSignature, receipt,
    issuerSignature:await sign(signer, encode("sumplus-receipt-v3", order(receipt, outcomeReceiptFields)))};
  await verify(bundle, manifest, buyer);
  return bundle;
}

async function ensurePrivateJournal(directory) {
  await mkdir(directory,{recursive:true,mode:0o700});
  requireThat(((await stat(directory)).mode & 0o077) === 0,"Journal directory must be private");
}

export function journalTransport(directory, prefix) {
  let sequence = 0;
  requireThat(/^[a-f0-9]{24}$/.test(prefix),"Invalid private capture identifier");
  return async (path, body, send) => {
    await ensurePrivateJournal(directory);
    const stem = "capture-" + prefix + "-" + String(++sequence).padStart(3,"0");
    const metadataPath = join(directory,stem + ".json");
    const metadata = {path,method:body ? "POST" : "GET",started:seconds(),requestBody:body ?? null,complete:false};
    await createJson(metadataPath,metadata);
    const file = await open(join(directory,stem + ".bin"),"wx",0o600);
    try {
      const response = await send();
      metadata.status = response.status;
      const allowedHeaders = ["content-type","x-saferouter-call-id","x-saferouter-response-sha256",
        "x-saferouter-tee-quote-id","x-saferouter-log-index","x-saferouter-fallback-from","x-saferouter-fallback-to"];
      metadata.headers = Object.fromEntries(allowedHeaders.filter(name => response.headers.has(name))
        .map(name => [name,response.headers.get(name)]));
      await writeFile(metadataPath,JSON.stringify(metadata,null,2) + "\n",{mode:0o600});
      const reader = response.body?.getReader();
      const chunks = [];
      if (reader) {
        for (;;) {
          const {value,done} = await reader.read();
          if (done) break;
          await file.writeFile(value);
          chunks.push(value);
        }
      }
      const bytes = new Uint8Array(Buffer.concat(chunks));
      metadata.complete = true;
      metadata.bodySha256 = await digest(bytes);
      return {response,bytes};
    } catch (error) {
      metadata.error = "Transport or private capture failed. No automatic retry was attempted.";
      throw error;
    } finally {
      metadata.finished = seconds();
      await file.close();
      await writeFile(metadataPath,JSON.stringify(metadata,null,2) + "\n",{mode:0o600});
    }
  };
}

function gatewayRequest(key, capture) {
  return async (path, body) => {
    const send = () => fetch(ROUTER + path, {
      method:body ? "POST" : "GET",redirect:"error",signal:AbortSignal.timeout(30000),
      headers:{authorization:"Bearer " + key,...(body && {"content-type":"application/json"})},
      body:body && JSON.stringify(body)
    });
    let raw;
    try {
      if (capture) raw = await capture(path,body,send);
      else {
        const response = await send();
        raw = {response,bytes:new Uint8Array(await response.arrayBuffer())};
      }
    } catch {
      throw new Error("SafeRouter connection or private capture failed; inspect the journal before any follow-up");
    }
    const {response,bytes} = raw;
    requireThat(response.ok,`SafeRouter returned HTTP ${response.status}`);
    let parsed;
    try { parsed = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { throw new Error("SafeRouter response was not JSON; raw bytes are in the private journal"); }
    return {body:parsed,headers:response.headers,bytes};
  };
}

export async function replayStudio(contextPath, issuerJwk) {
  const context = JSON.parse(await privateFile(contextPath));
  const directory = dirname(contextPath);
  requireThat(/^[a-f0-9]{24}$/.test(context.capturePrefix) && isCount(context.started),"Invalid replay context");
  let sequence = 0, recordedNow = context.started;
  const request = async (path, body) => {
    const stem = "capture-" + context.capturePrefix + "-" + String(++sequence).padStart(3,"0");
    const metadata = JSON.parse(await privateFile(join(directory,stem + ".json")));
    requireThat(metadata.path === path && metadata.method === (body ? "POST" : "GET") && metadata.complete === true &&
      metadata.started >= context.started && metadata.finished >= metadata.started &&
      JSON.stringify(metadata.requestBody) === JSON.stringify(body ?? null),"Captured request does not match this pre-signed studio authorization");
    const bytes = new Uint8Array(await privateFile(join(directory,stem + ".bin"),null));
    requireThat(await digest(bytes) === metadata.bodySha256,"Private capture bytes changed");
    if (body) recordedNow = metadata.finished;
    requireThat(metadata.status >= 200 && metadata.status < 300,"Captured SafeRouter call was unsuccessful");
    return {body:JSON.parse(new TextDecoder().decode(bytes)),headers:new Headers(metadata.headers),bytes};
  };
  return runStudio({...context,issuerJwk,request,reserve:async () => {},now:() => recordedNow});
}

export function reserveStudio(directory) {
  return async (keyId, nonce) => {
    await ensurePrivateJournal(directory);
    try {
      const keyHash = await digest(encode("sumplus-studio-key-v2", [keyId]));
      await createJson(join(directory, "key-" + keyHash), {started:seconds()});
      await createJson(join(directory, "nonce-" + nonce), {started:seconds()});
    } catch (error) {
      if (error.code === "EEXIST") throw new Error("Studio key or quote already consumed in this journal");
      throw error;
    }
  };
}

async function loadGatewayKey(apiKeyPath, capture) {
  const key = (await privateFile(apiKeyPath)).trim();
  requireThat(/^sk-sr-[A-Za-z0-9_-]+$/.test(key), "Expected a SafeRouter API key");
  return gatewayRequest(key,capture);
}

async function cli() {
  const [command, ...args] = process.argv.slice(2);
  let operatorCapNanoUsd;
  const operatorIndex = args.indexOf("--operator-cap-nano-usd");
  if (operatorIndex !== -1) {
    requireThat(operatorIndex < args.length-1 && args.lastIndexOf("--operator-cap-nano-usd") === operatorIndex,
      "Provide exactly one --operator-cap-nano-usd value");
    operatorCapNanoUsd = args[operatorIndex+1];
    args.splice(operatorIndex,2);
    requireThat(command === "preflight" || command === "run", "Operator cap is supported for preflight and run");
  }
  if (command === "keygen" && args.length === 2) {
    const [privatePath, publicPath] = args;
    const pair = await crypto.subtle.generateKey(ecdsa, true, ["sign","verify"]);
    await createJson(privatePath, await crypto.subtle.exportKey("jwk", pair.privateKey));
    await createJson(publicPath, publicPart(await crypto.subtle.exportKey("jwk", pair.publicKey)));
    return;
  }
  if (command === "quote" && args.length === 4) {
    const [manifestPath, buyerPrivatePath, cap, output] = args;
    const auth = await makeAuthorization(await json(manifestPath), JSON.parse(await privateFile(buyerPrivatePath)),
      cap, String(seconds() + 300));
    await createJson(output, auth);
    return;
  }
  if (command === "verify" && args.length === 3) {
    const [manifestPath, bundlePath, buyerPath] = args;
    console.log(JSON.stringify(await verify(await json(bundlePath), await json(manifestPath), await json(buyerPath)), null, 2));
    return;
  }
  if (command === "preflight" && args.length === 4) {
    const [manifestPath, authPath, buyerPath, apiKeyPath] = args;
    const manifest = await json(manifestPath);
    requireThat(!manifest.policy.version.startsWith("mock-"), "A mock policy cannot authorize a live call");
    const {quote, buyerSignature} = await json(authPath);
    await verifyLiveQuote(quote, buyerSignature, manifest, await json(buyerPath));
    requireThat(Number(quote.expires) > seconds(), "Quote expired before preflight");
    const key = await checkStudioKey(await loadGatewayKey(apiKeyPath), manifest.policy, quote, operatorCapNanoUsd);
    console.log(JSON.stringify({mode:"read-only",billableCallsDispatched:0,
      lifetimeRequests:key.lifetime_requests,remainingAllowanceUsd:key.remaining_allowance_usd,
      lifetimeCostUsd:key.lifetime_cost_usd,lifetimeInputTokens:key.lifetime_prompt_tokens,
      lifetimeOutputTokens:key.lifetime_completion_tokens,allowanceSpentUsd:key.allowance_spent_usd,
      activityCount:0,requestProfile:manifest.policy.requestProfile,maxInputTokens:manifest.policy.maxInput,
      maxOutputTokens:manifest.policy.maxOutput,
      worstCaseQuotedNanoUsd:String(quoteCharge(manifest.policy,manifest.policy.maxInput,manifest.policy.maxOutput)),
      signedQuoteCapNanoUsd:quote.maxCharge,operatorCapNanoUsd:operatorCapNanoUsd ?? null,
      limitScope:"One-call dispatch authorization and receipt validation. Gateway settlement can cross the key allocation."
    },null,2));
    return;
  }
  if (command === "replay" && args.length === 3) {
    const [contextPath,issuerPath,output] = args;
    const bundle = await replayStudio(contextPath,JSON.parse(await privateFile(issuerPath)));
    await createJson(output,bundle);
    console.log("Signed receipt replayed from the original pre-signed authorization and private capture. Network calls: 0.");
    return;
  }
  if (command === "run" && args.length === 8 && args.at(-1) === "--execute-live") {
    const [manifestPath, authPath, buyerPath, issuerPath, apiKeyPath, journal, output] = args;
    const manifest = await json(manifestPath);
    requireThat(!manifest.policy.version.startsWith("mock-"), "A mock policy cannot authorize a live call");
    await ensurePrivateJournal(journal);
    const capturePrefix = randomBytes(12).toString("hex");
    const context = {manifest,authorization:await json(authPath),buyer:await json(buyerPath),
      operatorCapNanoUsd,capturePrefix,started:seconds()};
    await createJson(join(journal,"context-" + capturePrefix + ".json"),context);
    const request = await loadGatewayKey(apiKeyPath,journalTransport(journal,capturePrefix));
    // Claim the output before any network activity so accidental overwrites fail early.
    await createJson(output, {status:"pending"});
    const bundle = await runStudio({...context, issuerJwk:JSON.parse(await privateFile(issuerPath)),
      request, reserve:reserveStudio(journal), operatorCapNanoUsd,
      recordMismatch:evidence => createJson(join(journal, "mismatch-" + evidence.quoteHash + ".json"), evidence)});
    await writeFile(output, JSON.stringify(bundle, null, 2) + "\n", {mode:0o600});
    console.log("Signed reconciled receipt; output contains no prompt, response, account identifier or upstream cost.");
    return;
  }
  throw new Error("Usage: studio.mjs keygen PRIVATE PUBLIC | quote MANIFEST BUYER_PRIVATE CAP_NANO_USD AUTH_OUTPUT | replay PRIVATE_CONTEXT ISSUER_PRIVATE BUNDLE_OUTPUT | verify MANIFEST BUNDLE BUYER_PUBLIC | preflight MANIFEST AUTH BUYER_PUBLIC API_KEY_FILE [--operator-cap-nano-usd CAP] | run MANIFEST AUTH BUYER_PUBLIC ISSUER_PRIVATE API_KEY_FILE JOURNAL BUNDLE_OUTPUT [--operator-cap-nano-usd CAP] --execute-live");
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  cli().catch(error => { console.error(error.message); process.exitCode = 1; });
}
