const encoder = new TextEncoder();
const UINT = /^(0|[1-9][0-9]{0,23})$/;
const HEX = /^[a-f0-9]{64}$/;

function check(ok, message) {
  if (!ok) throw new Error(message);
}

function uint(value) {
  check(typeof value === "string" && UINT.test(value), "Invalid integer field");
  return BigInt(value);
}

function fields(object, names) {
  check(object && Object.keys(object).length === names.length &&
    names.every(name => Object.hasOwn(object, name)), "Unexpected schema");
  return names.map(name => object[name]);
}

export function encode(domain, values) {
  return encoder.encode(JSON.stringify([domain, ...values]));
}

export async function digest(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    byte => byte.toString(16).padStart(2, "0")).join("");
}

export const policyFields = ["chain", "container", "version", "model", "input", "output"];
export const quoteFields = ["policyHash", "nonce", "maxCharge", "expires"];
export const receiptFields = ["quoteHash", "requestHash", "model", "input", "output", "cached", "charge", "completed"];

async function validSignature(publicKey, bytes, signature) {
  check(typeof signature === "string" && /^[a-f0-9]{128}$/.test(signature), "Invalid signature encoding");
  const key = await crypto.subtle.importKey("jwk", publicKey, {name:"ECDSA", namedCurve:"P-256"}, false, ["verify"]);
  return crypto.subtle.verify({name:"ECDSA", hash:"SHA-256"}, key,
    Uint8Array.from(signature.match(/../g), byte => parseInt(byte, 16)), bytes);
}

export async function verify(bundle, manifest, expectedBuyer) {
  if (Object.hasOwn(manifest.policy, "requestProfile")) return verifyLive(bundle, manifest, expectedBuyer);
  const {policy, issuer} = manifest;
  const {quote, receipt, buyerSignature, issuerSignature} = bundle;
  check(policy.chain === "196" && /^0x[a-f0-9]{40}$/.test(policy.container), "Wrong deployment");
  const policyHash = await digest(encode("sumplus-policy-v1", [...fields(policy, policyFields), issuer.x, issuer.y]));
  check(policyHash === quote.policyHash, "Unrecognized policy");
  check(HEX.test(quote.nonce) && HEX.test(receipt.requestHash), "Invalid identifiers");
  const quoteBytes = encode("sumplus-quote-v1", fields(quote, quoteFields));
  check(await validSignature(expectedBuyer, quoteBytes, buyerSignature), "Invalid buyer signature");
  const quoteHash = await digest(encode("sumplus-bound-quote-v1", [await digest(quoteBytes), expectedBuyer.x, expectedBuyer.y]));
  check(quoteHash === receipt.quoteHash, "Receipt belongs to another quote");
  check(await validSignature(issuer, encode("sumplus-receipt-v1", fields(receipt, receiptFields)), issuerSignature),
    "Invalid issuer signature");
  check(receipt.model === policy.model && receipt.cached === "0", "Unsupported model or cache usage");
  check(uint(receipt.completed) <= uint(quote.expires), "Quote expired before completion");
  const input = uint(receipt.input), output = uint(receipt.output);
  // Rates in nano-USD per million tokens. Round once, up, to nano-USD.
  const charge = (input * uint(policy.input) + output * uint(policy.output) + 999999n) / 1000000n;
  check(uint(receipt.charge) === charge, "Charge mismatch");
  check(charge <= uint(quote.maxCharge), "Charge exceeds budget");
  return {input: input.toString(), output: output.toString(), chargeNanoUsd: charge.toString()};
}

export const livePolicyFields = [...policyFields, "provider", "activityProvider", "maxInput", "maxOutput", "requestProfile"];
export const liveReceiptFields = [...receiptFields, "billedUsd"];
export const outcomeReceiptFields = [...liveReceiptFields, "returnedModel", "finishReason", "reasoningTokens"];

// The catalog identifies the requested id as a legacy V4.1 alias. The CM wire
// response confirms this exact returned label. Scope the exception to that line.
export function validateReturnedModel(policy, returnedModel) {
  const catalogAlias = policy.model === "deepseek-v4-flash" && policy.provider === "cm" &&
    policy.activityProvider === "C" && returnedModel === "deepseek-v4.1-flash";
  check(returnedModel === policy.model || catalogAlias, "Unsupported returned model alias");
}

export function validateOutcome(finishReason, reasoningTokens, output) {
  check(finishReason === "stop" || finishReason === "length", "Unsupported finish reason");
  check(uint(reasoningTokens) <= uint(output), "Reasoning tokens exceed output usage");
}
export const LIVE_PROFILE = "studio-text-v1";

export function quoteCharge(policy, input, output) {
  return (uint(input) * uint(policy.input) + uint(output) * uint(policy.output) + 999999n) / 1000000n;
}

export function validateLivePolicy(policy) {
  fields(policy, livePolicyFields);
  check(policy.chain === "196" && /^0x[a-f0-9]{40}$/.test(policy.container), "Wrong deployment");
  for (const name of ["version", "model", "provider"]) {
    check(typeof policy[name] === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}$/.test(policy[name]), "Invalid " + name);
  }
  check(typeof policy.activityProvider === "string" && /^[A-Za-z0-9._:/\[\]-]{1,80}$/.test(policy.activityProvider), "Invalid activity provider");
  check(policy.version !== "fixture" && policy.requestProfile === LIVE_PROFILE, "Unsupported call profile");
  check(uint(policy.maxInput) > 0n && uint(policy.maxInput) <= 4096n &&
    uint(policy.maxOutput) > 0n && uint(policy.maxOutput) <= 32n, "Unsupported token ceiling");
  check(uint(policy.input) > 0n && uint(policy.output) > 0n, "Expected positive rates");
}

export async function verifyLiveQuote(quote, signature, manifest, buyer) {
  const {policy, issuer} = manifest;
  validateLivePolicy(policy);
  const policyHash = await digest(encode("sumplus-policy-v2", [...fields(policy, livePolicyFields), issuer.x, issuer.y]));
  check(policyHash === quote.policyHash, "Unrecognized policy");
  check(typeof quote.nonce === "string" && HEX.test(quote.nonce), "Invalid quote nonce");
  const bytes = encode("sumplus-quote-v2", fields(quote, quoteFields));
  check(await validSignature(buyer, bytes, signature), "Invalid buyer signature");
  check(quoteCharge(policy, policy.maxInput, policy.maxOutput) <= uint(quote.maxCharge), "Token ceilings exceed quote budget");
  check(uint(quote.maxCharge) > 0n && uint(quote.maxCharge) <= 1000000n, "Quote exceeds studio limit");
  uint(quote.expires);
  return digest(encode("sumplus-bound-quote-v2", [await digest(bytes), buyer.x, buyer.y]));
}

export function billedNanoUsd(billedUsd) {
  check(typeof billedUsd === "string" && /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:e[-+]?[0-9]+)?$/.test(billedUsd), "Invalid billed USD");
  const billed = Number(billedUsd);
  check(Number.isFinite(billed) && billed > 0 && billed <= 0.001, "Invalid billed USD");
  // SafeRouter serializes an f64. Snap machine error at integer boundaries, then round up.
  const nanos = billed * 1e9;
  const nearest = Math.round(nanos);
  return BigInt(Math.abs(nanos - nearest) <= Math.max(1, nanos) * Number.EPSILON * 8 ? nearest : Math.ceil(nanos));
}

export async function verifyLive(bundle, manifest, buyer) {
  const {quote, receipt, buyerSignature, issuerSignature} = bundle;
  const quoteHash = await verifyLiveQuote(quote, buyerSignature, manifest, buyer);
  check(quoteHash === receipt.quoteHash, "Receipt belongs to another quote");
  const hasOutcome = Object.hasOwn(receipt, "returnedModel");
  const domain = hasOutcome ? "sumplus-receipt-v3" : "sumplus-receipt-v2";
  const signedFields = hasOutcome ? outcomeReceiptFields : liveReceiptFields;
  check(await validSignature(manifest.issuer, encode(domain, fields(receipt, signedFields)), issuerSignature),
    "Invalid issuer signature");
  check(typeof receipt.requestHash === "string" && HEX.test(receipt.requestHash), "Invalid request hash");
  const {policy} = manifest;
  check(receipt.model === policy.model && receipt.cached === "0", "Unsupported model or cache usage");
  check(uint(receipt.completed) <= uint(quote.expires), "Quote expired before completion");
  check(uint(receipt.input) <= uint(policy.maxInput) && uint(receipt.output) <= uint(policy.maxOutput), "Usage exceeded signed token ceilings");
  const charge = quoteCharge(policy, receipt.input, receipt.output);
  check(uint(receipt.charge) === charge, "Charge mismatch");
  check(charge <= uint(quote.maxCharge), "Charge exceeds budget");
  check(billedNanoUsd(receipt.billedUsd) === charge, "SafeRouter billed amount differs from quoted charge");
  const result = {input:receipt.input, output:receipt.output, chargeNanoUsd:receipt.charge, billedUsd:receipt.billedUsd,
    maxChargeNanoUsd:quote.maxCharge, requestHash:receipt.requestHash};
  if (hasOutcome) {
    validateReturnedModel(policy, receipt.returnedModel);
    validateOutcome(receipt.finishReason, receipt.reasoningTokens, receipt.output);
    Object.assign(result, {requestedModel:receipt.model, returnedModel:receipt.returnedModel,
      finishReason:receipt.finishReason, reasoningTokens:receipt.reasoningTokens,
      nonReasoningTokens:(uint(receipt.output)-uint(receipt.reasoningTokens)).toString()});
  }
  return result;
}
