import {validateLivePolicy} from "./verify.mjs";
import {readFile, writeFile} from "node:fs/promises";

const path = process.argv[2];
if (!path) throw new Error("Provide a trusted release manifest JSON");
const manifest = JSON.parse(await readFile(path, "utf8"));
if (!manifest.policy || !manifest.issuer) throw new Error("Missing release policy or issuer");
if (manifest.policy.requestProfile) validateLivePolicy(manifest.policy);
const {kty, crv, x, y} = manifest.issuer;
const issuer = {kty, crv, x, y};
if (Object.hasOwn(manifest.issuer, "d")) throw new Error("Do not provide a private issuer key to the build");
await crypto.subtle.importKey("jwk", issuer, {name:"ECDSA", namedCurve:"P-256"}, false, ["verify"]);
const safeManifest = JSON.stringify({policy:manifest.policy, issuer}).replaceAll("<", "\\u003c");
const code = (await readFile(new URL("./verify.mjs", import.meta.url), "utf8")).replace(/^export /gm, "");
const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeRouter Receipt Desk</title>
<style>
:root{color-scheme:dark;background:#0a1019;color:#e3edf9;font:16px system-ui}main{max-width:680px;margin:9vh auto;padding:24px}
header{color:#73e3d1;font-size:.85rem;letter-spacing:.12em}h1{font-size:clamp(2rem,7vw,4rem);line-height:1.05;margin:.4em 0}
p{color:#adbed2;line-height:1.6}label{display:block;margin:1.2rem 0}.panel{border:1px solid #33465b;border-radius:14px;padding:24px}
button{padding:.7rem 1.2rem;color:#0a1019;background:#73e3d1;border:0;border-radius:6px;font-weight:700}
output{display:block;margin-top:1rem;white-space:pre-wrap;overflow-wrap:anywhere}input{display:block;margin-top:.5rem;max-width:100%}
</style></head><body><main><header>SUMPLUS / SAFEROUTER</header><h1>Receipt Desk</h1>
<p>Check a signed AI receipt against the rate card and budget approved before the call. Files stay in this browser.</p>
<div class="panel"><form><label>Signed receipt bundle<input id="bundle" type="file" accept=".json" required></label>
<label>Buyer public key from your authorization record<input id="buyer" type="file" accept=".json" required></label>
<button>Verify receipt</button><output id="status" aria-live="polite"></output></form></div>
<p>The issuer attests usage and the recorded customer charge with an application signature. The buyer signs the quote with a separate application key. Verification runs locally and makes no payment.</p>
</main><script type="module">
${code}
const manifest = ${safeManifest};
const status = document.querySelector("#status");
if (manifest.policy.version === "fixture" || manifest.policy.version.startsWith("mock-")) {
  document.querySelector("header").textContent += " / SYNTHETIC DEMO";
}
async function load(id) {
  const file = document.getElementById(id).files[0];
  if (!file || file.size > 65536) throw new Error("Expected a JSON file under 64 KiB");
  return JSON.parse(await file.text());
}
document.querySelector("form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.target.querySelector("button");
  button.disabled = true;
  status.textContent = "Checking…";
  try {
    const result = await verify(await load("bundle"), manifest, await load("buyer"));
    status.textContent = "Billing verified under " + manifest.policy.version + "\\nInput tokens: " + result.input +
      "\\nOutput tokens: " + result.output + "\\nQuoted charge: " + result.chargeNanoUsd + " nano-USD";
    if (result.billedUsd !== undefined) {
      status.textContent += "\\nSafeRouter recorded customer charge: $" + result.billedUsd +
        "\\nAuthorized limit: " + result.maxChargeNanoUsd + " nano-USD" +
        "\\nRequest commitment: " + result.requestHash;
    }
    if (result.returnedModel !== undefined) {
      status.textContent += "\\nRequested and billed model: " + result.requestedModel +
        "\\nReturned model: " + result.returnedModel + "\\nFinish reason: " + result.finishReason +
        "\\nReasoning tokens: " + result.reasoningTokens + "\\nOther output tokens: " + result.nonReasoningTokens;
      if (result.finishReason === "length") status.textContent += "\\nGeneration ended at the output limit. This receipt verifies billing.";
    }
  } catch (error) {
    status.textContent = "Could not verify: " + error.message;
  } finally {
    button.disabled = false;
  }
});
</script></body></html>`;
if (Buffer.byteLength(html) > 24000) throw new Error("TapeOut single chunk limit exceeded");
const output = process.argv[3];
await writeFile(output || new URL("./index.html", import.meta.url), html, output ? {flag:"wx"} : {});
console.log("Built", Buffer.byteLength(html), "bytes");
