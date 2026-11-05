# SafeRouter Receipt Desk

Teams buying AI APIs need to reconcile individual charges against approved prices. Receipt Desk joins a pre-signed quote to a signed usage receipt, then checks the bill locally in the browser.

Open the [published verifier](https://2-2-409-open.tapekit.org/v1/index.html) and import `release/receipt.json` and `release/buyer-public.json`. The verifier checks the buyer authorization and issuer signature, recomputes the charge with integer arithmetic, and shows the requested model, actual response model and generation outcome. Receipt import runs locally.

The real studio example has 37 input tokens and 8 output tokens. All eight output tokens were reported as reasoning tokens, with `finish_reason=length`. The charge is 4,452 nano-USD, or $0.000004452 at the approved rates. Generation ended at its output limit. The signed receipt keeps that outcome visible alongside billing agreement.

The quote uses requested and billed model `deepseek-v4-flash` on line C. Its response reports `deepseek-v4.1-flash`. The verifier permits this exact CM/C alias pair and rejects unknown returned names. Buyer and issuer use P-256 application signatures. Usage, customer debit and outcome are gateway-derived issuer attestations.

The release is stored on X Layer 196, processor 409, circuit 2, in container `0xde9a54ecaf32e6406fba0fcd78153ddc6777a63b`. The canonical address is `tape://2.2.409.tape/v1/index.html`. For this browser demonstration, the HTTPS compatibility gateway reads and verifies the chain content in server mode. The browser verifies the imported receipt locally. A separate script compares the publication byte for byte through independent reads from OKX and dRPC. Opening the compatibility URL depends on gateway availability.

- Versioned path `v1/index.html`
- Release length 12,844 bytes
- SHA-256 `c8582d26be5ec94aa9a9532d5039d931a7ad03db6d0e29396e2f2315d2ed4ab4`
- [Publication transaction](https://www.oklink.com/xlayer/tx/0x2284935c743956cfb291e2a7c97dcb64508c0cd04df1ca1836303ce2083d1831)
- [Source](https://github.com/sumplus-real/saferouter-receipt-desk/tree/6596cee9100dd6f3ef5762fd46b37cfaf42d6928)

To check the sample from the source directory, run `node studio.mjs verify release/manifest.json release/receipt.json release/buyer-public.json`. `node self-check.mjs` and `node studio-check.mjs` exercise valid receipts and negative controls, including altered usage, returned model and finish reason.

Existing work includes the SafeRouter API gateway and Model Desk's pre-call model selection. This project adds the linked quote/receipt workflow, charge reconciliation, signed generation-outcome fields and the versioned TapeOut verifier delivery.

The name was activated for three 30-day periods with zero transaction value and no automatic renewal. Total mint, tapeout, open, publication and activation spend was 0.082034961523748076 OKB, including gas. The observed standard service-worker URL stalled in both tested browsers; the linked compatibility URL succeeded. See `evidence/standard-gateway-risk.txt` and `evidence/publication-acceptance-activated.json`.

Independent read-only acceptance requires Python 3, Foundry `cast` and `curl`:

```sh
python3 publication-check.py
node wallet-check.mjs
python3 verify-publication.py --tx 0x2284935c743956cfb291e2a7c97dcb64508c0cd04df1ca1836303ce2083d1831 --extra-tx 0x4d4fc7de62192cdf93835df0725daa6bf6937f01e5a10daac4fc37400efd3f0e --local-file release/index.html --check-gateway
```

`plan-activation.py` is a read-only unsigned-plan generator. It refuses a nonzero monthly fee and returns an already-activated result instead of preparing a repeat activation. `wallet-plan-activate.json` is the historical unsigned regression fixture, not a new instruction to transact. Wallet tests use a fake provider and do not broadcast.
