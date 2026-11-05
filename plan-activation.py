"""Prepare a zero-value, unsigned name activation within the existing 0.09 OKB budget."""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("publication_reader", Path(__file__).with_name("verify-publication.py"))
chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain)
BINDING_IMPLEMENTATION = "0x0000000000000000000000005ebf29b80789e548907c707530c3c7607c4347df"
NAME = "2.2.409.tape"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication-tx", required=True)
    parser.add_argument("--local-file", type=Path, required=True)
    parser.add_argument("--months", type=int, default=1, help="Activation months, 1–120. Default is one 30-day period.")
    args = parser.parse_args()
    chain.require(1 <= args.months <= 120, "Activation term must be 1–120 months")
    chain.require(chain.re.fullmatch(r"0x[0-9a-f]{64}", args.publication_tx), "Expected publication transaction hash")
    local = args.local_file.read_bytes()
    chain.require(len(local) == 12844 and chain.hashlib.sha256(local).hexdigest() == chain.EXPECTED_SHA,
                  "Local release differs from the frozen publication")
    chain.require(chain.agree("eth_chainId", []) == "0xc4", "Wrong chain")
    pinned = min(int(number, 16) for number in chain.pair("eth_blockNumber", []))-8
    block = hex(pinned)

    def call(target, signature, *values):
        return chain.agree("eth_call", [{"to": target, "data": chain.calldata(signature, *values)}, block])

    chain.require("0x"+call(chain.FACTORY, "cpuAt(uint256)", 409)[-40:] == chain.PROCESSOR,
                  "Factory processor mapping changed")
    chain.require("0x"+call(chain.PROCESSOR, "ownerOf(uint256)", 2)[-40:] == chain.OWNER and
                  "0x"+call(chain.CONTAINER, "owner()")[-40:] == chain.OWNER, "Studio NFT/container ownership changed")
    chain.require("0x"+call(chain.OPENER, "accountOf(address,uint256)", chain.PROCESSOR, 2)[-40:] == chain.CONTAINER and
                  int(call(chain.REGISTRY, "isOpenedContainer(address)", chain.CONTAINER), 16) == 1,
                  "Circuit/container mapping or opened status differs")
    chain.require(chain.agree("eth_getStorageAt", [chain.BINDING, chain.SLOT, block]) == BINDING_IMPLEMENTATION,
                  "Unexpected activation contract implementation")
    chain.require(chain.agree("eth_getStorageAt", [chain.REGISTRY, chain.SLOT, block]) == chain.IMPLEMENTATION,
                  "Unexpected site registry implementation")
    monthly_fee = int(call(chain.BINDING, "monthlyFee()"), 16)
    chain.require(monthly_fee == 0, "Activation is no longer free; no paid transaction will be prepared")
    name_live = int(call(chain.BINDING, "isLive(string,address)", NAME, chain.CONTAINER), 16) == 1
    container_live = int(call(chain.BINDING, "isContainerLive(address)", chain.CONTAINER), 16) == 1
    if name_live or container_live:
        print(json.dumps(dict(alreadyActivated=True, name=NAME, container=chain.CONTAINER, walletStep=None), indent=2))
        return
    info = call(chain.REGISTRY, "fileInfo(address,string)", chain.CONTAINER, chain.PATH)[2:]
    chain.require(len(info) >= 320 and int(info[:64], 16) == 12844 and info[128:192] == chain.EXPECTED_SHA and
                  int(info[256:320], 16) == 1, "Expected release is not yet published")
    ledger = []
    for nonce, tx_hash in enumerate([*chain.ACQUISITION, args.publication_tx]):
        tx, _, cost = chain.confirmed_transaction(tx_hash, pinned)
        chain.require(int(tx["nonce"], 16) == nonce, "Unexpected prior wallet nonce sequence")
        ledger.append(cost)
        if nonce == 3:
            expected = chain.calldata("putFile(address,string,string,bytes32,bytes)", chain.CONTAINER, chain.PATH,
                                      "text/html", "0x"+chain.EXPECTED_SHA, "0x"+local.hex())
            chain.require(tx["to"] == chain.REGISTRY and tx["input"] == expected and int(tx["value"], 16) == 0,
                          "Confirmed publication differs from the frozen release")
    spent = sum(int(item["totalWei"]) for item in ledger)
    balance = int(chain.agree("eth_getBalance", [chain.OWNER, block]), 16)
    chain.require(spent <= chain.BUDGET and balance+spent == chain.BUDGET,
                  "Prior actual spend and wallet balance do not reconcile with 0.09 OKB")
    latest = chain.agree("eth_getTransactionCount", [chain.OWNER, "latest"])
    pending = chain.agree("eth_getTransactionCount", [chain.OWNER, "pending"])
    chain.require(int(latest, 16) == int(pending, 16) == 4, "Wallet nonce changed or a transaction remains pending")
    tx = {"from": chain.OWNER, "to": chain.BINDING, "value": "0x0",
          "data": chain.calldata("bind(string,address,uint256)", NAME, chain.CONTAINER, args.months)}
    estimates = chain.pair("eth_estimateGas", [tx])
    gas = (max(int(value, 16) for value in estimates)*120+99)//100
    price = max(int(value, 16) for value in chain.pair("eth_gasPrice", []))
    ceiling = gas*price
    chain.require(spent+ceiling <= chain.BUDGET and balance >= ceiling,
                  "Activation gas would exceed the existing 0.09 OKB budget")
    tx.update(chainId="0xc4", gas=hex(gas), gasPrice=hex(price), nonce=latest)
    print(json.dumps(dict(chainId=196, block=pinned, rpcProviders=list(chain.RPCS), processorIndex=409,
        processor=chain.PROCESSOR, transistors="0x5d7e99c4d1b71f4d24c9d53f41aed8196064a61f",
        resolvedCircuit=dict(id="2", container=chain.CONTAINER, opened=True), ledger=ledger,
        binding=dict(address=chain.BINDING, implementation=BINDING_IMPLEMENTATION, name=NAME,
                     container=chain.CONTAINER, months=args.months, termDays=args.months*30, autoRenew=False, monthlyFeeWei="0", nameLive=False, containerLive=False,
                     abiSource="https://github.com/TapeOutProtocol/TapeKit/blob/main/SPEC.md#b6-payment-contract-domainbinding-uups-proxy"),
        walletStep=dict(stage="activate", transaction=tx, budgetWei=str(chain.BUDGET), previousActualSpendWei=str(spent),
            futureReservedValueWei="0", estimatedGas=[str(int(value, 16)) for value in estimates],
            maxGasFeeWei=str(ceiling), maxTotalWithFutureValuesWei=str(spent+ceiling), walletBalanceWei=str(balance),
            snapshotBlock=pinned),
        notes=["Zero native protocol payment; gas is still spent.",
               f"Fixed {args.months*30}-day activation term. No automatic renewal. Renew manually before expiry if still needed.",
               "Monthly fee and active status are checked again by the wallet page immediately before a user signing request.",
               "Publication is already confirmed and is never resent by this plan."]), indent=2))


if __name__ == "__main__":
    main()
