"""Read-only X Layer container plan. Emits unsigned templates, never signs or broadcasts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

PRIMARY_RPC = "https://rpc.xlayer.tech"
SECOND_RPCS = ("https://xlayerrpc.okx.com", "https://xlayer.drpc.org")
RPCS = (PRIMARY_RPC, SECOND_RPCS[0])
FACTORY = "0x1f09daefa827f02cbb40967cc91b259763760761"
OPENER = "0x536add8f30f03b69f6fbf29d425a816a0dc50106"
REGISTRY = "0xd6efb7adcc9c83dc4924ad56f6a8e4e969b9adb6"
IMPLEMENTATION = "0x000000000000000000000000a85c4143d1d4a77f54b8e4ecc9e6d1418afea45f"
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
GENESIS = "0x839bdd6fa7a66416a609a735e11de5411b98574e"
ZERO = "0x" + "0" * 40
NETLIST = "0x00000002000003"
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")


def cast(*args):
    return subprocess.check_output(["cast", *map(str, args)], text=True, timeout=10).strip()


def rpc(url, method, params):
    payload = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params))
    response = subprocess.check_output(["curl", "-fsS", "--max-time", "15", "--retry", "1",
        "--retry-delay", "1", "-H", "Content-Type: application/json", "--data-binary", payload, url],
        text=True, timeout=35)
    result = json.loads(response)
    if "result" not in result:
        raise ValueError(f"RPC rejected read-only {method}: {result.get('error')}")
    return result["result"]


def reads(method, params):
    with ThreadPoolExecutor(2) as pool:
        return list(pool.map(lambda url: rpc(url, method, params), RPCS))


def agree(method, params):
    first, second = reads(method, params)
    # rpc.xlayer.tech adds blockTimestamp to transaction objects; dRPC omits it.
    # Canonical block identity is checked separately. Compare every other field.
    if method == "eth_getTransactionByHash" and isinstance(first, dict) and isinstance(second, dict):
        first_fields = {key: value for key, value in first.items() if key != "blockTimestamp"}
        second_fields = {key: value for key, value in second.items() if key != "blockTimestamp"}
    else:
        first_fields, second_fields = first, second
    if first_fields != second_fields:
        raise ValueError(f"RPC disagreement for {method}")
    return first


def okb(wei):
    return format(Decimal(wei) / Decimal(10**18), "f")


def receipt_id(receipt, transaction, processor, wallet, expected_value):
    """Require consistent ERC-721 and TapeOut events from the actual successful transaction."""
    if receipt.get("status") != "0x1" or not receipt.get("blockHash"):
        raise ValueError("Tapeout receipt must be successful and mined")
    if (receipt.get("transactionHash") != transaction.get("hash") or
            receipt.get("blockHash") != transaction.get("blockHash") or
            transaction.get("to", "").lower() != processor or
            transaction.get("from", "").lower() != wallet or
            int(transaction.get("value", "0x0"), 16) != expected_value or
            transaction.get("input", "").lower() != cast("calldata", "tapeout(bytes,uint32,uint32)", NETLIST, "2", "1")):
        raise ValueError("Receipt transaction does not match the requested one-NAND tapeout")
    transfer = cast("keccak", "Transfer(address,address,uint256)")
    taped = cast("keccak", "TapedOut(uint256,address,uint32,uint32)")
    address_topic = "0x" + wallet[2:].rjust(64, "0")
    zero_topic = "0x" + "0" * 64
    transfers, taped_ids = [], []
    for log in receipt.get("logs", []):
        if log.get("address", "").lower() != processor or log.get("removed", False):
            continue
        topics = [t.lower() for t in log.get("topics", [])]
        data = log.get("data", "").lower()
        if len(topics) == 4 and topics[:3] == [transfer, zero_topic, address_topic] and data == "0x":
            transfers.append(int(topics[3], 16))
        if len(topics) == 3 and topics[0] == taped and topics[2] == address_topic:
            if data == "0x" + format(1, "064x") + format(0, "064x"):
                taped_ids.append(int(topics[1], 16))
    if len(transfers) != 1 or transfers != taped_ids or transfers[0] <= 0:
        raise ValueError("Expected one matching ERC-721 mint and TapedOut event for this author")
    return transfers[0]


def transaction_cost(receipt, transaction):
    if receipt.get("effectiveGasPrice") is None:
        raise ValueError("Receipt does not expose effective gas price")
    extra = int(receipt.get("l1Fee", "0x0"), 16)
    return int(transaction["value"], 16) + int(receipt["gasUsed"], 16) * int(receipt["effectiveGasPrice"], 16) + extra


def confirmed_transaction(tx_hash, wallet, target, block):
    receipt = agree("eth_getTransactionReceipt", [tx_hash])
    tx = agree("eth_getTransactionByHash", [tx_hash])
    if (not receipt or not tx or receipt.get("status") != "0x1" or
            receipt.get("transactionHash") != tx.get("hash") or
            receipt.get("blockHash") != tx.get("blockHash") or
            tx.get("from", "").lower() != wallet or tx.get("to", "").lower() != target or
            int(receipt["blockNumber"], 16) > int(block, 16)):
        raise ValueError("Expected a successful confirmed transaction from the intended wallet to the intended contract")
    canonical = agree("eth_getBlockByNumber", [receipt["blockNumber"], False])
    if not canonical or canonical["hash"] != receipt["blockHash"]:
        raise ValueError("Transaction receipt is no longer canonical")
    return receipt, tx


def prepare_publication(args, container, wallet, call):
    manifest_path = Path(args.release_manifest).resolve()
    manifest = json.loads(manifest_path.read_text())
    policy = manifest.get("policy", {})
    if (policy.get("container") != container or policy.get("chain") != "196" or
            not re.fullmatch(r"v[1-9][0-9]*(?:\.[0-9]+){0,2}", policy.get("version", "")) or
            policy.get("requestProfile") != "studio-text-v1"):
        raise ValueError("Expected a live release manifest for the actual container; fixture and mock releases are rejected")
    root = Path(__file__).parent
    verified = json.loads(subprocess.check_output(["node", str(root / "studio.mjs"), "verify",
        str(manifest_path), args.verified_bundle, args.buyer_public], text=True, timeout=15))
    with tempfile.TemporaryDirectory(prefix="receipt-desk-release-") as directory:
        generated = Path(directory) / "index.html"
        subprocess.run(["node", str(root / "build.mjs"), str(manifest_path), str(generated)],
                       capture_output=True, text=True, check=True, timeout=15)
        html = Path(args.release_html).read_bytes()
        if html != generated.read_bytes() or not 0 < len(html) <= 24000:
            raise ValueError("Local HTML differs from the release manifest build or exceeds one chunk")
    path = policy["version"] + "/index.html"
    info = call(REGISTRY, "fileInfo(address,string)", container, path)[2:]
    if len(info) < 320 or int(info[256:320], 16) != 0:
        raise ValueError("Release path is occupied or metadata is invalid; overwrites are refused")
    sha256 = "0x" + hashlib.sha256(html).hexdigest()
    data = cast("calldata", "putFile(address,string,string,bytes32,bytes)",
                container, path, "text/html", sha256, "0x" + html.hex())
    publication = dict(container=container, registry=REGISTRY, path=path, sha256=sha256,
                       size=len(html), contentType="text/html", implementation=IMPLEMENTATION,
                       existingChunks=0, verifiedReceipt=verified)
    transaction = dict(chainId=196, **{"from": wallet}, to=REGISTRY, value="0x0", data=data)
    return publication, transaction


def main():
    global RPCS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--second-rpc", choices=SECOND_RPCS,
                        default=os.environ.get("TAPEOUT_SECOND_RPC", SECOND_RPCS[0]),
                        help="Independent comparison endpoint, or TAPEOUT_SECOND_RPC")
    parser.add_argument("--processor", type=int, default=0)
    parser.add_argument("--wallet", help="Public transaction sender address")
    parser.add_argument("--mint-tx", help="Successful one-NAND mint hash, required before preparing tapeout")
    parser.add_argument("--open-tx", help="Successful opening hash for cumulative budget and publication checks")
    parser.add_argument("--release-manifest")
    parser.add_argument("--release-html")
    parser.add_argument("--verified-bundle")
    parser.add_argument("--buyer-public")
    parser.add_argument("--tapeout-tx", help="Successful tapeout hash, to resolve the actual NFT id")
    args = parser.parse_args()
    if args.second_rpc not in SECOND_RPCS:
        parser.error("TAPEOUT_SECOND_RPC must be a whitelisted OKX or dRPC endpoint")
    RPCS = (PRIMARY_RPC, args.second_rpc)
    if args.processor < 0 or (args.wallet and (not ADDRESS.fullmatch(args.wallet) or args.wallet.lower() == ZERO)):
        parser.error("Expected a nonnegative processor index and a nonzero public wallet address")
    if args.mint_tx and (not HASH.fullmatch(args.mint_tx) or not args.wallet):
        parser.error("--mint-tx requires a transaction hash and --wallet")
    if args.tapeout_tx and not args.mint_tx:
        parser.error("--tapeout-tx requires the preceding --mint-tx for budget accounting")
    if args.tapeout_tx and (not HASH.fullmatch(args.tapeout_tx) or not args.wallet):
        parser.error("--tapeout-tx requires a transaction hash and --wallet")
    if args.open_tx and (not HASH.fullmatch(args.open_tx) or not args.tapeout_tx):
        parser.error("--open-tx requires a hash and the preceding mint/tapeout hashes")
    release_arguments = (args.release_manifest, args.release_html, args.verified_bundle, args.buyer_public)
    if any(release_arguments) and (not all(release_arguments) or not args.open_tx):
        parser.error("Publication requires --open-tx and all four release manifest/HTML/receipt/buyer files")
    if agree("eth_chainId", []) != "0xc4":
        raise ValueError("Unexpected chain ID")
    block = hex(min(int(n, 16) for n in reads("eth_blockNumber", [])) - 8)
    block_info = agree("eth_getBlockByNumber", [block, False])
    if not block_info or not block_info.get("hash"):
        raise ValueError("No confirmed block found")

    def call(address, signature, *values):
        return agree("eth_call", [{"to": address, "data": cast("calldata", signature, *map(str, values))}, block])

    processor = "0x" + call(FACTORY, "cpuAt(uint256)", args.processor)[-40:]
    if args.processor == 0 and processor != GENESIS:
        raise ValueError("Factory processor zero changed")
    transistors = "0x" + call(processor, "transistors()")[-40:]
    if "0x" + call(transistors, "circuits()")[-40:] != processor or int(call(transistors, "NAND()"), 16) != 0:
        raise ValueError("Processor/transistor linkage or NAND token id differs")
    for address in (processor, transistors, OPENER):
        if agree("eth_getCode", [address, block]) == "0x":
            raise ValueError("Target contract has no code")
    cap = int(call(transistors, "supplyCap()"), 16)
    minted = int(call(transistors, "minted()"), 16)
    mint_price = int(call(transistors, "mintPrice()"), 16)
    protocol_fee = int(call(transistors, "protocolFee()"), 16)
    tape_fee = int(call(processor, "TAPEOUT_FEE()"), 16)
    open_fee = int(call(OPENER, "FEE()"), 16)
    mint_value = mint_price + protocol_fee
    total = mint_value + tape_fee + open_fee
    wallet = args.wallet.lower() if args.wallet else "<PUBLIC_STUDIO_WALLET>"
    fee_values = {"transistorPrice": mint_price, "mintProtocolFee": protocol_fee,
                  "mintTransactionValue": mint_value, "tapeout": tape_fee, "open": open_fee,
                  "totalBeforeGas": total}
    result = dict(chainId=196, block=int(block, 16), blockHash=block_info["hash"], rpcProviders=list(RPCS),
                  interfaceSource="https://tapeout.net/app/assets/index-DsAkZLRU.js",
                  processorIndex=args.processor, processor=processor, transistors=transistors,
                  supplyCap=str(cap), minted=str(minted), remaining=str(cap-minted), feasible=cap-minted >= 1,
                  fees={name: dict(wei=str(value), OKB=okb(value)) for name, value in fee_values.items()},
                  gas={"included": False, "gasPriceWeiObservations": reads("eth_gasPrice", []),
                       "note": "Estimate each dependent transaction against its actual preceding confirmed state."})
    mint = dict(chainId=196, **{"from": wallet}, to=transistors, value=hex(mint_value),
                data=cast("calldata", "mint(uint256,uint256)", "0", "1"))
    tapeout = dict(chainId=196, **{"from": wallet}, to=processor, value=hex(tape_fee),
                   data=cast("calldata", "tapeout(bytes,uint32,uint32)", NETLIST, "2", "1"))
    open_template = dict(chainId=196, **{"from": wallet}, to=OPENER, value=hex(open_fee),
                         function="open(address,uint256)",
                         arguments=[processor, "<CIRCUIT_ID_FROM_SUCCESSFUL_TAPEOUT_RECEIPT>"],
                         dataTemplate=cast("calldata", "open(address,uint256)", processor, "0")[:-64] +
                         "<CIRCUIT_ID_AS_64_HEX_DIGITS>")

    result["netlist"] = dict(bytes=NETLIST, inputs=2, outputs=1, NAND=1)
    if cap - minted < 1:
        result["reason"] = "Processor has no remaining mint capacity. Choose a different processor before preparing execution."
        result["transactions"] = []
    else:
        result["transactions"] = [dict(stage="mint", **mint), dict(stage="tapeout-after-mint-confirmation", **tapeout),
                                  dict(stage="open-after-tapeout-receipt-verification", **open_template)]
        result["receiptCommand"] = f"python3 plan-container.py --processor {args.processor} --wallet {wallet} --mint-tx <MINT_HASH> --tapeout-tx <TAPEOUT_HASH>"
    spent = 0
    stage = 0
    if args.mint_tx:
        mint_receipt, mint_transaction = confirmed_transaction(args.mint_tx, wallet, transistors, block)
        fee_at_mint = int(agree("eth_call", [{"to": transistors,
            "data": cast("calldata", "mintPrice()")}, mint_receipt["blockNumber"]]), 16)
        fee_at_mint += int(agree("eth_call", [{"to": transistors,
            "data": cast("calldata", "protocolFee()")}, mint_receipt["blockNumber"]]), 16)
        if (mint_transaction["input"].lower() != cast("calldata", "mint(uint256,uint256)", "0", "1") or
                int(mint_transaction["value"], 16) != fee_at_mint):
            raise ValueError("Mint transaction differs from the one-NAND plan")
        minted_topic = cast("keccak", "Minted(address,uint256,uint256,uint256)")
        wallet_topic = "0x" + wallet[2:].rjust(64, "0")
        matches = [log for log in mint_receipt["logs"] if log.get("address", "").lower() == transistors and
            [t.lower() for t in log.get("topics", [])] == [minted_topic, wallet_topic, "0x" + "0" * 64] and
            log.get("data", "").lower() == "0x" + format(1, "064x") + format(fee_at_mint, "064x")]
        if len(matches) != 1:
            raise ValueError("Successful mint event is missing or inconsistent")
        spent += transaction_cost(mint_receipt, mint_transaction)
        stage = 1
    if args.tapeout_tx:
        receipt = agree("eth_getTransactionReceipt", [args.tapeout_tx])
        transaction = agree("eth_getTransactionByHash", [args.tapeout_tx])
        if not receipt or not transaction or not receipt.get("blockNumber"):
            raise ValueError("Tapeout transaction is missing or unconfirmed")
        historical_fee = int(agree("eth_call", [{"to": processor,
            "data": cast("calldata", "TAPEOUT_FEE()")}, receipt["blockNumber"]]), 16)
        token_id = receipt_id(receipt, transaction, processor, wallet, historical_fee)
        if int(receipt["blockNumber"], 16) > int(block, 16):
            raise ValueError("Tapeout receipt is not yet eight blocks confirmed")
        canonical = agree("eth_getBlockByNumber", [receipt["blockNumber"], False])
        if not canonical or canonical["hash"] != receipt["blockHash"]:
            raise ValueError("Tapeout receipt is no longer canonical")
        if "0x" + call(processor, "ownerOf(uint256)", token_id)[-40:] != wallet:
            raise ValueError("Receipt NFT is no longer owned by the intended wallet")
        container = "0x" + call(OPENER, "accountOf(address,uint256)", processor, token_id)[-40:]
        opened = int(call(OPENER, "isOpened(address,uint256)", processor, token_id), 16) == 1
        result["resolvedCircuit"] = dict(id=str(token_id), container=container, opened=opened,
                                        tape=f"tape://{token_id}.2.{args.processor}.tape/v1/index.html")
        result["openTransaction"] = None if opened else dict(chainId=196, **{"from": wallet}, to=OPENER,
            value=hex(open_fee), data=cast("calldata", "open(address,uint256)", processor, token_id))
        if (int(receipt["blockNumber"], 16), int(receipt["transactionIndex"], 16)) <= (
                int(mint_receipt["blockNumber"], 16), int(mint_receipt["transactionIndex"], 16)):
            raise ValueError("Tapeout did not occur after the approved mint")
        spent += transaction_cost(receipt, transaction)
        stage = 2
    if args.open_tx:
        open_receipt, open_transaction = confirmed_transaction(args.open_tx, wallet, OPENER, block)
        historical_open_fee = int(agree("eth_call", [{"to": OPENER,
            "data": cast("calldata", "FEE()")}, open_receipt["blockNumber"]]), 16)
        if (open_transaction["input"].lower() != cast("calldata", "open(address,uint256)", processor, token_id) or
                int(open_transaction["value"], 16) != historical_open_fee or not opened):
            raise ValueError("Opening receipt or current opened status does not match this circuit")
        event_topics = [cast("keccak", "Opened(address,uint256,address,address)"),
                        "0x" + processor[2:].rjust(64, "0"), "0x" + format(token_id, "064x"),
                        "0x" + container[2:].rjust(64, "0")]
        matches = [log for log in open_receipt["logs"] if log.get("address", "").lower() == OPENER and
            [topic.lower() for topic in log.get("topics", [])] == event_topics and
            log.get("data", "").lower() == "0x" + wallet[2:].rjust(64, "0")]
        if len(matches) != 1:
            raise ValueError("Expected the matching successful Opened event")
        if (int(open_receipt["blockNumber"], 16), int(open_receipt["transactionIndex"], 16)) <= (
                int(receipt["blockNumber"], 16), int(receipt["transactionIndex"], 16)):
            raise ValueError("Opening did not occur after the approved tapeout")
        if "0x" + call(container, "owner()")[-40:] != wallet:
            raise ValueError("Live container owner differs from the approved wallet")
        token = call(container, "token()")[2:]
        if (len(token) != 192 or int(token[:64], 16) != 196 or
                "0x" + token[88:128] != processor or int(token[128:192], 16) != token_id):
            raise ValueError("Container token binding differs from the receipt circuit")
        if (agree("eth_getStorageAt", [REGISTRY, IMPLEMENTATION_SLOT, block]) != IMPLEMENTATION or
                int(call(REGISTRY, "isOpenedContainer(address)", container), 16) != 1):
            raise ValueError("Unexpected SiteRegistry implementation or unopened container")
        spent += transaction_cost(open_receipt, open_transaction)
        if spent > 90000000000000000:
            raise ValueError("Confirmed acquisition spending exceeds the authorized 0.09 OKB budget")
        stage = 3
        default_info = call(REGISTRY, "fileInfo(address,string)", container, "v1/index.html")[2:]
        if len(default_info) < 320:
            raise ValueError("Invalid SiteRegistry release-path metadata")
        result["siteRegistry"] = dict(address=REGISTRY, implementation=IMPLEMENTATION, openedContainer=True,
            checkedPath="v1/index.html", existingChunks=int(default_info[256:320], 16))
        balance = int(agree("eth_getBalance", [wallet, block]), 16)
        result["budget"] = dict(limitWei="90000000000000000", actualAcquisitionSpendWei=str(spent),
            remainingWei=str(90000000000000000-spent), walletBalanceWei=str(balance))
        if args.release_manifest:
            publication, publish_transaction = prepare_publication(args, container, wallet, call)
            result["publication"], result["publishTransaction"] = publication, publish_transaction
        else:
            result["publicationStatus"] = "Awaiting the real release manifest, matching HTML, verified live receipt and buyer public key."
    if args.wallet and (cap-minted >= 1 or stage > 0) and (stage < 3 or args.release_manifest):
        budget = 90000000000000000
        future_values = (tape_fee + open_fee, open_fee, 0, 0)[stage]
        selected = (mint, tapeout, result.get("openTransaction"), result.get("publishTransaction"))[stage]
        if selected is None:
            raise ValueError("Container is already opened; do not repeat acquisition")
        tx = {key: value for key, value in selected.items() if key != "chainId"}
        latest_nonce = agree("eth_getTransactionCount", [wallet, "latest"])
        pending_nonce = agree("eth_getTransactionCount", [wallet, "pending"])
        if latest_nonce != pending_nonce:
            raise ValueError("Wallet has pending transactions; reconcile them before preparing the next step")
        estimates = reads("eth_estimateGas", [tx])
        estimate = max(int(value, 16) for value in estimates)
        gas_price = max(int(value, 16) for value in reads("eth_gasPrice", []))
        gas_limit = (estimate * 120 + 99) // 100
        gas_ceiling = gas_price * gas_limit
        maximum_total = spent + int(tx["value"], 16) + gas_ceiling + future_values
        balance = int(agree("eth_getBalance", [wallet, block]), 16)
        if maximum_total > budget or balance < int(tx["value"], 16) + gas_ceiling + future_values:
            raise ValueError("Current step and reserved future values exceed the 0.09 OKB budget or wallet balance")
        tx.update(chainId="0xc4", gas=hex(gas_limit), gasPrice=hex(gas_price), nonce=latest_nonce)
        result["walletStep"] = dict(stage=("mint", "tapeout", "open", "publish")[stage], transaction=tx,
            budgetWei=str(budget), previousActualSpendWei=str(spent), futureReservedValueWei=str(future_values),
            estimatedGas=[str(int(value, 16)) for value in estimates], maxGasFeeWei=str(gas_ceiling),
            maxTotalWithFutureValuesWei=str(maximum_total), walletBalanceWei=str(balance),
            snapshotBlock=int(block, 16))
    result["notes"] = ["No signing, broadcast, or private-key access occurs in this tool.",
                       "Values are a confirmed-block snapshot. Refresh fees and estimate gas before an authorized transaction.",
                       "Stage dependencies require confirmed receipts. NFT ids come from matching receipt events, never nextId."]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
