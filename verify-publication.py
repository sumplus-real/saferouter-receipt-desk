"""Independent read-only acceptance of the frozen Receipt Desk X Layer publication."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

RPCS = ("https://rpc.xlayer.tech", "https://xlayer.drpc.org")
FACTORY = "0x1f09daefa827f02cbb40967cc91b259763760761"
PROCESSOR = "0x39e44dba62811e87fde122ca4d6c082568a384d0"
OPENER = "0x536add8f30f03b69f6fbf29d425a816a0dc50106"
REGISTRY = "0xd6efb7adcc9c83dc4924ad56f6a8e4e969b9adb6"
BINDING = "0x68809fd2fb343aa57d0aeb7f33defe477c9666f9"
CONTAINER = "0xde9a54ecaf32e6406fba0fcd78153ddc6777a63b"
OWNER = "0x91000b484b5d4d5ba888c8a2f5dbdbbbcbf788d2"
SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
IMPLEMENTATION = "0x000000000000000000000000a85c4143d1d4a77f54b8e4ecc9e6d1418afea45f"
EXPECTED_SHA = "c8582d26be5ec94aa9a9532d5039d931a7ad03db6d0e29396e2f2315d2ed4ab4"
PATH = "v1/index.html"
BUDGET = 90000000000000000
ACQUISITION = (
    "0xe003f7cd27beb0046c800f3a4a3cbcf37c19da2e74e59d19137017de01f7b725",
    "0x4bd8a37a7bb1b057c2c3216472d444a68e4b6cfecc35a97b91aea0f7ad696652",
    "0xb524dd8169b3b1990a023efcbeff5934c16ab0c2973dec8df62a5a16a4634095",
)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def calldata(signature, *values):
    return subprocess.check_output(["cast", "calldata", signature, *map(str, values)], text=True, timeout=10).strip()


def rpc(url, method, params):
    payload = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params))
    raw = subprocess.check_output(["curl", "-fsS", "--max-time", "15", "--retry", "1", "--retry-delay", "1",
        "-H", "Content-Type: application/json", "--data-binary", "@-", url], input=payload, text=True, timeout=35)
    response = json.loads(raw)
    require("result" in response, f"{url} rejected read-only {method}")
    return response["result"]


def pair(method, params):
    with ThreadPoolExecutor(2) as pool:
        return list(pool.map(lambda endpoint: rpc(endpoint, method, params), RPCS))


def normalized(method, value):
    if method == "eth_getTransactionByHash" and isinstance(value, dict):
        # Only this observed supplier extension differs. Preserve every standard transaction field.
        return {key: item for key, item in value.items() if key != "blockTimestamp"}
    return value


def agree(method, params):
    first, second = pair(method, params)
    require(normalized(method, first) == normalized(method, second), f"RPC disagreement for {method}")
    return first


def dynamic_bytes(encoded, offset_word=0):
    """Decode a bounded ABI bytes/string value without permissive truncation."""
    require(isinstance(encoded, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", encoded), "Malformed ABI bytes")
    raw = bytes.fromhex(encoded[2:])
    require(len(raw) >= (offset_word+1)*32, "Missing ABI offset")
    offset = int.from_bytes(raw[offset_word*32:(offset_word+1)*32], "big")
    require(offset % 32 == 0 and offset+32 <= len(raw), "Invalid ABI dynamic offset")
    size = int.from_bytes(raw[offset:offset+32], "big")
    require(size <= 24000 and offset+32+size <= len(raw), "ABI bytes exceed available data")
    return raw[offset+32:offset+32+size]


def confirmed_transaction(tx_hash, pinned):
    receipt = agree("eth_getTransactionReceipt", [tx_hash])
    tx = agree("eth_getTransactionByHash", [tx_hash])
    require(isinstance(receipt, dict) and isinstance(tx, dict), "Transaction is missing or not yet mined")
    require(receipt.get("status") == "0x1" and receipt.get("transactionHash") == tx_hash and tx.get("hash") == tx_hash,
            "Expected a successful receipt for the specified transaction")
    require(tx.get("from", "").lower() == OWNER and receipt.get("from", "").lower() == OWNER,
            "Unexpected transaction sender")
    require(tx["blockHash"] == receipt["blockHash"] and tx["blockNumber"] == receipt["blockNumber"], "Transaction/receipt block mismatch")
    require(int(receipt["blockNumber"], 16) <= pinned, "Publication requires at least eight-block depth")
    block = agree("eth_getBlockByNumber", [receipt["blockNumber"], False])
    index = int(receipt["transactionIndex"], 16)
    require(block and block["hash"] == receipt["blockHash"] and index < len(block["transactions"]) and
            block["transactions"][index] == tx_hash, "Receipt is not included in the canonical block")
    require(tx["transactionIndex"] == receipt["transactionIndex"] and tx.get("to") == receipt.get("to"), "Receipt transaction identity differs")
    require(receipt.get("effectiveGasPrice") is not None, "Effective receipt gas price is missing")
    gas_fee = int(receipt["gasUsed"], 16)*int(receipt["effectiveGasPrice"], 16) + int(receipt.get("l1Fee", "0x0"), 16)
    return tx, receipt, dict(hash=tx_hash, valueWei=str(int(tx["value"], 16)), gasFeeWei=str(gas_fee),
                            totalWei=str(int(tx["value"], 16)+gas_fee), gasUsed=int(receipt["gasUsed"], 16))


def check_gateway(expected_bytes):
    url = "https://2-2-409-open.tapekit.org/v1/index.html"
    with tempfile.TemporaryDirectory(prefix="receipt-gateway-read-") as directory:
        headers_path, body_path = Path(directory)/"headers", Path(directory)/"body"
        result = subprocess.run(["curl", "-sS", "--max-time", "30", "-D", str(headers_path),
            "-o", str(body_path), "-w", "%{http_code}", url], capture_output=True, text=True, timeout=35)
        require(result.returncode == 0 and result.stdout == "200", "Compatibility gateway did not return HTTP 200")
        headers = {}
        for line in headers_path.read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()
        require(body_path.read_bytes() == expected_bytes, "Gateway body differs from the dual-RPC verified HTML")
        require(headers.get("x-tape-name") == "2.2.409.tape" and headers.get("x-tape-verified") == "1" and
                headers.get("x-tape-sha256", "").removeprefix("0x") == EXPECTED_SHA and
                headers.get("x-tape-mode") == "server", "Gateway identity or verification headers differ")
        return dict(url=url, httpStatus=200, allBytesMatch=True, mode="server", verifiedHeader=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tx", required=True, help="Confirmed putFile publication transaction hash")
    parser.add_argument("--local-file", type=Path, required=True)
    parser.add_argument("--check-gateway", action="store_true", help="Also verify the actual HTTPS compatibility gateway response")
    parser.add_argument("--write-html", type=Path, help="Save the independently read bytes to a new file")
    parser.add_argument("--extra-tx", action="append", default=[], help="Additional known wallet expense included in the budget")
    args = parser.parse_args()
    for tx_hash in [args.tx, *args.extra_tx]:
        require(re.fullmatch(r"0x[0-9a-f]{64}", tx_hash), "Expected lowercase transaction hashes")
    require(len({*ACQUISITION, args.tx, *args.extra_tx}) == 4+len(args.extra_tx), "Duplicate transaction in spending ledger")
    local = args.local_file.read_bytes()
    require(len(local) == 12844 and hashlib.sha256(local).hexdigest() == EXPECTED_SHA, "Local HTML differs from the frozen release")
    require(agree("eth_chainId", []) == "0xc4", "Wrong chain")
    pinned = min(int(height, 16) for height in pair("eth_blockNumber", []))-8
    block = hex(pinned)
    block_header = agree("eth_getBlockByNumber", [block, False])

    def call(target, signature, *values):
        return agree("eth_call", [{"to": target, "data": calldata(signature, *values)}, block])

    require("0x"+call(FACTORY, "cpuAt(uint256)", 409)[-40:] == PROCESSOR, "Factory processor mapping changed")
    require("0x"+call(PROCESSOR, "ownerOf(uint256)", 2)[-40:] == OWNER, "NFT owner changed")
    require("0x"+call(OPENER, "accountOf(address,uint256)", PROCESSOR, 2)[-40:] == CONTAINER, "Derived container differs")
    require("0x"+call(CONTAINER, "owner()")[-40:] == OWNER, "Container owner differs")
    token = call(CONTAINER, "token()")[2:]
    require(len(token) == 192 and int(token[:64], 16) == 196 and "0x"+token[88:128] == PROCESSOR and
            int(token[128:192], 16) == 2, "Container token binding differs")
    require(int(call(OPENER, "isOpened(address,uint256)", PROCESSOR, 2), 16) == 1 and
            int(call(REGISTRY, "isOpenedContainer(address)", CONTAINER), 16) == 1, "Container is not opened")
    require(agree("eth_getStorageAt", [REGISTRY, SLOT, block]) == IMPLEMENTATION, "Registry implementation changed")
    info = call(REGISTRY, "fileInfo(address,string)", CONTAINER, PATH)
    words = info[2:]
    require(len(words) >= 320, "Missing file metadata")
    size, chunks = int(words[:64], 16), int(words[256:320], 16)
    require(size == 12844 and chunks == 1 and words[128:192] == EXPECTED_SHA, "Publication size/chunks/hash differ")
    require(dynamic_bytes(info, 1) == b"text/html", "Unexpected content type")
    data = dynamic_bytes(call(REGISTRY, "read(address,string)", CONTAINER, PATH))
    require(len(data) == size and hashlib.sha256(data).hexdigest() == EXPECTED_SHA and data == local,
            "On-chain bytes differ from metadata or local release")

    tx, receipt, publication_cost = confirmed_transaction(args.tx, pinned)
    expected_input = calldata("putFile(address,string,string,bytes32,bytes)", CONTAINER, PATH, "text/html",
                              "0x"+EXPECTED_SHA, "0x"+local.hex())
    require(tx.get("to") == REGISTRY and int(tx["value"], 16) == 0 and tx.get("input") == expected_input,
            "Publication transaction does not bind this exact release/path/registry")
    ledger = []
    expected_targets = ("0x5d7e99c4d1b71f4d24c9d53f41aed8196064a61f", PROCESSOR, OPENER)
    for nonce, (tx_hash, target) in enumerate(zip(ACQUISITION, expected_targets)):
        old_tx, _, cost = confirmed_transaction(tx_hash, pinned)
        require(old_tx.get("to") == target and int(old_tx["nonce"], 16) == nonce, "Acquisition transaction target/nonce differs")
        ledger.append(cost)
    nonces = [0, 1, 2, int(tx["nonce"], 16)]
    ledger.append(publication_cost)
    for tx_hash in args.extra_tx:
        extra_tx, _, cost = confirmed_transaction(tx_hash, pinned)
        nonces.append(int(extra_tx["nonce"], 16))
        ledger.append(cost)
    require(sorted(nonces) == list(range(len(ledger))), "Wallet spending ledger omits or duplicates a transaction nonce")
    spent = sum(int(item["totalWei"]) for item in ledger)
    balance = int(agree("eth_getBalance", [OWNER, block]), 16)
    require(spent <= BUDGET and balance+spent == BUDGET, "Wallet budget or complete spending reconciliation failed")
    activated = int(call(BINDING, "isContainerLive(address)", CONTAINER), 16) == 1 or \
                int(call(BINDING, "isLive(string,address)", "2.2.409.tape", CONTAINER), 16) == 1
    gateway = check_gateway(local) if activated and args.check_gateway else None
    if args.write_html:
        with args.write_html.open("xb") as output:
            output.write(data)
    print(json.dumps(dict(verified=activated, chainBytesVerified=True, chainId=196, confirmationPolicy="Two operators, at least eight-block depth, canonical receipt inclusion at read time", block=pinned, blockHash=block_header["hash"],
        rpcProviders=list(RPCS), owner=OWNER, container=CONTAINER, registry=REGISTRY,
        implementation=IMPLEMENTATION, path=PATH, size=size, sha256=EXPECTED_SHA, allBytesMatch=True,
        publicationTransaction=args.tx, ledger=ledger, totalSpendWei=str(spent), remainingBudgetWei=str(BUDGET-spent),
        walletBalanceWei=str(balance), tape="tape://2.2.409.tape/v1/index.html",
        browser="https://2-2-409.tapekit.org/v1/index.html", statusPage="https://2-2-409.tapekit.org/.tape/status",
        nameActivated=activated, compatibilityBrowser="https://2-2-409-open.tapekit.org/v1/index.html", gateway=gateway, browserInteraction="Requires separate real-browser verification of the service worker and receipt import"), indent=2))
    if not activated:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
