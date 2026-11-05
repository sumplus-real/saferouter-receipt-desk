"""Offline guards for the independent publication reader."""
import hashlib
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("verify_publication", Path(__file__).with_name("verify-publication.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

payload = b"abc"
encoded = "0x" + format(32,"064x") + format(len(payload),"064x") + payload.hex()
assert reader.dynamic_bytes(encoded) == payload
for invalid in [encoded[:-2], "0x"+format(9999,"064x"), "0x"+format(3,"064x")+"00"*32]:
    try:
        reader.dynamic_bytes(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("Truncated or invalid ABI payload accepted")
reader.pair = lambda method, params: ["0xc4", "0xc4"]
assert reader.agree("eth_chainId", []) == "0xc4"
reader.pair = lambda method, params: ["0xc4", "0x38"]
try:
    reader.agree("eth_chainId", [])
except ValueError:
    pass
else:
    raise AssertionError("Conflicting RPC answers accepted")
release = Path(__file__).parent / "release" / "index.html"
if not release.exists():
    release = Path(__file__).parent.parent / "release" / "index.html"
assert len(release.read_bytes()) == 12844
assert hashlib.sha256(release.read_bytes()).hexdigest() == reader.EXPECTED_SHA
print("PASS: frozen release identity, complete ABI bytes and RPC-disagreement rejection")
