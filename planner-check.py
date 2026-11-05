"""Offline regression for integer NFT ids crossing the cast subprocess boundary."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("plan_container", Path(__file__).with_name("plan-container.py"))
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)

with patch.object(planner.subprocess, "check_output", return_value="0x00\n") as process:
    assert planner.cast("calldata", "ownerOf(uint256)", 2) == "0x00"
    assert process.call_args.args[0] == ["cast", "calldata", "ownerOf(uint256)", "2"]

for signature, arguments in [
    ("ownerOf(uint256)", []),
    ("open(address,uint256)", [planner.GENESIS]),
]:
    assert planner.cast("calldata", signature, *arguments, 2) == planner.cast("calldata", signature, *arguments, "2")
print("PASS: integer NFT id is stringified at subprocess boundary and produces the expected calldata")

# Publication validation is exercised with fake verifier/build results and no RPC.
import hashlib
import json
import tempfile
from types import SimpleNamespace

with tempfile.TemporaryDirectory(prefix="publication-guard-") as directory:
    root = Path(directory)
    manifest = root / "manifest.json"
    release = root / "index.html"
    release.write_bytes(b"<html>Offline publication guard fixture</html>")
    container = "0x" + "11" * 20
    args = SimpleNamespace(release_manifest=str(manifest), release_html=str(release),
                           verified_bundle="offline-bundle", buyer_public="offline-buyer")
    policy = dict(chain="196", container=container, version="mock-v2", requestProfile="studio-text-v1")
    manifest.write_text(json.dumps(dict(policy=policy)))
    try:
        planner.prepare_publication(args, container, "0x" + "22" * 20, lambda *args: None)
    except ValueError as error:
        assert "mock" in str(error)
    else:
        raise AssertionError("Mock release was accepted")

    policy["version"] = "v1"
    manifest.write_text(json.dumps(dict(policy=policy)))
    real_run = planner.subprocess.run

    def fake_output(command, **kwargs):
        if command[0] == "node":
            return '{"chargeNanoUsd":"1"}'
        return real_run(command, capture_output=True, check=True, **kwargs).stdout

    def fake_build(command, **kwargs):
        Path(command[-1]).write_bytes(release.read_bytes())

    def metadata(chunks):
        return "0x" + "0" * 256 + format(chunks, "064x")

    with patch.object(planner.subprocess, "check_output", side_effect=fake_output), \
            patch.object(planner.subprocess, "run", side_effect=fake_build):
        try:
            planner.prepare_publication(args, container, "0x" + "22" * 20, lambda *args: metadata(1))
        except ValueError as error:
            assert "occupied" in str(error)
        else:
            raise AssertionError("Occupied release path was accepted")
        publication, tx = planner.prepare_publication(args, container, "0x" + "22" * 20,
                                                      lambda *args: metadata(0))
        assert publication["path"] == "v1/index.html"
        assert publication["sha256"] == "0x" + hashlib.sha256(release.read_bytes()).hexdigest()
        assert tx["to"] == planner.REGISTRY and tx["value"] == "0x0"
print("PASS: mock release and occupied version path rejected; publication hash and registry binding checked offline")
