import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
import requests

import main


def checkpoint(tree_id=7, size=10, root="a" * 64):
    return {"treeID": tree_id, "treeSize": size, "rootHash": root}


def entry_for(data):
    body = {
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(data).hexdigest(),
                }
            },
            "signature": {
                "content": base64.b64encode(b"signature").decode(),
                "publicKey": {"content": base64.b64encode(b"certificate").decode()},
            },
        },
    }
    return {
        "logIndex": 42,
        "body": base64.b64encode(json.dumps(body).encode()).decode(),
        "verification": {
            "inclusionProof": {
                "logIndex": 4,
                "treeSize": 8,
                "hashes": [],
                "rootHash": "b" * 64,
            }
        },
    }


def test_fetch_json_checks_http_status(monkeypatch):
    class Response:
        def raise_for_status(self):
            raise requests.HTTPError("bad response")

    monkeypatch.setattr(main.requests, "get", lambda *args, **kwargs: Response())
    with pytest.raises(requests.HTTPError):
        main.fetch_json("/api/v1/log")


def test_get_log_entry_rejects_wrong_index(monkeypatch):
    monkeypatch.setattr(main, "fetch_json", lambda *args: {"id": {"logIndex": 9}})
    with pytest.raises(ValueError, match="does not match"):
        main.get_log_entry(10)


def test_get_log_entry_rejects_missing_or_duplicate_entries(monkeypatch):
    monkeypatch.setattr(main, "fetch_json", lambda *args: {})
    with pytest.raises(ValueError, match="exactly one"):
        main.get_log_entry(10)
    monkeypatch.setattr(main, "fetch_json", lambda *args: {"a": {}, "b": {}})
    with pytest.raises(ValueError, match="exactly one"):
        main.get_log_entry(10)


def test_inclusion_accepts_matching_hash_and_proof(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"test artifact\n")
    entry = entry_for(artifact.read_bytes())
    monkeypatch.setattr(main, "get_log_entry", lambda *args: entry)
    monkeypatch.setattr(main, "extract_public_key", lambda cert: b"public key")
    monkeypatch.setattr(main, "verify_artifact_signature", lambda *args: None)
    calls = []
    monkeypatch.setattr(
        main, "verify_inclusion", lambda *args, **kwargs: calls.append(args)
    )

    main.inclusion(42, artifact)
    assert calls[0][1:3] == (4, 8)
    assert calls[0][3] == main.compute_leaf_hash(entry["body"])


def test_inclusion_rejects_artifact_hash_mismatch(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"changed")
    monkeypatch.setattr(main, "get_log_entry", lambda *args: entry_for(b"original"))
    with pytest.raises(ValueError, match="artifact hash does not match"):
        main.inclusion(42, artifact)


def test_inclusion_rejects_unsupported_hash_algorithm(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"content")
    entry = entry_for(artifact.read_bytes())
    body = json.loads(base64.b64decode(entry["body"]))
    body["spec"]["data"]["hash"]["algorithm"] = "sha512"
    entry["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    monkeypatch.setattr(main, "get_log_entry", lambda *args: entry)
    with pytest.raises(ValueError, match="SHA-256"):
        main.inclusion(42, artifact)


def test_inclusion_rejects_signature_failure(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"content")
    monkeypatch.setattr(
        main, "get_log_entry", lambda *args: entry_for(artifact.read_bytes())
    )
    monkeypatch.setattr(main, "extract_public_key", lambda cert: b"public key")
    monkeypatch.setattr(
        main, "verify_artifact_signature", lambda *args: print("Signature is invalid")
    )
    with pytest.raises(ValueError, match="Signature is invalid"):
        main.inclusion(42, artifact)


def test_inclusion_requires_file(tmp_path):
    with pytest.raises(ValueError, match="existing file"):
        main.inclusion(42, tmp_path / "missing")


def test_save_checkpoint_preserves_size_named_snapshots(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    main.save_checkpoint(checkpoint(size=10))
    main.save_checkpoint(checkpoint(size=11))
    assert json.loads(Path("checkpoint-7-10.json").read_text())["treeSize"] == 10
    assert json.loads(Path("checkpoint-7-11.json").read_text())["treeSize"] == 11
    assert json.loads(Path("checkpoint.json").read_text())["treeSize"] == 11


def test_consistency_checks_matching_tree_and_proof(monkeypatch):
    latest = checkpoint(size=12, root="b" * 64)
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: latest)
    monkeypatch.setattr(main, "fetch_json", lambda path, params: {"hashes": ["c" * 64]})
    calls = []
    monkeypatch.setattr(main, "verify_consistency", lambda *args: calls.append(args))
    main.consistency(checkpoint())
    assert calls[0][1:3] == (10, 12)
    assert calls[0][-2:] == ("a" * 64, "b" * 64)


def test_consistency_rejects_wrong_tree(monkeypatch):
    monkeypatch.setattr(
        main, "get_latest_checkpoint", lambda debug=False: checkpoint(8)
    )
    with pytest.raises(ValueError, match="not found"):
        main.consistency(checkpoint(7))


def test_consistency_rejects_non_growing_tree(monkeypatch):
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: checkpoint())
    with pytest.raises(ValueError, match="smaller tree size"):
        main.consistency(checkpoint())


def test_validate_checkpoint_rejects_bad_root_and_size():
    with pytest.raises(ValueError, match="positive"):
        main.validate_checkpoint(checkpoint(size=0))
    with pytest.raises(ValueError, match="64 hexadecimal"):
        main.validate_checkpoint(checkpoint(root="abc"))


def test_cli_checkpoint_saves_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "-c"])
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: checkpoint())
    assert main.main() == 0
    assert Path("checkpoint-7-10.json").exists()


def test_cli_requires_an_action(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py"])
    with pytest.raises(SystemExit) as error:
        main.main()
    assert error.value.code == 2
