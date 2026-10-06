import argparse
import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import sys

import requests

from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

REKOR_URL = "https://rekor.sigstore.dev"


def fetch_json(path, params=None):
    response = requests.get(REKOR_URL + path, params=params, timeout=30)
    response.raise_for_status()
    return response.json()


def validate_index(log_index):
    if type(log_index) is not int or log_index < 0:
        raise ValueError("log index must be a nonnegative integer")


def save_debug(filename, value, debug):
    if debug:
        Path(filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def get_log_entry(log_index, debug=False):
    validate_index(log_index)
    result = fetch_json("/api/v1/log/entries", {"logIndex": log_index})
    if not isinstance(result, dict) or len(result) != 1:
        raise ValueError("expected exactly one Rekor entry")
    entry = next(iter(result.values()))
    if entry["logIndex"] != log_index:
        raise ValueError("returned log index does not match the requested index")
    return entry


def get_verification_proof(log_index, debug=False, entry=None):
    validate_index(log_index)
    if entry is None:
        entry = get_log_entry(log_index, debug)
    proof = entry["verification"]["inclusionProof"]
    if not isinstance(proof, dict):
        raise ValueError("missing inclusion proof")
    return proof


def inclusion(log_index, artifact_filepath, debug=False):
    validate_index(log_index)
    if not artifact_filepath or not Path(artifact_filepath).is_file():
        raise ValueError("artifact must be an existing file")

    entry = get_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"], validate=True))
    if body["kind"] != "hashedrekord":
        raise ValueError("expected a hashedrekord entry for a Cosign-signed blob")
    spec = body["spec"]
    signature = base64.b64decode(spec["signature"]["content"], validate=True)
    certificate = base64.b64decode(spec["signature"]["publicKey"]["content"], validate=True)
    public_key = extract_public_key(certificate)

    # The supplied helper prints failures and returns None on both success and
    # failure. Preserve util.py, but turn any reported failure into an exception.
    signature_result = io.StringIO()
    with redirect_stdout(signature_result):
        verify_artifact_signature(signature, public_key, artifact_filepath)
    if signature_result.getvalue().strip():
        raise ValueError(signature_result.getvalue().strip())
    print("Artifact signature verification successful")

    proof = get_verification_proof(log_index, debug, entry)
    proof_index = proof["logIndex"]
    validate_index(proof_index)
    if type(proof["treeSize"]) is not int or proof["treeSize"] <= proof_index:
        raise ValueError("invalid inclusion-proof tree size")
    # Rekor's entry index can be global across shards; the proof index is local
    # to its Merkle tree and is the index required by verify_inclusion.
    verify_inclusion(DefaultHasher, proof_index, proof["treeSize"],
                     compute_leaf_hash(entry["body"]), proof["hashes"],
                     proof["rootHash"], debug)
    print("Inclusion verification successful")


def validate_checkpoint(checkpoint):
    if not isinstance(checkpoint, dict) or not checkpoint:
        raise ValueError("checkpoint must not be empty")
    if not re.fullmatch(r"[0-9]+", str(checkpoint["treeID"])):
        raise ValueError("tree ID must contain only digits")
    if type(checkpoint["treeSize"]) is not int or checkpoint["treeSize"] <= 0:
        raise ValueError("tree size must be a positive integer")
    if not isinstance(checkpoint["rootHash"], str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", checkpoint["rootHash"]):
        raise ValueError("root hash must be 64 hexadecimal characters")


def get_latest_checkpoint(debug=False):
    checkpoint = fetch_json("/api/v1/log")
    validate_checkpoint(checkpoint)
    save_debug("checkpoint.json", checkpoint, debug)
    return checkpoint


def consistency(prev_checkpoint, debug=False):
    validate_checkpoint(prev_checkpoint)
    log_info = get_latest_checkpoint(debug)
    checkpoints = [log_info] + log_info.get("inactiveShards", [])
    latest = next((item for item in checkpoints
                   if str(item["treeID"]) == str(prev_checkpoint["treeID"])), None)
    if latest is None:
        raise ValueError("tree ID was not found in Rekor's active or inactive shards")
    validate_checkpoint(latest)
    if latest["treeSize"] <= prev_checkpoint["treeSize"]:
        raise ValueError("use an older checkpoint with a smaller tree size")

    proof = fetch_json("/api/v1/log/proof", {
        "firstSize": prev_checkpoint["treeSize"],
        "lastSize": latest["treeSize"],
        "treeID": prev_checkpoint["treeID"],
    })
    # The response rootHash describes the log when the server answers, which
    # can be newer than lastSize. Verify hashes against our two fixed snapshots.
    verify_consistency(DefaultHasher, prev_checkpoint["treeSize"],
                       latest["treeSize"], proof["hashes"],
                       prev_checkpoint["rootHash"], latest["rootHash"])
    print(f"Tree ID: {latest['treeID']}")
    print(f"Older tree size: {prev_checkpoint['treeSize']}")
    print(f"Newer tree size: {latest['treeSize']}")
    print("Consistency verification successful")


def main():
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Show verification details and save the checkpoint")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("-c", "--checkpoint", action="store_true",
                         help="Fetch the latest Rekor checkpoint")
    actions.add_argument("--inclusion", type=int, metavar="LOG_INDEX",
                         help="Verify an artifact signature and log inclusion")
    actions.add_argument("--consistency", action="store_true",
                         help="Compare an older checkpoint with Rekor")
    parser.add_argument("--artifact", help="Artifact filepath")
    parser.add_argument("--tree-id", help="Older checkpoint tree ID")
    parser.add_argument("--tree-size", type=int, help="Older checkpoint tree size")
    parser.add_argument("--root-hash", help="Older checkpoint root hash")
    args = parser.parse_args()
    if args.inclusion is not None and not args.artifact:
        parser.error("--inclusion requires --artifact")
    if args.consistency and any(value is None for value in
                                (args.tree_id, args.tree_size, args.root_hash)):
        parser.error("--consistency requires --tree-id, --tree-size, and --root-hash")
    try:
        if args.checkpoint:
            print(json.dumps(get_latest_checkpoint(args.debug), indent=4))
        elif args.inclusion is not None:
            inclusion(args.inclusion, args.artifact, args.debug)
        else:
            consistency({"treeID": args.tree_id, "treeSize": args.tree_size,
                         "rootHash": args.root_hash}, args.debug)
    except (requests.RequestException, ValueError, KeyError, TypeError, OSError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # The provided Merkle helper raises its own RootMismatchError.
        print(f"Verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
