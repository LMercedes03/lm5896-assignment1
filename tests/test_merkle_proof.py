import base64

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
)


def two_leaf_tree():
    left = DefaultHasher.hash_leaf(b"left")
    right = DefaultHasher.hash_leaf(b"right")
    root = DefaultHasher.hash_children(left, right)
    return left, right, root


def test_compute_leaf_hash_uses_rfc6962_prefix():
    body = base64.b64encode(b"left").decode()
    assert compute_leaf_hash(body) == DefaultHasher.hash_leaf(b"left").hex()


@pytest.mark.parametrize("index", [0, 1])
def test_verify_inclusion_accepts_each_leaf(index):
    left, right, root = two_leaf_tree()
    leaf, sibling = (left, right) if index == 0 else (right, left)
    verify_inclusion(DefaultHasher, index, 2, leaf.hex(), [sibling.hex()], root.hex())


def test_verify_inclusion_rejects_wrong_root():
    left, right, _ = two_leaf_tree()
    with pytest.raises(RootMismatchError):
        verify_inclusion(DefaultHasher, 0, 2, left.hex(), [right.hex()], "0" * 64)


def test_inclusion_rejects_wrong_proof_length_and_index():
    left, _, _ = two_leaf_tree()
    with pytest.raises(ValueError, match="wrong proof size"):
        root_from_inclusion_proof(DefaultHasher, 0, 2, left, [])
    with pytest.raises(ValueError, match="beyond size"):
        root_from_inclusion_proof(DefaultHasher, 2, 2, left, [])


def test_consistency_accepts_tree_growth():
    left, right, root = two_leaf_tree()
    verify_consistency(DefaultHasher, 1, 2, [right.hex()], left.hex(), root.hex())


def test_consistency_rejects_incorrect_new_root():
    left, right, _ = two_leaf_tree()
    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 1, 2, [right.hex()], left.hex(), "0" * 64)


def test_consistency_rejects_reversed_sizes_or_missing_proof():
    left, _, root = two_leaf_tree()
    with pytest.raises(ValueError, match="size2"):
        verify_consistency(DefaultHasher, 2, 1, [], left.hex(), root.hex())
    with pytest.raises(ValueError, match="empty"):
        verify_consistency(DefaultHasher, 1, 2, [], left.hex(), root.hex())


def test_consistency_accepts_equal_roots_only_without_proof():
    left, _, _ = two_leaf_tree()
    verify_consistency(DefaultHasher, 1, 1, [], left.hex(), left.hex())
    with pytest.raises(ValueError, match="not empty"):
        verify_consistency(DefaultHasher, 1, 1, [left.hex()], left.hex(), left.hex())
