"""
Simple Serialize (SSZ) hash_tree_root for the LUCID reveal commitment.

Implements the minimal SSZ subset required by EIP-8184 for computing
``hash_tree_root(RevealCommitmentPreimage(...))``.

Reference:
  https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
"""

import math
from hashlib import sha256
from typing import List

from ethereum_types.bytes import Bytes32


def _sha256_pair(left: bytes, right: bytes) -> bytes:
    """Return SHA-256 hash of two 32-byte nodes concatenated."""
    return sha256(left + right).digest()


def _next_power_of_two(n: int) -> int:
    """Return the smallest power of two >= n (minimum 1)."""
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def merkleize(chunks: List[bytes], limit: int | None = None) -> bytes:
    """
    Compute the Merkle root of a list of 32-byte chunks.

    Pads the chunk list to the next power of two (bounded by ``limit`` when
    provided) with 32-byte zero chunks, then builds a binary Merkle tree
    using SHA-256 as the node hash function.

    Parameters
    ----------
    chunks :
        List of 32-byte leaf chunks.
    limit :
        Upper bound on chunk count (for variable-length types). The tree is
        padded to the next power of two >= max(limit, len(chunks)).

    Returns
    -------
    root : `bytes`
        32-byte Merkle root.

    """
    if limit is None:
        size = _next_power_of_two(max(len(chunks), 1))
    else:
        size = _next_power_of_two(max(limit, 1))

    padded: List[bytes] = list(chunks) + [b"\x00" * 32] * (size - len(chunks))

    while len(padded) > 1:
        padded = [
            _sha256_pair(padded[i], padded[i + 1])
            for i in range(0, len(padded), 2)
        ]

    return padded[0] if padded else b"\x00" * 32


def _mix_in_length(root: bytes, length: int) -> bytes:
    """Mix the element count into a Merkle root for variable-length types."""
    return _sha256_pair(root, length.to_bytes(32, "little"))


def _pack_bytes(data: bytes) -> List[bytes]:
    """Split arbitrary bytes into 32-byte chunks, zero-padding the last."""
    if not data:
        return []
    chunks = []
    for i in range(0, len(data), 32):
        chunk = data[i : i + 32]
        if len(chunk) < 32:
            chunk = chunk + b"\x00" * (32 - len(chunk))
        chunks.append(chunk)
    return chunks


def _htr_uint256(value: int) -> bytes:
    """
    Return hash_tree_root of a uint256.

    The root is the 32-byte little-endian encoding of the value.
    """
    return value.to_bytes(32, "little")


def _htr_address(address: bytes) -> bytes:
    """
    Return hash_tree_root of a 20-byte Ethereum address.

    Right-pads to 32 bytes: ``address || 0x00 * 12``.
    """
    if len(address) != 20:
        raise ValueError(f"expected 20-byte address, got {len(address)}")
    return address + b"\x00" * 12


def _htr_byte_list(data: bytes, max_length: int) -> bytes:
    """
    Return hash_tree_root of a SSZ ByteList[max_length].

    Parameters
    ----------
    data :
        Variable-length byte content.
    max_length :
        Maximum number of bytes the list may contain.

    Returns
    -------
    root : `bytes`
        32-byte hash tree root with length mixed in.

    """
    chunks = _pack_bytes(data)
    chunk_limit = math.ceil(max_length / 32)
    raw_root = merkleize(chunks, limit=chunk_limit)
    return _mix_in_length(raw_root, len(data))


def hash_tree_root_reveal_commitment_preimage(
    chain_id: int,
    ticket_from: bytes,
    ticket_nonce: int,
    plaintext_tx: bytes,
    max_bytes_per_st: int,
) -> Bytes32:
    """
    Return the SSZ hash_tree_root of a RevealCommitmentPreimage container.

    The container has four fields in order:

    - chain_id        : uint256
    - ticket_from     : Address (20 bytes)
    - ticket_nonce    : uint256
    - plaintext_tx    : ByteList[max_bytes_per_st]

    Parameters
    ----------
    chain_id :
        Network chain identifier.
    ticket_from :
        20-byte sender address recovered from the sealed ticket signature.
    ticket_nonce :
        Nonce value from the sealed ticket transaction.
    plaintext_tx :
        Raw bytes of the decrypted EIP-1559 transaction.
    max_bytes_per_st :
        Maximum byte length of a sealed transaction payload
        (``MAX_BYTES_PER_ST`` from the LUCID specification).

    Returns
    -------
    root : `Bytes32`
        32-byte SSZ hash tree root.

    """
    field_roots = [
        _htr_uint256(chain_id),
        _htr_address(ticket_from),
        _htr_uint256(ticket_nonce),
        _htr_byte_list(plaintext_tx, max_bytes_per_st),
    ]
    return Bytes32(merkleize(field_roots))
