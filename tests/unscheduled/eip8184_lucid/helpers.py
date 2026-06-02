"""Helpers for building sealed ticket execution contexts in EIP-8184 tests."""

import os
from dataclasses import dataclass
from typing import Optional, cast

from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305 as _ChaCha20Poly1305,
)
from ethereum_types.bytes import Bytes, Bytes32
from ethereum_types.numeric import U64, Uint

from ethereum.crypto.hash import keccak256
from ethereum.crypto.ssz import hash_tree_root_reveal_commitment_preimage
from ethereum.forks.lucid.fork import (
    MAX_BYTES_PER_ST,
    SealedTransactionContext,
)
from ethereum.forks.lucid.transactions import (
    FeeMarketTransaction,
    SealedTicketTransaction,
    encode_transaction,
)
from ethereum.state import Address


@dataclass
class SealedTicketParams:
    """
    Parameters for constructing a SealedTicketTransaction and its decryption
    context.

    Provides a single place to control all fee and commitment values so that
    tests can vary only the knobs under test.
    """

    sender: Address
    """Ticket sender (recovered from ECDSA signature)."""

    plaintext_tx: FeeMarketTransaction
    """Decrypted EIP-1559 transaction (max_fee == max_priority_fee == 0)."""

    chain_id: int = 1
    nonce: int = 0
    max_priority_fee_per_gas: int = 0
    max_fee_per_gas: int = 10**9
    max_tob_fee: int = 0
    max_preceding_commitments: int = 0
    key_publication_fee: int = 0
    key_publication_fee_recipient: Optional[Address] = None
    commitment_slot: int = 1
    commitment_index: int = 0


def _chacha20_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """Encrypt plaintext with ChaCha20-Poly1305; return ciphertext+tag."""
    cipher = _ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, plaintext, aad)


def build_sealed_ticket_context(
    params: SealedTicketParams,
    *,
    key_publisher: Optional[Address] = None,
) -> SealedTransactionContext:
    """
    Build a fully-validated SealedTransactionContext from high-level params.

    Derives all commitment hashes and encrypts the plaintext transaction so
    that ``validate_sealed_transaction_context`` will accept the result.

    Parameters
    ----------
    params :
        High-level parameters for the sealed ticket.
    key_publisher :
        Address of the key publisher.  Defaults to the sender address.

    Returns
    -------
    ctx : SealedTransactionContext
        A context ready for use in state/blockchain tests.

    """
    if key_publisher is None:
        key_publisher = params.sender
    kpf_recipient = (
        params.key_publication_fee_recipient
        if params.key_publication_fee_recipient is not None
        else params.sender
    )

    # Generate a random k_dem and nonce.
    k_dem = Bytes32(os.urandom(32))
    nonce_bytes = os.urandom(12)

    # Encode the plaintext transaction.
    # FeeMarketTransaction always encodes to Bytes (not LegacyTransaction).
    plaintext_bytes = bytes(
        cast(Bytes, encode_transaction(params.plaintext_tx))
    )

    # Compute the SSZ reveal commitment.
    reveal_commitment = hash_tree_root_reveal_commitment_preimage(
        chain_id=params.chain_id,
        ticket_from=bytes(params.sender),
        ticket_nonce=params.nonce,
        plaintext_tx=plaintext_bytes,
        max_bytes_per_st=int(MAX_BYTES_PER_ST),
    )

    # Encrypt: ciphertext_envelope = nonce || encrypt(k_dem, nonce, plaintext,
    #          aad=reveal_commitment)
    ciphertext_with_tag = _chacha20_encrypt(
        bytes(k_dem),
        nonce_bytes,
        plaintext_bytes,
        bytes(reveal_commitment),
    )
    ciphertext_envelope = Bytes(nonce_bytes + ciphertext_with_tag)

    # Derive commitment hashes.
    key_commitment = keccak256(k_dem)
    ciphertext_hash = keccak256(ciphertext_envelope)

    # Build a minimal (unsigned) SealedTicketTransaction.
    # In tests we supply the sender directly so signature recovery is not used.
    ticket = SealedTicketTransaction(
        chain_id=U64(params.chain_id),
        nonce=params.plaintext_tx.nonce,
        max_priority_fee_per_gas=Uint(params.max_priority_fee_per_gas),
        max_fee_per_gas=Uint(params.max_fee_per_gas),
        gas_limit=Uint(params.plaintext_tx.gas),
        max_tob_fee=Uint(params.max_tob_fee),
        max_preceding_commitments=U64(params.max_preceding_commitments),
        key_publisher=key_publisher,
        key_publication_fee_recipient=kpf_recipient,
        key_publication_fee=Uint(params.key_publication_fee),
        key_commitment=key_commitment,
        reveal_commitment=reveal_commitment,
        ciphertext_hash=ciphertext_hash,
        # Signature fields — not used for ordering or commitment checks,
        # only for recovering the sender in the full pipeline. Tests supply
        # ticket_sender directly, so we use a placeholder.
        signature_id=U64(1),
        signature=Bytes(b"\x00" * 65),
    )

    return SealedTransactionContext(
        ticket=ticket,
        ticket_sender=params.sender,
        plaintext_tx=params.plaintext_tx,
        ciphertext_envelope=ciphertext_envelope,
        k_dem=k_dem,
        commitment_slot=U64(params.commitment_slot),
        commitment_index=Uint(params.commitment_index),
    )
