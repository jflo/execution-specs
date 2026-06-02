"""Unit tests for EIP-8184 LUCID — run with plain pytest, not fill."""

import os

import pytest
from ethereum_types.bytes import Bytes, Bytes20, Bytes32
from ethereum_types.numeric import U64, U256, Uint

from ethereum.forks.lucid.exceptions import (
    SealedTicketDecryptionError,
    SealedTicketFeeError,
)
from ethereum.forks.lucid.fork import (
    SealedTransactionContext,
    check_sealed_ticket_ordering,
    compute_effective_tob_fee,
    validate_sealed_transaction_context,
)
from ethereum.forks.lucid.transactions import (
    FeeMarketTransaction,
    SealedTicketTransaction,
)
from ethereum.state import Address

from .helpers import SealedTicketParams, build_sealed_ticket_context

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_ticket(
    *,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
    max_tob_fee: int,
    gas_limit: int = 100_000,
) -> SealedTicketTransaction:
    """Construct a minimal SealedTicketTransaction for fee calculations."""
    return SealedTicketTransaction(
        chain_id=U64(1),
        nonce=U256(0),
        max_priority_fee_per_gas=Uint(max_priority_fee_per_gas),
        max_fee_per_gas=Uint(max_fee_per_gas),
        gas_limit=Uint(gas_limit),
        max_tob_fee=Uint(max_tob_fee),
        max_preceding_commitments=U64(0),
        key_publisher=Bytes20(b"\x00" * 20),
        key_publication_fee_recipient=Bytes20(b"\x00" * 20),
        key_publication_fee=Uint(0),
        key_commitment=Bytes32(b"\x00" * 32),
        reveal_commitment=Bytes32(b"\x00" * 32),
        ciphertext_hash=Bytes32(b"\x00" * 32),
        signature_id=U64(1),
        signature=Bytes(b"\x00" * 65),
    )


def _make_ctx_for_ordering(
    *,
    max_fee_per_gas: int,
    max_tob_fee: int,
    gas_limit: int,
    reveal_commitment_byte: int,
) -> SealedTransactionContext:
    """Return a minimal SealedTransactionContext for ordering tests."""
    ticket = _make_ticket(
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=0,
        max_tob_fee=max_tob_fee,
        gas_limit=gas_limit,
    )
    ticket = SealedTicketTransaction(
        chain_id=ticket.chain_id,
        nonce=ticket.nonce,
        max_priority_fee_per_gas=ticket.max_priority_fee_per_gas,
        max_fee_per_gas=ticket.max_fee_per_gas,
        gas_limit=ticket.gas_limit,
        max_tob_fee=ticket.max_tob_fee,
        max_preceding_commitments=ticket.max_preceding_commitments,
        key_publisher=ticket.key_publisher,
        key_publication_fee_recipient=ticket.key_publication_fee_recipient,
        key_publication_fee=ticket.key_publication_fee,
        key_commitment=ticket.key_commitment,
        reveal_commitment=Bytes32(
            bytes([reveal_commitment_byte]) + b"\x00" * 31
        ),
        ciphertext_hash=ticket.ciphertext_hash,
        signature_id=ticket.signature_id,
        signature=ticket.signature,
    )
    plaintext_tx = FeeMarketTransaction(
        chain_id=U64(1),
        nonce=U256(0),
        max_priority_fee_per_gas=Uint(0),
        max_fee_per_gas=Uint(0),
        gas=Uint(gas_limit),
        to=Bytes20(b"\x00" * 20),
        value=U256(0),
        data=Bytes(b""),
        access_list=(),
        y_parity=U256(0),
        r=U256(1),
        s=U256(1),
    )
    return SealedTransactionContext(
        ticket=ticket,
        ticket_sender=Address(b"\x00" * 20),
        plaintext_tx=plaintext_tx,
        ciphertext_envelope=Bytes(b"\x00" * 13),
        k_dem=Bytes32(b"\x00" * 32),
        commitment_slot=U64(1),
        commitment_index=Uint(0),
    )


def _make_plaintext_tx(
    *,
    recipient: Bytes20,
    gas_limit: int = 21_000,
    chain_id: int = 1,
    nonce: int = 0,
) -> FeeMarketTransaction:
    """Construct a valid LUCID plaintext FeeMarketTransaction."""
    return FeeMarketTransaction(
        chain_id=U64(chain_id),
        nonce=U256(nonce),
        max_priority_fee_per_gas=Uint(0),
        max_fee_per_gas=Uint(0),
        gas=Uint(gas_limit),
        to=recipient,
        value=U256(0),
        data=Bytes(b""),
        access_list=(),
        y_parity=U256(0),
        r=U256(1),
        s=U256(1),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests: compute_effective_tob_fee
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    (
        "max_fee",
        "max_priority",
        "max_tob",
        "gas_limit",
        "base_fee",
        "expected",
    ),
    [
        pytest.param(
            10**9,
            0,
            0,
            100_000,
            10**9 - 1,
            0,
            id="zero_tob_when_max_tob_is_zero",
        ),
        pytest.param(
            10**9,
            0,
            5 * 10**8,
            100_000,
            0,
            5 * 10**8,
            id="tob_capped_by_max_tob_fee",
        ),
        pytest.param(
            10**9,
            0,
            10**18,
            100_000,
            0,
            10**9 * 100_000,
            id="tob_bounded_by_headroom_times_gas",
        ),
        pytest.param(
            100,
            0,
            10**18,
            100_000,
            200,
            0,
            id="zero_when_max_fee_below_base_fee",
        ),
        pytest.param(
            10**9,
            10**9,
            10**18,
            100_000,
            0,
            0,
            id="zero_tob_when_priority_consumes_all_headroom",
        ),
    ],
)
def test_compute_effective_tob_fee(
    max_fee: int,
    max_priority: int,
    max_tob: int,
    gas_limit: int,
    base_fee: int,
    expected: int,
) -> None:
    """compute_effective_tob_fee matches hand-computed expected values."""
    ticket = _make_ticket(
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=max_priority,
        max_tob_fee=max_tob,
        gas_limit=gas_limit,
    )
    result = compute_effective_tob_fee(ticket, Uint(base_fee))
    assert int(result) == expected


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests: check_sealed_ticket_ordering
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("contexts_spec", "base_fee", "expected_valid"),
    [
        pytest.param(
            [],
            0,
            True,
            id="empty_list_is_valid",
        ),
        pytest.param(
            [
                {
                    "max_fee": 10**9,
                    "max_tob": 5 * 10**8,
                    "gas": 100_000,
                    "rc": 0,
                }
            ],
            0,
            True,
            id="single_context_is_valid",
        ),
        pytest.param(
            [
                {
                    "max_fee": 10**9,
                    "max_tob": 5 * 10**8,
                    "gas": 100_000,
                    "rc": 0,
                },
                {
                    "max_fee": 10**9,
                    "max_tob": 1 * 10**8,
                    "gas": 100_000,
                    "rc": 1,
                },
            ],
            0,
            True,
            id="descending_tob_fee_is_valid",
        ),
        pytest.param(
            [
                {
                    "max_fee": 10**9,
                    "max_tob": 1 * 10**8,
                    "gas": 100_000,
                    "rc": 0,
                },
                {
                    "max_fee": 10**9,
                    "max_tob": 5 * 10**8,
                    "gas": 100_000,
                    "rc": 1,
                },
            ],
            0,
            False,
            id="ascending_tob_fee_is_invalid",
        ),
        pytest.param(
            [
                {"max_fee": 10**9, "max_tob": 0, "gas": 200_000, "rc": 0},
                {"max_fee": 10**9, "max_tob": 0, "gas": 100_000, "rc": 1},
            ],
            0,
            True,
            id="equal_tob_descending_gas_is_valid",
        ),
        pytest.param(
            [
                {"max_fee": 10**9, "max_tob": 0, "gas": 100_000, "rc": 0x00},
                {"max_fee": 10**9, "max_tob": 0, "gas": 100_000, "rc": 0x01},
            ],
            0,
            True,
            id="equal_tob_equal_gas_ascending_rc_is_valid",
        ),
        pytest.param(
            [
                {"max_fee": 10**9, "max_tob": 0, "gas": 100_000, "rc": 0x01},
                {"max_fee": 10**9, "max_tob": 0, "gas": 100_000, "rc": 0x00},
            ],
            0,
            False,
            id="equal_tob_equal_gas_descending_rc_is_invalid",
        ),
    ],
)
def test_check_sealed_ticket_ordering(
    contexts_spec: list,
    base_fee: int,
    expected_valid: bool,
) -> None:
    """check_sealed_ticket_ordering matches expected validity."""
    contexts = tuple(
        _make_ctx_for_ordering(
            max_fee_per_gas=spec["max_fee"],
            max_tob_fee=spec["max_tob"],
            gas_limit=spec["gas"],
            reveal_commitment_byte=spec["rc"],
        )
        for spec in contexts_spec
    )
    result = check_sealed_ticket_ordering(contexts, Uint(base_fee))
    assert result == expected_valid


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests: validate_sealed_transaction_context
# ─────────────────────────────────────────────────────────────────────────────


def test_validate_sealed_transaction_context_valid() -> None:
    """
    validate_sealed_transaction_context accepts a correctly-formed context.
    """
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))
    plaintext_tx = _make_plaintext_tx(recipient=recipient)

    params = SealedTicketParams(
        sender=sender,
        plaintext_tx=plaintext_tx,
        max_fee_per_gas=10**9,
    )
    ctx = build_sealed_ticket_context(params)

    # Should not raise.
    validate_sealed_transaction_context(
        ctx,
        chain_id=U64(1),
        base_fee_per_gas=Uint(10**9 // 2),
    )


def test_validate_ciphertext_hash_mismatch_raises() -> None:
    """A tampered ciphertext_envelope raises SealedTicketDecryptionError."""
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))
    plaintext_tx = _make_plaintext_tx(recipient=recipient)

    ctx = build_sealed_ticket_context(
        SealedTicketParams(
            sender=sender,
            plaintext_tx=plaintext_tx,
            max_fee_per_gas=10**9,
        )
    )

    tampered_envelope = Bytes(bytes(ctx.ciphertext_envelope)[:-1] + b"\xff")
    bad_ctx = SealedTransactionContext(
        ticket=ctx.ticket,
        ticket_sender=ctx.ticket_sender,
        plaintext_tx=ctx.plaintext_tx,
        ciphertext_envelope=tampered_envelope,
        k_dem=ctx.k_dem,
        commitment_slot=ctx.commitment_slot,
        commitment_index=ctx.commitment_index,
    )

    with pytest.raises(
        SealedTicketDecryptionError, match="ciphertext_hash mismatch"
    ):
        validate_sealed_transaction_context(
            bad_ctx,
            chain_id=U64(1),
            base_fee_per_gas=Uint(0),
        )


def test_validate_key_commitment_mismatch_raises() -> None:
    """A wrong k_dem raises SealedTicketDecryptionError."""
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))
    plaintext_tx = _make_plaintext_tx(recipient=recipient)

    ctx = build_sealed_ticket_context(
        SealedTicketParams(
            sender=sender,
            plaintext_tx=plaintext_tx,
            max_fee_per_gas=10**9,
        )
    )

    wrong_k_dem = Bytes32(os.urandom(32))
    bad_ctx = SealedTransactionContext(
        ticket=ctx.ticket,
        ticket_sender=ctx.ticket_sender,
        plaintext_tx=ctx.plaintext_tx,
        ciphertext_envelope=ctx.ciphertext_envelope,
        k_dem=wrong_k_dem,
        commitment_slot=ctx.commitment_slot,
        commitment_index=ctx.commitment_index,
    )

    with pytest.raises(
        SealedTicketDecryptionError, match="key_commitment mismatch"
    ):
        validate_sealed_transaction_context(
            bad_ctx,
            chain_id=U64(1),
            base_fee_per_gas=Uint(0),
        )


def test_validate_max_fee_below_base_fee_raises() -> None:
    """A ticket with max_fee_per_gas < base_fee raises SealedTicketFeeError."""
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))
    plaintext_tx = _make_plaintext_tx(recipient=recipient)

    ctx = build_sealed_ticket_context(
        SealedTicketParams(
            sender=sender,
            plaintext_tx=plaintext_tx,
            max_fee_per_gas=10**9,
        )
    )

    with pytest.raises(SealedTicketFeeError, match="max_fee_per_gas below"):
        validate_sealed_transaction_context(
            ctx,
            chain_id=U64(1),
            base_fee_per_gas=Uint(2 * 10**9),
        )


def test_validate_nonzero_plaintext_max_fee_raises() -> None:
    """
    A plaintext_tx with max_fee_per_gas != 0 raises
    SealedTicketDecryptionError.
    """
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))

    bad_plaintext = FeeMarketTransaction(
        chain_id=U64(1),
        nonce=U256(0),
        max_priority_fee_per_gas=Uint(0),
        max_fee_per_gas=Uint(1),  # violates LUCID zero-fee constraint
        gas=Uint(21_000),
        to=recipient,
        value=U256(0),
        data=Bytes(b""),
        access_list=(),
        y_parity=U256(0),
        r=U256(1),
        s=U256(1),
    )

    ctx = build_sealed_ticket_context(
        SealedTicketParams(
            sender=sender,
            plaintext_tx=bad_plaintext,
            max_fee_per_gas=10**9,
        )
    )

    with pytest.raises(
        SealedTicketDecryptionError,
        match="max_fee_per_gas must be zero",
    ):
        validate_sealed_transaction_context(
            ctx,
            chain_id=U64(1),
            base_fee_per_gas=Uint(0),
        )


def test_validate_gas_mismatch_raises() -> None:
    """
    A ticket whose gas_limit differs from the plaintext_tx gas raises
    SealedTicketDecryptionError.
    """
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))
    plaintext_tx = _make_plaintext_tx(recipient=recipient, gas_limit=21_000)

    ctx = build_sealed_ticket_context(
        SealedTicketParams(
            sender=sender,
            plaintext_tx=plaintext_tx,
            max_fee_per_gas=10**9,
        )
    )

    # Construct a ticket whose gas_limit disagrees with the plaintext_tx.
    mismatched_ticket = SealedTicketTransaction(
        chain_id=ctx.ticket.chain_id,
        nonce=ctx.ticket.nonce,
        max_priority_fee_per_gas=ctx.ticket.max_priority_fee_per_gas,
        max_fee_per_gas=ctx.ticket.max_fee_per_gas,
        gas_limit=Uint(50_000),  # plaintext_tx.gas == 21_000 → mismatch
        max_tob_fee=ctx.ticket.max_tob_fee,
        max_preceding_commitments=ctx.ticket.max_preceding_commitments,
        key_publisher=ctx.ticket.key_publisher,
        key_publication_fee_recipient=ctx.ticket.key_publication_fee_recipient,
        key_publication_fee=ctx.ticket.key_publication_fee,
        key_commitment=ctx.ticket.key_commitment,
        reveal_commitment=ctx.ticket.reveal_commitment,
        ciphertext_hash=ctx.ticket.ciphertext_hash,
        signature_id=ctx.ticket.signature_id,
        signature=ctx.ticket.signature,
    )
    bad_ctx = SealedTransactionContext(
        ticket=mismatched_ticket,
        ticket_sender=ctx.ticket_sender,
        plaintext_tx=ctx.plaintext_tx,
        ciphertext_envelope=ctx.ciphertext_envelope,
        k_dem=ctx.k_dem,
        commitment_slot=ctx.commitment_slot,
        commitment_index=ctx.commitment_index,
    )

    with pytest.raises(
        SealedTicketDecryptionError,
        match="gas must equal ticket.gas_limit",
    ):
        validate_sealed_transaction_context(
            bad_ctx,
            chain_id=U64(1),
            base_fee_per_gas=Uint(0),
        )


def test_validate_commitment_index_exceeds_max_raises() -> None:
    """
    A commitment_index > ticket.max_preceding_commitments raises
    SealedTicketDecryptionError.
    """
    sender = Address(os.urandom(20))
    recipient = Bytes20(os.urandom(20))
    plaintext_tx = _make_plaintext_tx(recipient=recipient)

    ctx = build_sealed_ticket_context(
        SealedTicketParams(
            sender=sender,
            plaintext_tx=plaintext_tx,
            max_fee_per_gas=10**9,
            max_preceding_commitments=0,
        )
    )

    bad_ctx = SealedTransactionContext(
        ticket=ctx.ticket,
        ticket_sender=ctx.ticket_sender,
        plaintext_tx=ctx.plaintext_tx,
        ciphertext_envelope=ctx.ciphertext_envelope,
        k_dem=ctx.k_dem,
        commitment_slot=ctx.commitment_slot,
        commitment_index=Uint(1),  # exceeds max_preceding_commitments == 0
    )

    with pytest.raises(
        SealedTicketDecryptionError,
        match="commitment_index exceeds max_preceding_commitments",
    ):
        validate_sealed_transaction_context(
            bad_ctx,
            chain_id=U64(1),
            base_fee_per_gas=Uint(0),
        )
