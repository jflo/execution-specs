"""
Exceptions specific to this fork.
"""

from typing import TYPE_CHECKING, Final

from ethereum_types.numeric import Uint

from ethereum.exceptions import InvalidBlock, InvalidTransaction

if TYPE_CHECKING:
    from .transactions import Transaction


class TransactionTypeError(InvalidTransaction):
    """
    Unknown [EIP-2718] transaction type byte.

    [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    """

    transaction_type: Final[int]
    """
    The type byte of the transaction that caused the error.
    """

    def __init__(self, transaction_type: int):
        super().__init__(f"unknown transaction type `{transaction_type}`")
        self.transaction_type = transaction_type


class TransactionTypeContractCreationError(InvalidTransaction):
    """
    Contract creation is not allowed for a transaction type.
    """

    transaction: "Transaction"
    """
    The transaction that caused the error.
    """

    def __init__(self, transaction: "Transaction"):
        super().__init__(
            f"transaction type `{type(transaction).__name__}` not allowed to "
            "create contracts"
        )
        self.transaction = transaction


class BlobGasLimitExceededError(InvalidTransaction):
    """
    The blob gas limit for the transaction exceeds the maximum allowed.
    """


class InsufficientMaxFeePerBlobGasError(InvalidTransaction):
    """
    The maximum fee per blob gas is insufficient for the transaction.
    """


class InsufficientMaxFeePerGasError(InvalidTransaction):
    """
    The maximum fee per gas is insufficient for the transaction.
    """

    transaction_max_fee_per_gas: Final[Uint]
    """
    The maximum fee per gas specified in the transaction.
    """

    block_base_fee_per_gas: Final[Uint]
    """
    The base fee per gas of the block in which the transaction is included.
    """

    def __init__(
        self, transaction_max_fee_per_gas: Uint, block_base_fee_per_gas: Uint
    ):
        super().__init__(
            f"Insufficient max fee per gas "
            f"({transaction_max_fee_per_gas} < {block_base_fee_per_gas})"
        )
        self.transaction_max_fee_per_gas = transaction_max_fee_per_gas
        self.block_base_fee_per_gas = block_base_fee_per_gas


class InvalidBlobVersionedHashError(InvalidTransaction):
    """
    The versioned hash of the blob is invalid.
    """


class NoBlobDataError(InvalidTransaction):
    """
    The transaction does not contain any blob data.
    """


class BlobCountExceededError(InvalidTransaction):
    """
    The transaction has more blobs than the limit.
    """


class PriorityFeeGreaterThanMaxFeeError(InvalidTransaction):
    """
    The priority fee is greater than the maximum fee per gas.
    """


class EmptyAuthorizationListError(InvalidTransaction):
    """
    The authorization list in the transaction is empty.
    """


class InitCodeTooLargeError(InvalidTransaction):
    """
    The init code of the transaction is too large.
    """


class TransactionGasLimitExceededError(InvalidTransaction):
    """
    The transaction has specified a gas limit that is greater than the allowed
    maximum.

    Note that this is _not_ the exception thrown when bytecode execution runs
    out of gas.
    """


class BlockAccessListGasLimitExceededError(InvalidBlock):
    """
    The block access list exceeds the gas limit constraint.

    Introduced in [EIP-7928].

    [EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928
    """


class InvalidSealedTicketSignatureIdError(InvalidTransaction):
    """
    The sealed ticket transaction carries an unsupported signature identifier.

    Only ``signature_id == 0x01`` (ECDSA) is currently valid per [EIP-8184].

    [EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
    """


class SealedTicketDecryptionError(InvalidBlock):
    """
    Decryption or commitment-binding validation failed for a sealed ticket.

    Any of the following constitutes a decryption failure:

    - AEAD authentication tag mismatch (wrong key or tampered ciphertext).
    - ``ciphertext_hash`` does not match ``keccak256(ciphertext_envelope)``.
    - ``key_commitment`` does not match ``keccak256(k_dem)``.
    - ``reveal_commitment`` does not match the SSZ hash_tree_root of the
      RevealCommitmentPreimage.
    - The decrypted plaintext violates the zero-fee or gas-limit constraints.

    Introduced in [EIP-8184].

    [EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
    """


class SealedTicketOrderingError(InvalidBlock):
    """
    Sealed-transaction commitments are not in the required order.

    Commitments must be ordered by descending ``tob_fee``, then descending
    ``gas_obligation``, then ascending ``commitment_root``.

    Introduced in [EIP-8184].

    [EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
    """


class SealedTicketFeeError(InvalidBlock):
    """
    Fee validation failed for a sealed ticket commitment.

    Raised when ``max_fee < base_fee + key_publication_fee``, or when the
    sender has insufficient balance to cover the ticket fee.

    Introduced in [EIP-8184].

    [EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
    """
