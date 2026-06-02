"""
Ethereum Types.

.. contents:: Table of Contents
    :backlinks: none
    :local:

Introduction
------------

Types reused throughout the specification, which are specific to Ethereum.
"""

from dataclasses import dataclass
from typing import Tuple

from ethereum_rlp import rlp
from ethereum_types.bytes import Bytes, Bytes256
from ethereum_types.frozen import slotted_freezable
from ethereum_types.numeric import U8, U64, U256, Uint

from ethereum.crypto.hash import Hash32
from ethereum.state import Account, Address

VersionedHash = Hash32

Bloom = Bytes256


def encode_account(raw_account_data: Account, storage_root: Bytes) -> Bytes:
    """
    Encode `Account` dataclass.

    Storage is not stored in the `Account` dataclass, so `Accounts` cannot be
    encoded without providing a storage root.
    """
    return rlp.encode(
        (
            raw_account_data.nonce,
            raw_account_data.balance,
            storage_root,
            raw_account_data.code_hash,
        )
    )


@slotted_freezable
@dataclass
class Authorization:
    """
    The authorization for a set code transaction.
    """

    chain_id: U256
    address: Address
    nonce: U64
    y_parity: U8
    r: U256
    s: U256


@slotted_freezable
@dataclass
class STCommitment:
    """
    Sealed-transaction commitment included in a scheduling execution payload.

    Introduced in [EIP-8184].

    [EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
    """

    commitment_root: Hash32
    """
    keccak256 of the sealed ticket bytes (single ST) or the bundle root
    (keccak256 over each ticket's keccak256 hash in order).
    """

    commitment_key: Hash32
    """
    keccak256(k_dem) for a single ST, or
    keccak256(keccak256(k_dems[0]) || ... || keccak256(k_dems[n])) for a
    bundle.  Only executable members contribute.
    """

    gas_obligation: Uint
    """
    Aggregate gas_limit of all executable sealed transactions in this
    commitment.
    """

    executable: Bytes
    """
    Bitfield indicating which bundle members are executable.  Empty for
    single-ST commitments.
    """


@slotted_freezable
@dataclass
class KeyMessage:
    """
    Decryption key material for one sealed-transaction commitment.

    Provided by the key publisher after the commitment deadline.  Modelled
    here as test-supplied input; the CL dissemination mechanism is out of
    scope for execution-specs.

    Introduced in [EIP-8184].

    [EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
    """

    chain_id: U256
    """Chain identifier binding the key to the correct network."""

    scheduling_beacon_block_root: Hash32
    """Root of the beacon block that contained the ST commitment."""

    scheduling_slot: U64
    """Slot number of the block that contained the ST commitment."""

    commit_index: U8
    """Index of the commitment within the scheduling block's IL."""

    k_dems: Tuple[Hash32, ...]
    """
    Per-ST decryption keys.  Length is 1 for single STs; for bundles it
    equals the number of executable members.
    """
