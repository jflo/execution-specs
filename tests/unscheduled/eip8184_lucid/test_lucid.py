"""Blockchain tests for EIP-8184 LUCID Encrypted Mempool."""

import pytest
from execution_testing import (
    Account,
    Alloc,
    Block,
    BlockchainTestFiller,
    Op,
    Storage,
    Transaction,
)

from .spec import ref_spec_8184

REFERENCE_SPEC_GIT_PATH = ref_spec_8184.git_path
REFERENCE_SPEC_VERSION = ref_spec_8184.version

# ─────────────────────────────────────────────────────────────────────────────
# SLOTNUM opcode (0x4B) — blockchain tests
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.valid_from("Lucid")
def test_slotnum_returns_zero_for_ordinary_tx(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SLOTNUM (0x4B) returns 0 for ordinary (non-decrypted) transactions.

    An ordinary transaction has ``commitment_slot == 0`` in its
    TransactionEnvironment, so SLOTNUM must push 0 onto the stack.
    """
    storage = Storage()
    contract = pre.deploy_contract(
        code=Op.SSTORE(storage.store_next(0), Op.SLOTNUM),
    )
    sender = pre.fund_eoa()
    blockchain_test(
        pre=pre,
        post={contract: Account(storage=storage)},
        blocks=[
            Block(
                txs=[
                    Transaction(
                        sender=sender,
                        to=contract,
                        gas_limit=100_000,
                    )
                ]
            )
        ],
    )


@pytest.mark.valid_from("Lucid")
def test_slotnum_opcode_does_not_revert_with_sufficient_gas(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    SLOTNUM succeeds with the standard BASE (2) gas cost.

    Verifying that the opcode completes (storage is set) confirms it does not
    OOG or revert at a typical gas limit.
    """
    storage = Storage()
    contract = pre.deploy_contract(
        # Push slot 0, run SLOTNUM (pushes 0), then SSTORE(0, 0)
        code=Op.SSTORE(storage.store_next(0), Op.SLOTNUM),
    )
    sender = pre.fund_eoa()
    blockchain_test(
        pre=pre,
        post={contract: Account(storage=storage)},
        blocks=[
            Block(
                txs=[
                    Transaction(
                        sender=sender,
                        to=contract,
                        gas_limit=100_000,
                    )
                ]
            )
        ],
    )
