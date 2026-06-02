"""Reference spec for [EIP-8184: LUCID](https://eips.ethereum.org/EIPS/eip-8184)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReferenceSpec:
    """Reference specification."""

    git_path: str
    version: str


ref_spec_8184 = ReferenceSpec(
    git_path="EIPS/eip-8184.md",
    version="0000000000000000000000000000000000000000",
)


@dataclass(frozen=True)
class Spec:
    """Constants and parameters from EIP-8184."""

    SEALED_TICKET_TX_TYPE = 0x05
    SLOTNUM_OPCODE = 0x4B
    TOB_GAS_FRACTION_DENOMINATOR = 8
    TOB_FEE_FRACTION = 128
