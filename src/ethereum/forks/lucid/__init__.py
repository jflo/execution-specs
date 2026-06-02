"""
The Lucid fork ([EIP-8184]) adds the LUCID encrypted mempool protocol.

### Changes

- [EIP-8184: LUCID Encrypted Mempool][EIP-8184]

### Releases

[EIP-8184]: https://eips.ethereum.org/EIPS/eip-8184
"""

from ethereum.fork_criteria import ForkCriteria, Unscheduled

FORK_CRITERIA: ForkCriteria = Unscheduled(order_index=4)
