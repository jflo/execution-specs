"""
ChaCha20-Poly1305 Authenticated Encryption with Associated Data.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305 as _ChaCha20Poly1305,
)
from ethereum_types.bytes import Bytes, Bytes32


class AEADDecryptionError(Exception):
    """
    Raised when ChaCha20-Poly1305 authentication verification fails.

    Indicates that the ciphertext was tampered with or the wrong key was used.
    """


def chacha20poly1305_decrypt(
    key: Bytes32,
    nonce: bytes,
    ciphertext_with_tag: Bytes,
    associated_data: Bytes = b"",
) -> Bytes:
    """
    Decrypt and authenticate a ChaCha20-Poly1305 ciphertext.

    Parameters
    ----------
    key :
        32-byte symmetric decryption key (k_dem).
    nonce :
        12-byte nonce. The same nonce must never be reused with the same key.
    ciphertext_with_tag :
        Concatenation of ciphertext bytes and the 16-byte Poly1305 auth tag.
    associated_data :
        Additional data authenticated but not encrypted. Defaults to empty.

    Returns
    -------
    plaintext : `Bytes`
        The decrypted plaintext bytes.

    Raises
    ------
    AEADDecryptionError
        If authentication fails (tampered ciphertext or wrong key).

    """
    try:
        cipher = _ChaCha20Poly1305(bytes(key))
        return Bytes(
            cipher.decrypt(
                nonce,
                bytes(ciphertext_with_tag),
                bytes(associated_data),
            )
        )
    except InvalidTag as e:
        raise AEADDecryptionError(
            "ChaCha20-Poly1305 authentication failed"
        ) from e
