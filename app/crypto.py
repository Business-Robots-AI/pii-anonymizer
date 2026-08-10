"""
Encryption utilities for PII data protection.
Uses AES-256-CBC with PKCS7 padding.

Encrypted format: base64(IV_16bytes + AES256_ciphertext)
Key: SHA-256 hash of PII_ENCRYPTION_KEY env var (produces 32-byte / 256-bit key)
"""
import os
import base64
import hashlib
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# AES block size in bits/bytes
AES_BLOCK_BITS = 128
AES_BLOCK_BYTES = AES_BLOCK_BITS // 8  # 16 bytes
AES_KEY_BITS = 256
AES_KEY_BYTES = AES_KEY_BITS // 8  # 32 bytes


def _get_key() -> bytes:
    """Derive a 32-byte (256-bit) AES key from the environment variable."""
    raw = os.getenv("PII_ENCRYPTION_KEY", "")
    if not raw:
        # The placeholder is kept so data written by an earlier misconfigured run
        # stays decryptable — but it is public knowledge, so anything encrypted
        # under it must be treated as plaintext until the key is set and rotated.
        raw = "default-change-me-in-production-32!"
        logger.error(
            "PII_ENCRYPTION_KEY is not set — falling back to a publicly known key. "
            "Stored PII is NOT protected. Set the variable and re-encrypt."
        )
    return hashlib.sha256(raw.encode()).digest()  # 32 bytes = 256 bits


_aes_key = _get_key()


def encrypt_value(plaintext: str) -> str:
    """
    Encrypt a string with AES-256-CBC.
    Returns base64-encoded string: base64(IV + ciphertext).
    """
    iv = os.urandom(AES_BLOCK_BYTES)  # 16-byte random IV

    # PKCS7 padding
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # AES-256-CBC encryption
    cipher = Cipher(algorithms.AES(_aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return base64(IV + ciphertext) as string for DB storage
    return base64.b64encode(iv + ciphertext).decode("ascii")


def decrypt_value(encrypted: str | bytes) -> str:
    """
    Decrypt an AES-256-CBC encrypted value.
    Accepts base64-encoded string or bytes: base64(IV + ciphertext).
    """
    if isinstance(encrypted, memoryview):
        encrypted = bytes(encrypted)
    if isinstance(encrypted, bytes):
        encrypted = encrypted.decode("ascii")

    raw = base64.b64decode(encrypted)
    iv = raw[:AES_BLOCK_BYTES]
    ciphertext = raw[AES_BLOCK_BYTES:]

    # AES-256-CBC decryption
    cipher = Cipher(algorithms.AES(_aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode("utf-8")


def is_encrypted(value: str) -> bool:
    """Check if a value looks like it's AES-256 encrypted (base64 with IV prefix)."""
    if not value or len(value) < 44:  # min base64 length for 16-byte IV + 16-byte block
        return False
    try:
        raw = base64.b64decode(value)
        # Must be at least IV (16) + one AES block (16) = 32 bytes
        # And total length must be IV + multiple of block size
        return len(raw) >= 32 and (len(raw) - AES_BLOCK_BYTES) % AES_BLOCK_BYTES == 0
    except Exception:
        return False


def safe_decrypt(value) -> str:
    """Decrypt if encrypted, return as-is if plaintext (for migration period).
    Handles str, bytes, and memoryview inputs."""
    if not value:
        return value if isinstance(value, str) else ""
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except Exception:
            return ""
    if is_encrypted(value):
        try:
            return decrypt_value(value)
        except Exception:
            return value  # corrupted or wrong key format
    return value  # plaintext legacy data