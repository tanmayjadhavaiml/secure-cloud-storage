"""
encryption.py - Cryptographic operations for Secure Cloud Storage.

Responsibilities:
- Master key parsing and validation (256-bit / 32 bytes).
- Per-file key derivation using HKDF-SHA256 with unique random salt.
- 1 MB file chunk segmentation and sequential reconstruction.
- AES-256-GCM chunk encryption with unique 12-byte nonces.
- AES-256-GCM chunk decryption with authentication tag verification.
"""

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Constants
CHUNK_SIZE = 1024 * 1024  # 1 MB chunk size
NONCE_SIZE = 12           # 12 bytes (96 bits) recommended for AES-GCM
SALT_SIZE = 16            # 16 bytes (128 bits) salt for HKDF
KEY_SIZE = 32             # 32 bytes (256 bits) for AES-256


def parse_master_key(master_key_hex: str) -> bytes:
    """
    Validates and converts a 64-character hexadecimal master key string into 32 bytes.
    Raises ValueError if invalid.
    """
    cleaned = master_key_hex.strip()
    try:
        key_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(
            "Master key must be a valid 64-character hexadecimal string."
        ) from e

    if len(key_bytes) != KEY_SIZE:
        raise ValueError(
            f"Master key must be exactly 32 bytes (256 bits). Received {len(key_bytes)} bytes."
        )
    return key_bytes


def generate_salt(length: int = SALT_SIZE) -> bytes:
    """Generates cryptographically secure random bytes for HKDF salt."""
    return os.urandom(length)


def derive_file_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derives a 256-bit encryption key specific to a file using HKDF-SHA256.
    Ensures that every file uses a distinct key derived from the master key and salt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=b"secure-cloud-storage-file-key",
    )
    return hkdf.derive(master_key)


def split_file_into_chunks(file_bytes: bytes, chunk_size: int = CHUNK_SIZE) -> list[bytes]:
    """
    Divides file bytes into sequential chunks of chunk_size (default 1 MB).
    Returns an empty list for empty files (0 bytes).
    """
    if not file_bytes:
        return []
    return [file_bytes[i:i + chunk_size] for i in range(0, len(file_bytes), chunk_size)]


def encrypt_chunk(chunk_bytes: bytes, file_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a single chunk using AES-256-GCM with a unique 12-byte nonce.
    Returns:
        tuple (nonce_bytes, ciphertext_with_tag)
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, chunk_bytes, None)
    return nonce, ciphertext


def decrypt_chunk(ciphertext: bytes, nonce: bytes, file_key: bytes) -> bytes:
    """
    Decrypts a single chunk using AES-256-GCM and verifies the authentication tag.
    Raises InvalidTag if data/tag is modified, corrupted, or if the key is incorrect.
    """
    aesgcm = AESGCM(file_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def reconstruct_file(decrypted_chunks: list[bytes]) -> bytes:
    """
    Reconstructs the original file bytes by concatenating decrypted chunks in sequential order.
    """
    return b"".join(decrypted_chunks)
