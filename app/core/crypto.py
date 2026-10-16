import json
import os
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings


def encrypt_vector(vector: List[float]) -> bytes:
    """
    Encrypts a keystroke dynamics feature vector using AES-256-GCM (RNF-01, CP-S10).

    Args:
        vector: A list of float numbers representing flight times, dwell times, etc.

    Returns:
        bytes: 12-byte random nonce prepended to the ciphertext (which includes
               the 16-byte authentication tag).
    """
    if not isinstance(vector, list) or not all(isinstance(x, (int, float)) for x in vector):
        raise ValueError("Vector must be a list of numeric values (floats).")

    # Serialize float vector to UTF-8 JSON bytes
    data_bytes = json.dumps(vector).encode("utf-8")

    # Generate a cryptographically secure 12-byte (96-bit) nonce
    nonce = os.urandom(12)

    # Initialize AES-256-GCM cipher with 32-byte master key
    aesgcm = AESGCM(settings.AES_KEY_BYTES)

    # Encrypt data (ciphertext includes 16-byte authentication tag)
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)

    # Return nonce + ciphertext as bytes
    return nonce + ciphertext


def decrypt_vector(encrypted_data: bytes) -> List[float]:
    """
    Decrypts an encrypted keystroke dynamics feature vector using AES-256-GCM (RNF-01, CP-S10).
    Verifies cryptographic integrity and authenticity; raises an exception if tampered.

    Args:
        encrypted_data: bytes consisting of 12-byte nonce followed by ciphertext + tag.

    Returns:
        List[float]: The original list of floating point biometric measurements.

    Raises:
        ValueError: If data is not bytes or length is shorter than nonce + auth tag.
        cryptography.exceptions.InvalidTag: If the ciphertext or tag was tampered with.
    """
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise ValueError("Encrypted data must be bytes or bytearray.")

    # 12 bytes nonce + at least 16 bytes auth tag = minimum 28 bytes
    if len(encrypted_data) < 28:
        raise ValueError("Invalid encrypted data length: minimum 28 bytes required.")

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(settings.AES_KEY_BYTES)

    # AESGCM.decrypt validates the tag and raises InvalidTag if corrupted or modified
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    # Deserialize JSON list of floats
    parsed = json.loads(decrypted_bytes.decode("utf-8"))
    return [float(x) for x in parsed]
