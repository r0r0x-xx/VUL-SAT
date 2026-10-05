"""Helpers for the intentionally weak Pwnsat AES-128 link wrapper."""

from __future__ import annotations

try:
    from Cryptodome.Cipher import AES as _AES

    def _aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
        return _AES.new(key, _AES.MODE_ECB).encrypt(data)

    def _aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
        return _AES.new(key, _AES.MODE_ECB).decrypt(data)

except ImportError:
    try:
        from Crypto.Cipher import AES as _AES

        def _aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
            return _AES.new(key, _AES.MODE_ECB).encrypt(data)

        def _aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
            return _AES.new(key, _AES.MODE_ECB).decrypt(data)

    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def _aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()

        def _aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()


AES_BLOCK_SIZE = 16
AES_KEY = b"PWNsatLabKey1234"
LENGTH_PREFIX_SIZE = 2


def encrypted_size(plain_len: int) -> int:
    total = plain_len + LENGTH_PREFIX_SIZE
    return (total + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1)


def encrypt_payload(payload: bytes, key: bytes = AES_KEY) -> bytes:
    plain = len(payload).to_bytes(2, "big") + payload
    padded_len = encrypted_size(len(payload))
    plain = plain.ljust(padded_len, b"\x00")
    return _aes_ecb_encrypt(plain, key)


def decrypt_payload(payload: bytes, key: bytes = AES_KEY) -> bytes:
    if len(payload) == 0 or len(payload) % AES_BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a non-zero multiple of 16")
    plain = _aes_ecb_decrypt(payload, key)
    plain_len = int.from_bytes(plain[:2], "big")
    if plain_len > len(plain) - LENGTH_PREFIX_SIZE:
        raise ValueError("declared plaintext length exceeds decrypted buffer")
    return plain[LENGTH_PREFIX_SIZE : LENGTH_PREFIX_SIZE + plain_len]
