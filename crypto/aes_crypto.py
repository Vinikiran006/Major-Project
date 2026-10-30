# ============================================================
# Adaptive IoT Security Framework
# Stage 2 - AES-128
# ============================================================

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AES128Crypto:

    def __init__(self, key=None):

        if key is None:
            key = AESGCM.generate_key(bit_length=128)

        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key.")

        self.key = key
        self.cipher = AESGCM(self.key)

    def encrypt(self, plaintext):

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        nonce = os.urandom(12)

        ciphertext = self.cipher.encrypt(
            nonce,
            plaintext,
            None
        )

        return nonce + ciphertext

    def decrypt(self, encrypted_data):

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        plaintext = self.cipher.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext.decode("utf-8")