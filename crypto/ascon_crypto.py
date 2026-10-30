# ============================================================
# Adaptive IoT Security Framework
# Stage 2 - ASCON
# ============================================================

import os
import ascon


class ASCON128Crypto:

    def __init__(self, key=None):

        if key is None:
            key = os.urandom(16)

        if len(key) != 16:
            raise ValueError("ASCON-128 requires a 16-byte key.")

        self.key = key

    def encrypt(self, plaintext):

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        nonce = os.urandom(16)

        associated_data = b""

        ciphertext = ascon.encrypt(
            self.key,
            nonce,
            associated_data,
            plaintext
        )

        return nonce + ciphertext

    def decrypt(self, encrypted_data):

        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        associated_data = b""

        plaintext = ascon.decrypt(
            self.key,
            nonce,
            associated_data,
            ciphertext
        )

        if plaintext is None:
            raise ValueError("ASCON authentication failed.")

        return plaintext.decode("utf-8")