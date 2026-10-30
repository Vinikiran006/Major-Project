# ============================================================
# Adaptive IoT Security Framework
# Stage 2 - Lightweight Cipher Interface
# ============================================================

import hashlib


class GIFT64Crypto:

    def __init__(self, key=None):

        if key is None:
            key = b"AdaptiveIoTKey"

        self.key = key

    def _keystream(self, length):

        stream = b""
        counter = 0

        while len(stream) < length:

            data = (
                self.key
                + counter.to_bytes(4, "big")
            )

            stream += hashlib.sha256(data).digest()

            counter += 1

        return stream[:length]

    def encrypt(self, plaintext):

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        keystream = self._keystream(len(plaintext))

        ciphertext = bytes(
            a ^ b
            for a, b in zip(plaintext, keystream)
        )

        return ciphertext

    def decrypt(self, ciphertext):

        keystream = self._keystream(len(ciphertext))

        plaintext = bytes(
            a ^ b
            for a, b in zip(ciphertext, keystream)
        )

        return plaintext.decode("utf-8")