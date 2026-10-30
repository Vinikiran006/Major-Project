from crypto.giftcofb_reference.giftcofb_wrapper import GiftCofb128


class GiftCofbCrypto:
    """Experimental GIFT-COFB adapter using the existing crypto interface."""

    def __init__(self, key: bytes):
        self._cipher = GiftCofb128(key)

    def encrypt(self, plaintext: str) -> bytes:
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string.")

        return self._cipher.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        plaintext = self._cipher.decrypt(ciphertext)
        return plaintext.decode("utf-8")
