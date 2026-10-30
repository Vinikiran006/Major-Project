from crypto.aes_crypto import AES128Crypto
from crypto.ascon_crypto import ASCON128Crypto
from crypto.giftcofb_crypto import GiftCofbCrypto
from crypto.key_config import load_optional_key


class CryptoManager:
    def __init__(self):
        aes_key = load_optional_key("IOT_AES128_KEY")
        ascon_key = load_optional_key("IOT_ASCON128_KEY")
        giftcofb_key = load_optional_key("IOT_GIFTCOFB128_KEY")

        self.algorithms = {
            "AES-128": AES128Crypto(key=aes_key),
            "ASCON-128": ASCON128Crypto(key=ascon_key),
        }

        # GIFT-COFB is explicitly enabled only when its key is configured.
        if giftcofb_key is not None:
            self.algorithms["GIFT-COFB-128"] = GiftCofbCrypto(
                key=giftcofb_key
            )

    def encrypt(self, algorithm, plaintext):
        if algorithm not in self.algorithms:
            raise ValueError(
                f"Unsupported or disabled algorithm: {algorithm}"
            )
        return self.algorithms[algorithm].encrypt(plaintext)

    def decrypt(self, algorithm, ciphertext):
        if algorithm not in self.algorithms:
            raise ValueError(
                f"Unsupported or disabled algorithm: {algorithm}"
            )
        return self.algorithms[algorithm].decrypt(ciphertext)

    def available_algorithms(self):
        return list(self.algorithms.keys())
