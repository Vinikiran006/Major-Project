from crypto.giftcofb_crypto import GiftCofbCrypto
from crypto.giftcofb_reference.giftcofb_wrapper import (
    GiftCofbAuthenticationError,
)

key = bytes.fromhex("00112233445566778899aabbccddeeff")
cipher = GiftCofbCrypto(key)

message = "Temperature=28.6C;Humidity=62%;Device=IOT-001"

sealed = cipher.encrypt(message)
recovered = cipher.decrypt(sealed)

assert recovered == message
print("[PASS] UTF-8 encryption/decryption")

tampered = bytearray(sealed)
tampered[-1] ^= 1

try:
    cipher.decrypt(bytes(tampered))
except GiftCofbAuthenticationError:
    print("[PASS] Tampered ciphertext rejected")
else:
    raise AssertionError("Tampered ciphertext was accepted")

print("All adapter tests passed.")
