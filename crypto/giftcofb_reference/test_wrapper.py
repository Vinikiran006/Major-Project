
from giftcofb_wrapper import (
    GiftCofb128,
    GiftCofbAuthenticationError,
)

key = bytes(range(16))
cipher = GiftCofb128(key)

plaintext = b"Temperature=28.6C;Device=IOT-001"
aad = b"sender=IOT-001;receiver=GATEWAY-001"

sealed = cipher.encrypt(plaintext, associated_data=aad)
recovered = cipher.decrypt(sealed, associated_data=aad)

assert recovered == plaintext
print("[PASS] Encryption/decryption")

# Changing associated data must fail authentication.
try:
    cipher.decrypt(sealed, associated_data=b"sender=ATTACKER")
    raise AssertionError("Modified associated data was accepted")
except GiftCofbAuthenticationError:
    print("[PASS] Modified associated data rejected")

# Changing ciphertext or the authentication tag must fail.
tampered = bytearray(sealed)
tampered[16] ^= 1

try:
    cipher.decrypt(bytes(tampered), associated_data=aad)
    raise AssertionError("Tampered ciphertext was accepted")
except GiftCofbAuthenticationError:
    print("[PASS] Tampered ciphertext rejected")

try:
    cipher.decrypt(b"too short")
    raise AssertionError("Short input was accepted")
except ValueError:
    print("[PASS] Short input rejected")

print("All wrapper tests passed.")
