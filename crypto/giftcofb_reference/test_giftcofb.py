
import ctypes
from pathlib import Path

dll_path = Path(__file__).with_name("giftcofb.dll")
dll = ctypes.CDLL(str(dll_path))

U8 = ctypes.c_ubyte
U8_PTR = ctypes.POINTER(U8)
ULL = ctypes.c_ulonglong

encrypt = dll.crypto_aead_encrypt
encrypt.argtypes = [
    U8_PTR, ctypes.POINTER(ULL),
    U8_PTR, ULL, U8_PTR, ULL,
    U8_PTR, U8_PTR, U8_PTR,
]
encrypt.restype = ctypes.c_int

decrypt = dll.crypto_aead_decrypt
decrypt.argtypes = [
    U8_PTR, ctypes.POINTER(ULL),
    U8_PTR, U8_PTR, ULL, U8_PTR, ULL,
    U8_PTR, U8_PTR,
]
decrypt.restype = ctypes.c_int


def buffer(data):
    # Allocate at least one byte even for empty input.
    return (U8 * max(1, len(data)))(*data) if data else (U8 * 1)()


key = bytes(range(16))
nonce = bytes(range(16, 32))
plaintext = b"Temperature=28.6C;Device=IOT-001"
aad = b"sender=IOT-001;algorithm=GIFT-COFB-128"

key_buf = buffer(key)
nonce_buf = buffer(nonce)
plaintext_buf = buffer(plaintext)
aad_buf = buffer(aad)

ciphertext = (U8 * (len(plaintext) + 16))()
ciphertext_len = ULL(0)

result = encrypt(
    ciphertext, ctypes.byref(ciphertext_len),
    plaintext_buf, ULL(len(plaintext)),
    aad_buf, ULL(len(aad)),
    None, nonce_buf, key_buf,
)

assert result == 0, f"Encryption failed: {result}"
sealed = bytes(ciphertext[:ciphertext_len.value])
print("[PASS] Encryption completed")

recovered = (U8 * max(1, len(plaintext)))()
recovered_len = ULL(0)

result = decrypt(
    recovered, ctypes.byref(recovered_len),
    None, buffer(sealed), ULL(len(sealed)),
    aad_buf, ULL(len(aad)),
    nonce_buf, key_buf,
)

assert result == 0, f"Valid decryption failed: {result}"
assert bytes(recovered[:recovered_len.value]) == plaintext
print("[PASS] Decryption recovered the original plaintext")

tampered = bytearray(sealed)
tampered[0] ^= 1

tampered_output = (U8 * max(1, len(plaintext)))()
tampered_len = ULL(0)

result = decrypt(
    tampered_output, ctypes.byref(tampered_len),
    None, buffer(bytes(tampered)), ULL(len(tampered)),
    aad_buf, ULL(len(aad)),
    nonce_buf, key_buf,
)

assert result != 0, "Tampered ciphertext was incorrectly accepted"
print("[PASS] Tampered ciphertext rejected")
print("\nAll GIFT-COFB smoke tests passed.")
