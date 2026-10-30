
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ascon

import ctypes
import os



KEY = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
AAD = b"ESP32-DHT22-v1"
PLAINTEXT = b'{"temperature":24.9,"humidity":62.6}'

GIFT_KEY = KEY
GIFT_DLL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "giftcofb.dll",
)

gift = ctypes.CDLL(GIFT_DLL_PATH)

U8P = ctypes.POINTER(ctypes.c_ubyte)
ULLP = ctypes.POINTER(ctypes.c_ulonglong)

gift.giftcofb_crypto_aead_encrypt.argtypes = [
    U8P, ULLP, U8P, ctypes.c_ulonglong,
    U8P, ctypes.c_ulonglong, U8P, U8P, U8P,
]
gift.giftcofb_crypto_aead_encrypt.restype = ctypes.c_int

gift.giftcofb_crypto_aead_decrypt.argtypes = [
    U8P, ULLP, U8P, U8P, ctypes.c_ulonglong,
    U8P, ctypes.c_ulonglong, U8P, U8P,
]
gift.giftcofb_crypto_aead_decrypt.restype = ctypes.c_int


def cbuf(data):
    if not data:
        return None
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def gift_encrypt(plaintext, nonce, aad, key):
    output = (ctypes.c_ubyte * (len(plaintext) + 16))()
    output_len = ctypes.c_ulonglong(0)

    result = gift.giftcofb_crypto_aead_encrypt(
        output, ctypes.byref(output_len),
        cbuf(plaintext), len(plaintext),
        cbuf(aad), len(aad),
        None, cbuf(nonce), cbuf(key)
    )

    if result != 0:
        raise RuntimeError("GIFT encryption failed")

    return bytes(output[:output_len.value])


def gift_decrypt(ciphertext, nonce, aad, key):
    output = (ctypes.c_ubyte * len(ciphertext))()
    output_len = ctypes.c_ulonglong(0)

    result = gift.giftcofb_crypto_aead_decrypt(
        output, ctypes.byref(output_len),
        None, cbuf(ciphertext), len(ciphertext),
        cbuf(aad), len(aad), cbuf(nonce), cbuf(key)
    )

    if result != 0:
        raise ValueError("GIFT authentication failed")

    return bytes(output[:output_len.value])



def test_gift_known_answer():
    print("\n--- GIFT-COFB Known-Answer Test ---")

    test_key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )
    test_nonce = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )
    test_aad = b""
    test_plaintext = bytes.fromhex("00")

    expected = bytes.fromhex(
        "5df96db329e92688242ef4e06f94fe1bd9"
    )

    actual = gift_encrypt(
        test_plaintext, test_nonce, test_aad, test_key
    )

    print("Expected:", expected.hex())
    print("Actual:  ", actual.hex())

    if actual != expected:
        print("Known-answer encryption: FAIL")
        return False

    print("Known-answer encryption: PASS")

    try:
        recovered = gift_decrypt(
            expected, test_nonce, test_aad, test_key
        )
    except ValueError as error:
        print("Known-answer decryption: FAIL", error)
        return False

    if recovered != test_plaintext:
        print("Known-answer decryption: FAIL")
        return False

    print("Known-answer decryption: PASS")
    return True



def test_aes_gcm():
    print("\n--- AES-128-GCM Tamper Test ---")

    nonce = secrets.token_bytes(12)
    aes = AESGCM(KEY)

    # AESGCM returns ciphertext followed by its 16-byte tag.
    encrypted = aes.encrypt(nonce, PLAINTEXT, AAD)

    recovered = aes.decrypt(nonce, encrypted, AAD)
    assert recovered == PLAINTEXT
    print("Valid message: PASS")

    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01

    try:
        aes.decrypt(nonce, bytes(tampered), AAD)
        print("Tamper test: FAIL - modified message accepted")
        return False
    except Exception:
        print("Tamper test: PASS - modified message rejected")
        return True


def test_ascon():
    print("\n--- ASCON-AEAD128 Tamper Test ---")

    nonce = secrets.token_bytes(16)

    encrypted = ascon.ascon_encrypt(
        KEY, nonce, AAD, PLAINTEXT,
        variant="Ascon-AEAD128"
    )

    recovered = ascon.ascon_decrypt(
        KEY, nonce, AAD, encrypted,
        variant="Ascon-AEAD128"
    )

    assert recovered == PLAINTEXT
    print("Valid message: PASS")

    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01

    recovered_tampered = ascon.ascon_decrypt(
        KEY, nonce, AAD, bytes(tampered),
        variant="Ascon-AEAD128"
    )

    if recovered_tampered is None:
        print("Tamper test: PASS - modified message rejected")
        return True

    print("Tamper test: FAIL - modified message accepted")
    return False



def test_gift():
    print("\n--- GIFT-COFB-128 Tamper Test ---")

    nonce = secrets.token_bytes(16)

    encrypted = gift_encrypt(PLAINTEXT, nonce, AAD, GIFT_KEY)

    recovered = gift_decrypt(encrypted, nonce, AAD, GIFT_KEY)
    assert recovered == PLAINTEXT
    print("Valid message: PASS")

    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01

    try:
        recovered_tampered = gift_decrypt(
            bytes(tampered), nonce, AAD, GIFT_KEY
        )
        print("Tamper test: FAIL - modified message accepted")
        return False
    except ValueError as error:
        if str(error) == "GIFT authentication failed":
            print("Tamper test: PASS - modified message rejected")
            return True
        raise



if __name__ == "__main__":
    aes_ok = test_aes_gcm()
    ascon_ok = test_ascon()
    gift_ok = test_gift()
    gift_kat_ok = test_gift_known_answer()
    print("\n--- FINAL RESULT ---")
    print("AES-128-GCM:", "PASS" if aes_ok else "FAIL")
    print("ASCON-AEAD128:", "PASS" if ascon_ok else "FAIL")
    print("GIFT-COFB-128:", "PASS" if gift_ok else "FAIL")
    print("GIFT known-answer test:", "PASS" if gift_kat_ok else "FAIL") 

    if not (aes_ok and ascon_ok and gift_ok and gift_kat_ok):
        raise SystemExit(1)

   
