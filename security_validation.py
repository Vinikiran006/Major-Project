import os
import ctypes


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ascon


# ============================================================
# CONFIGURATION
# ============================================================

KEY = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
AAD = b"ESP32-DHT22-v1"
PLAINTEXT = b'{"temperature":24.9,"humidity":62.6}'

AES_NONCE = bytes.fromhex("000102030405060708090a0b")
ASCON_NONCE = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
GIFT_NONCE = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

GIFT_DLL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "giftcofb.dll",
)


# ============================================================
# GIFT-COFB DLL SETUP
# ============================================================

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
        output,
        ctypes.byref(output_len),
        cbuf(plaintext),
        len(plaintext),
        cbuf(aad),
        len(aad),
        None,
        cbuf(nonce),
        cbuf(key),
    )

    if result != 0:
        raise RuntimeError("GIFT encryption failed")

    return bytes(output[:output_len.value])


def gift_decrypt(ciphertext, nonce, aad, key):
    output = (ctypes.c_ubyte * max(1, len(ciphertext)))()
    output_len = ctypes.c_ulonglong(0)

    result = gift.giftcofb_crypto_aead_decrypt(
        output,
        ctypes.byref(output_len),
        None,
        cbuf(ciphertext),
        len(ciphertext),
        cbuf(aad),
        len(aad),
        cbuf(nonce),
        cbuf(key),
    )

    if result != 0:
        raise ValueError("GIFT authentication failed")

    return bytes(output[:output_len.value])


# ============================================================
# ALGORITHM ADAPTERS
# ============================================================

def aes_encrypt(plaintext, nonce, aad, key):
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(ciphertext, nonce, aad, key):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def ascon_encrypt(plaintext, nonce, aad, key):
    return ascon.ascon_encrypt(
        key, nonce, aad, plaintext,
        variant="Ascon-AEAD128",
    )


def ascon_decrypt(ciphertext, nonce, aad, key):
    return ascon.ascon_decrypt(
        key, nonce, aad, ciphertext,
        variant="Ascon-AEAD128",
    )


# ============================================================
# SECURITY TEST RUNNER
# ============================================================

def run_algorithm_tests(name, encrypt, decrypt, nonce):
    print(f"\n{'=' * 58}")
    print(f" {name} SECURITY VALIDATION")
    print("=" * 58)

    passed = 0
    failed = 0

    def report(test_name, success, detail=""):
        nonlocal passed, failed

        if success:
            passed += 1
            print(f"[PASS] {test_name}")
        else:
            failed += 1
            print(f"[FAIL] {test_name} {detail}")

    try:
        ciphertext = encrypt(PLAINTEXT, nonce, AAD, KEY)

        recovered = decrypt(ciphertext, nonce, AAD, KEY)
        report(
            "Valid message decrypts correctly",
            recovered == PLAINTEXT,
        )

        # Each mutation starts from the original valid ciphertext.
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01

        wrong_nonce = bytearray(nonce)
        wrong_nonce[0] ^= 0x01

        wrong_aad = AAD + b"-modified"
        wrong_key = bytes([KEY[0] ^ 0x01]) + KEY[1:]

        truncated = ciphertext[:-1]

        invalid_cases = [
            ("Modified ciphertext", bytes(tampered), nonce, AAD, KEY),
            ("Incorrect key", ciphertext, nonce, AAD, wrong_key),
            ("Modified nonce", ciphertext, bytes(wrong_nonce), AAD, KEY),
            ("Modified AAD", ciphertext, nonce, wrong_aad, KEY),
            ("Truncated ciphertext/tag", truncated, nonce, AAD, KEY),
        ]

        for test_name, ct, n, aad, key in invalid_cases:
            try:
                result = decrypt(ct, n, aad, key)

                # Authenticated decryption should reject invalid input.
                # ASCON returns None on authentication failure.
                rejected = result is None

            except Exception:
                rejected = True

            report(test_name + " rejected", rejected)

    except Exception as exc:
        report("Test setup and valid-message round trip", False, str(exc))
        print(f"Error details: {type(exc).__name__}: {exc}")

    print(f"\n{name} summary: {passed} passed, {failed} failed")
    return passed, failed


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    results = {}

    algorithms = [
        ("AES-128-GCM", aes_encrypt, aes_decrypt, AES_NONCE),
        ("ASCON-AEAD128", ascon_encrypt, ascon_decrypt, ASCON_NONCE),
        ("GIFT-COFB-128", gift_encrypt, gift_decrypt, GIFT_NONCE),
    ]

    total_passed = 0
    total_failed = 0

    for name, encrypt, decrypt, nonce in algorithms:
        passed, failed = run_algorithm_tests(
            name, encrypt, decrypt, nonce
        )
        results[name] = (passed, failed)
        total_passed += passed
        total_failed += failed

    print("\n" + "=" * 58)
    print(" FINAL SECURITY VALIDATION SUMMARY")
    print("=" * 58)

    for name, (passed, failed) in results.items():
        status = "PASS" if failed == 0 and passed == 6 else "FAIL"
        print(f"{name}: {status} ({passed}/6 tests passed)")

    print(f"\nTotal: {total_passed} passed, {total_failed} failed")

    if total_failed or total_passed != 18:
        raise SystemExit(1)

    print("All security validation tests passed.")