import statistics
import time

from crypto.crypto_manager import CryptoManager
from crypto.giftcofb_reference.giftcofb_wrapper import GiftCofb128

RUNS = 100
WARMUPS = 5
MESSAGE = "Temperature=28.6C;Humidity=62%;Device=IOT-001"
DATA = MESSAGE.encode("utf-8")

manager = CryptoManager()
gift = GiftCofb128(bytes.fromhex(
    "00112233445566778899aabbccddeeff"
))

algorithms = {
    "AES-128": (
        lambda: manager.encrypt("AES-128", MESSAGE),
        lambda c: manager.decrypt("AES-128", c),
        MESSAGE,
    ),
    "ASCON-128": (
        lambda: manager.encrypt("ASCON-128", MESSAGE),
        lambda c: manager.decrypt("ASCON-128", c),
        MESSAGE,
    ),
    "GIFT-COFB-128": (
        lambda: gift.encrypt(DATA),
        lambda c: gift.decrypt(c),
        DATA,
    ),
}

print("Same-message authenticated-encryption comparison")
print(f"Plaintext: {len(DATA)} bytes | Runs: {RUNS}")
print("-" * 78)
print(
    f"{'Algorithm':<16} {'Enc ms':>10} {'Dec ms':>10} "
    f"{'Enc MB/s':>12} {'Sealed B':>10}"
)

for name, (encrypt, decrypt, expected) in algorithms.items():
    for _ in range(WARMUPS):
        sealed = encrypt()
        recovered = decrypt(sealed)
        assert recovered == expected, f"{name}: warm-up round trip failed"

    enc_times = []
    dec_times = []
    sealed = None

    for _ in range(RUNS):
        start = time.perf_counter()
        sealed = encrypt()
        enc_times.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        recovered = decrypt(sealed)
        dec_times.append((time.perf_counter() - start) * 1000)

        assert recovered == expected, f"{name}: round trip failed"

    enc_ms = statistics.median(enc_times)
    dec_ms = statistics.median(dec_times)
    throughput = len(DATA) / (1024 * 1024) / (enc_ms / 1000)

    print(
        f"{name:<16} {enc_ms:>10.4f} {dec_ms:>10.4f} "
        f"{throughput:>12.4f} {len(sealed):>10}"
    )

print("-" * 78)
print("All algorithms completed round-trip verification.")
