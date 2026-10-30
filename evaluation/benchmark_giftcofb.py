import statistics
import time

from crypto.giftcofb_reference.giftcofb_wrapper import GiftCofb128

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
RUNS = 100
MESSAGE = (
    "Temperature=28.6C;Humidity=62%;"
    "Device=IOT-001"
).encode("utf-8")

cipher = GiftCofb128(KEY)

encryption_times = []
decryption_times = []
sealed = None

# Warm-up: exclude initial setup effects from the measurements.
for _ in range(5):
    sample = cipher.encrypt(MESSAGE)
    assert cipher.decrypt(sample) == MESSAGE

# Benchmark encryption and decryption.
for _ in range(RUNS):
    start = time.perf_counter()
    sealed = cipher.encrypt(MESSAGE)
    encryption_times.append(
        (time.perf_counter() - start) * 1000
    )

    start = time.perf_counter()
    recovered = cipher.decrypt(sealed)
    decryption_times.append(
        (time.perf_counter() - start) * 1000
    )

    assert recovered == MESSAGE

enc_ms = statistics.median(encryption_times)
dec_ms = statistics.median(decryption_times)
payload_size = len(MESSAGE)
ciphertext_size = len(sealed)

print("GIFT-COFB-128 Benchmark")
print("-" * 40)
print(f"Runs: {RUNS}")
print(f"Plaintext size: {payload_size} bytes")
print(f"Sealed size (nonce + ciphertext + tag): {ciphertext_size} bytes")
print(f"Median encryption time: {enc_ms:.4f} ms")
print(f"Median decryption time: {dec_ms:.4f} ms")
print(
    f"Encryption throughput: "
    f"{payload_size / (1024 * 1024) / (enc_ms / 1000):.4f} MB/s"
)
print(
    f"Decryption throughput: "
    f"{payload_size / (1024 * 1024) / (dec_ms / 1000):.4f} MB/s"
)
print("Round-trip verification: PASS")
