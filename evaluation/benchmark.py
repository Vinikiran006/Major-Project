import statistics
import time

from crypto.crypto_manager import CryptoManager
from crypto.giftcofb_reference.giftcofb_wrapper import GiftCofb128

from evaluation.metrics import (
    get_process_memory_mb,
    calculate_throughput,
)


class CryptoBenchmark:
    def __init__(self, giftcofb_key=None):
        self.crypto = CryptoManager()

        if giftcofb_key is None:
            giftcofb_key = bytes.fromhex(
                "00112233445566778899aabbccddeeff"
            )

        self.giftcofb = GiftCofb128(giftcofb_key)

    def benchmark_algorithm(
        self, algorithm, plaintext, runs=100, warmups=5
    ):
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string.")

        data = plaintext.encode("utf-8")

        if algorithm == "GIFT-COFB-128":
            encrypt = lambda: self.giftcofb.encrypt(data)
            decrypt = lambda sealed: self.giftcofb.decrypt(sealed)
            expected = data
        elif algorithm in ("AES-128", "ASCON-128"):
            encrypt = lambda: self.crypto.encrypt(algorithm, plaintext)
            decrypt = lambda sealed: self.crypto.decrypt(algorithm, sealed)
            expected = plaintext
        else:
            raise ValueError(f"Unsupported benchmark algorithm: {algorithm}")

        for _ in range(warmups):
            sealed = encrypt()
            if decrypt(sealed) != expected:
                raise RuntimeError(f"{algorithm} round-trip failed.")

        encryption_times = []
        decryption_times = []
        memory_before = get_process_memory_mb()
        sealed = None

        for _ in range(runs):
            start = time.perf_counter()
            sealed = encrypt()
            encryption_times.append(
                (time.perf_counter() - start) * 1000
            )

            start = time.perf_counter()
            recovered = decrypt(sealed)
            decryption_times.append(
                (time.perf_counter() - start) * 1000
            )

            if recovered != expected:
                raise RuntimeError(f"{algorithm} round-trip failed.")

        memory_after = get_process_memory_mb()

        enc_ms = statistics.median(encryption_times)
        dec_ms = statistics.median(decryption_times)

        return {
            "algorithm": algorithm,
            "encryption_time_ms": enc_ms,
            "decryption_time_ms": dec_ms,
            "encryption_throughput_mb_s": calculate_throughput(
                len(data), enc_ms
            ),
            "decryption_throughput_mb_s": calculate_throughput(
                len(data), dec_ms
            ),
            "plaintext_size_bytes": len(data),
            "ciphertext_size_bytes": len(sealed),
            "memory_used_mb": max(memory_after - memory_before, 0),
            "correct": True,
            "runs": runs,
        }

    def benchmark_all(self, plaintext, runs=100, warmups=5):
        algorithms = ["AES-128", "ASCON-128", "GIFT-COFB-128"]
        return {
            algorithm: self.benchmark_algorithm(
                algorithm, plaintext, runs=runs, warmups=warmups
            )
            for algorithm in algorithms
        }
