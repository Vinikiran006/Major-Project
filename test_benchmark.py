from evaluation.benchmark import CryptoBenchmark


benchmark = CryptoBenchmark()

message = (
    "Temperature=27.4C,"
    "Humidity=63%,"
    "Pressure=1012hPa"
)

results = benchmark.benchmark_all(message)


for algorithm, metrics in results.items():

    print("\n" + "=" * 60)

    print(f"Algorithm: {algorithm}")

    print(
        f"Encryption Time   : "
        f"{metrics['encryption_time_ms']:.6f} ms"
    )

    print(
        f"Decryption Time   : "
        f"{metrics['decryption_time_ms']:.6f} ms"
    )

    print(
        f"Encryption Speed  : "
        f"{metrics['encryption_throughput_mb_s']:.4f} MB/s"
    )

    print(
        f"Decryption Speed  : "
        f"{metrics['decryption_throughput_mb_s']:.4f} MB/s"
    )

    print(
        f"Plaintext Size    : "
        f"{metrics['plaintext_size_bytes']} bytes"
    )

    print(
        f"Ciphertext Size   : "
        f"{metrics['ciphertext_size_bytes']} bytes"
    )

    print(
        f"Memory Used       : "
        f"{metrics['memory_used_mb']:.4f} MB"
    )

    print(
        f"Correct           : "
        f"{metrics['correct']}"
    )