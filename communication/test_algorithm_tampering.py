
from crypto.crypto_manager import CryptoManager

MESSAGE = "Temperature=28.6C;Humidity=62%;Device=IOT-001"

def test_algorithm(manager, algorithm):
    print(f"\nTesting {algorithm}")

    ciphertext = manager.encrypt(algorithm, MESSAGE)
    recovered = manager.decrypt(algorithm, ciphertext)

    if recovered != MESSAGE:
        print("FAIL: Normal round trip did not match")
        return False

    print("PASS: Normal round trip")

    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01

    try:
        manager.decrypt(algorithm, bytes(tampered))
        print("FAIL: Tampered ciphertext was accepted")
        return False
    except Exception as exc:
        print(f"PASS: Tampering rejected ({type(exc).__name__})")
        return True

def main():
    manager = CryptoManager()
    results = []

    for algorithm in manager.available_algorithms():
        results.append(test_algorithm(manager, algorithm))

    print("\n" + "=" * 45)
    print(f"Passed: {sum(results)}/{len(results)} algorithms")

    if not all(results):
        raise SystemExit("Tampering test failed for at least one algorithm.")

if __name__ == "__main__":
    main()
