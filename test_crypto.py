from crypto.crypto_manager import CryptoManager


crypto = CryptoManager()

message = "Temperature=27.4C"

print("Available Algorithms:")
print(crypto.available_algorithms())


for algorithm in crypto.available_algorithms():

    print("\n" + "=" * 50)

    print(f"Algorithm: {algorithm}")

    encrypted = crypto.encrypt(
        algorithm,
        message
    )

    print("\nEncrypted:")
    print(encrypted.hex())

    decrypted = crypto.decrypt(
        algorithm,
        encrypted
    )

    print("\nDecrypted:")
    print(decrypted)