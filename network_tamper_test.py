
import json
import socket
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ascon

HOST = "192.168.29.147"
PORT = 5000

KEY = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
AAD = b"ESP32-DHT22-v1"
PLAINTEXT = b'{"temperature":24.9,"humidity":62.6}'


def send_message(message):
    data = json.dumps(message).encode("utf-8") + b"\n"

    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.sendall(data)

    print(f"Tampered message sent to receiver at {HOST}:{PORT}")


def test_aes():
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(KEY).encrypt(nonce, PLAINTEXT, AAD)

    # AES-GCM output is ciphertext followed by its 16-byte tag.
    ciphertext = bytearray(encrypted[:-16])
    tag = encrypted[-16:]

    ciphertext[0] ^= 0x01  # Deliberately corrupt ciphertext.

    message = {
        "device_id": "TAMPER-TEST",
        "algorithm": "AES-128-GCM",
        "aad": AAD.decode(),
        "nonce": nonce.hex(),
        "ciphertext": bytes(ciphertext).hex(),
        "tag": tag.hex()
    }

    print("\nSending tampered AES-128-GCM message...")
    send_message(message)


def test_ascon():
    nonce = secrets.token_bytes(16)
    encrypted = ascon.ascon_encrypt(
        KEY, nonce, AAD, PLAINTEXT,
        variant="Ascon-AEAD128"
    )

    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01  # Deliberately corrupt ciphertext.

    message = {
        "device_id": "TAMPER-TEST",
        "algorithm": "ASCON-AEAD128",
        "aad": AAD.decode(),
        "nonce": nonce.hex(),
        "ciphertext": bytes(tampered).hex()
    }

    print("\nSending tampered ASCON-AEAD128 message...")
    send_message(message)


if __name__ == "__main__":
    test_aes()
    test_ascon()
    print("\nBoth test messages sent. Check the receiver terminal.")
