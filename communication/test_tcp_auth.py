
import hashlib
import hmac
import json
import socket
import uuid
from datetime import datetime, timezone

from crypto.crypto_manager import CryptoManager
from crypto.key_config import load_optional_hmac_key

HOST = "127.0.0.1"
PORT = 5000

crypto = CryptoManager()
hmac_key = load_optional_hmac_key()


def sign_packet(packet):
    content = {
        key: value
        for key, value in packet.items()
        if key != "hmac_sha256"
    }

    message = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    packet["hmac_sha256"] = hmac.new(
        hmac_key, message, hashlib.sha256
    ).hexdigest()

    return packet


def send_packet(packet):
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall((json.dumps(packet) + "\n").encode("utf-8"))

        with sock.makefile("rb") as stream:
            raw = stream.readline(1_000_001)

    if not raw:
        raise RuntimeError("Gateway returned no response")

    return json.loads(raw.decode("utf-8"))


def make_packet():
    message = "Authenticated IoT test"
    ciphertext = crypto.encrypt("ASCON-128", message)

    packet = {
        "packet_id": str(uuid.uuid4()),
        "sender_id": "IOT-001",
        "receiver_id": "GATEWAY-001",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "ASCON-128",
        "ciphertext_hex": ciphertext.hex(),
        "payload_encoding": "hex",
    }

    return sign_packet(packet)


def expect_rejected(label, packet):
    response = send_packet(packet)

    if response.get("status") != "ERROR":
        raise AssertionError(
            f"{label}: expected rejection, got {response}"
        )

    print(f"[PASS] {label}: rejected")


def main():
    print("TCP AUTHENTICATION TESTS")

    # A correctly signed packet should be accepted.
    packet = make_packet()
    response = send_packet(packet)

    assert response.get("status") == "SUCCESS", response
    assert response.get("plaintext") == "Authenticated IoT test"
    print("[PASS] Valid authenticated packet accepted")

    # Change sender identity without updating the HMAC.
    forged = make_packet()
    forged["sender_id"] = "IMPOSTOR"
    expect_rejected("Forged sender ID", forged)

    # Change ciphertext without updating the HMAC.
    tampered = make_packet()
    raw = bytearray.fromhex(tampered["ciphertext_hex"])
    raw[-1] ^= 1
    tampered["ciphertext_hex"] = raw.hex()
    expect_rejected("Modified ciphertext", tampered)

    # Replace the HMAC with an invalid value.
    invalid = make_packet()
    invalid["hmac_sha256"] = "0" * 64
    expect_rejected("Invalid HMAC", invalid)

    print("\nAll authentication tests passed.")


if __name__ == "__main__":
    main()
