
"""End-to-end TCP tests for enabled authenticated encryption algorithms."""

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
SENDER_ID = "IOT-TEST-001"
GATEWAY_ID = "GATEWAY-001"

crypto = CryptoManager()
hmac_key = load_optional_hmac_key()


def sign_packet(packet):
    """Sign all packet fields except the HMAC field itself."""
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
        hmac_key,
        message,
        hashlib.sha256,
    ).hexdigest()

    return packet


def make_packet(algorithm, message):
    """Create and sign a packet for the TCP gateway."""
    ciphertext = crypto.encrypt(algorithm, message)

    packet = {
        "packet_id": str(uuid.uuid4()),
        "sender_id": SENDER_ID,
        "receiver_id": GATEWAY_ID,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": algorithm,
        "ciphertext_hex": ciphertext.hex(),
        "payload_encoding": "hex",
    }

    # Important: sign the packet before sending it.
    return sign_packet(packet)


def send_packet(packet):
    """Send one JSON packet and return the gateway response."""
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall((json.dumps(packet) + "\n").encode("utf-8"))

        with sock.makefile("rb") as stream:
            response = stream.readline(1_000_001)

    if not response:
        raise RuntimeError("Gateway returned no response")

    return json.loads(response.decode("utf-8"))


def test_round_trip(algorithm):
    """Verify that the gateway decrypts the original message."""
    message = f"Security test message for {algorithm}"
    packet = make_packet(algorithm, message)
    response = send_packet(packet)

    assert response.get("status") == "SUCCESS", response
    assert response.get("plaintext") == message, response
    assert response.get("algorithm") == algorithm, response

    print(f"[PASS] {algorithm}: TCP round trip")


def test_tampering(algorithm):
    """Verify that ciphertext modification is rejected."""
    packet = make_packet(algorithm, "Message to tamper with")

    raw = bytearray.fromhex(packet["ciphertext_hex"])
    raw[-1] ^= 0x01
    packet["ciphertext_hex"] = raw.hex()

    # Do not re-sign: the HMAC must no longer match the packet.
    response = send_packet(packet)

    assert response.get("status") == "ERROR", response
    print(f"[PASS] {algorithm}: tampered ciphertext rejected")


def test_replay(algorithm):
    """Verify that sending the same packet twice is rejected."""
    packet = make_packet(algorithm, "Replay protection test")

    first = send_packet(packet)
    assert first.get("status") == "SUCCESS", first

    second = send_packet(packet)
    assert second.get("status") == "ERROR", second
    assert "replay" in second.get("error", "").lower(), second

    print(f"[PASS] {algorithm}: replay rejected")


def main():
    print("=" * 58)
    print("TCP CRYPTOGRAPHY AND SECURITY TESTS")
    print("=" * 58)

    algorithms = crypto.available_algorithms()

    if not algorithms:
        raise RuntimeError("No cryptographic algorithms are enabled.")

    for algorithm in algorithms:
        print(f"\nTesting {algorithm}")

        test_round_trip(algorithm)
        test_tampering(algorithm)
        test_replay(algorithm)

    print("\nAll TCP tests passed.")


if __name__ == "__main__":
    main()
