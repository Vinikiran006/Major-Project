
import hashlib
import hmac
import json
import socket
import uuid
from datetime import datetime, timezone, timedelta

from crypto.crypto_manager import CryptoManager
from crypto.key_config import load_optional_hmac_key

HOST = "127.0.0.1"
PORT = 5000
SENDER_ID = "IOT-TEST-001"
GATEWAY_ID = "GATEWAY-001"

crypto = CryptoManager()
hmac_key = load_optional_hmac_key()


def sign_packet(packet):
    content = {
        key: value
        for key, value in packet.items()
        if key != "hmac_sha256"
    }

    serialized = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    packet["hmac_sha256"] = hmac.new(
        hmac_key, serialized, hashlib.sha256
    ).hexdigest()

    return packet


def make_packet(timestamp):
    message = "Freshness test message"
    ciphertext = crypto.encrypt("ASCON-128", message)

    packet = {
        "packet_id": str(uuid.uuid4()),
        "sender_id": SENDER_ID,
        "receiver_id": GATEWAY_ID,
        "timestamp_utc": timestamp.isoformat(),
        "algorithm": "ASCON-128",
        "ciphertext_hex": ciphertext.hex(),
        "payload_encoding": "hex",
    }

    return sign_packet(packet)


def send_packet(packet):
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall((json.dumps(packet) + "\n").encode("utf-8"))

        with sock.makefile("rb") as stream:
            raw = stream.readline(1_000_001)

    if not raw:
        raise RuntimeError("Gateway returned no response")

    return json.loads(raw.decode("utf-8"))


def main():
    now = datetime.now(timezone.utc)

    print("TCP TIMESTAMP FRESHNESS TESTS")

    # 1. A fresh authenticated packet should be accepted.
    fresh_packet = make_packet(now)
    response = send_packet(fresh_packet)

    assert response.get("status") == "SUCCESS", response
    print("[PASS] Fresh timestamp accepted")

    # 2. A packet six minutes old should be rejected.
    old_packet = make_packet(now - timedelta(minutes=6))
    response = send_packet(old_packet)

    assert response.get("status") == "ERROR", response
    assert "expired" in response.get("error", "").lower(), response
    print("[PASS] Expired timestamp rejected")

    # 3. A packet one minute in the future should be rejected.
    future_packet = make_packet(now + timedelta(minutes=1))
    response = send_packet(future_packet)

    assert response.get("status") == "ERROR", response
    assert "future" in response.get("error", "").lower(), response
    print("[PASS] Future timestamp rejected")

    # 4. Sending the same valid packet twice should reject the replay.
    replay_packet = make_packet(datetime.now(timezone.utc))

    first = send_packet(replay_packet)
    assert first.get("status") == "SUCCESS", first

    second = send_packet(replay_packet)
    assert second.get("status") == "ERROR", second
    assert "replay" in second.get("error", "").lower(), second
    print("[PASS] Replayed packet rejected")

    print("\nAll timestamp and replay tests passed.")


if __name__ == "__main__":
    main()
