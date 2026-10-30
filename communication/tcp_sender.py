
"""Adaptive IoT sender using TCP transport."""

import json
import socket
import uuid
import hashlib
import hmac

from crypto.key_config import load_optional_hmac_key
from datetime import datetime, timezone

from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine
from simulation.device_simulator import IoTDeviceSimulator

HOST = "127.0.0.1"
PORT = 5000
SENDER_ID = "IOT-001"
GATEWAY_ID = "GATEWAY-001"

def calculate_hmac(packet, key):
    # The signature itself must not be included in the signed content.
    content = json.dumps(
        packet,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hmac.new(key, content, hashlib.sha256).hexdigest()

def main():
    hmac_key = load_optional_hmac_key()
    simulator = IoTDeviceSimulator()
    context_engine = ContextEngine()
    adaptive_crypto = AdaptiveCryptoEngine(
        model_path="models/adaptive_crypto_model_giftcofb_v2.pkl"
    )

    context = context_engine.process_context(
        simulator.normal_scenario()
    )
    message = "Temperature=28.6C;Humidity=62%;Device=IOT-001"

    encrypted = adaptive_crypto.encrypt(context, message)

    packet = {
        "packet_id": str(uuid.uuid4()),
        "sender_id": SENDER_ID,
        "receiver_id": GATEWAY_ID,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": encrypted["algorithm"],
        "ciphertext_hex": encrypted["ciphertext"].hex(),
        "payload_encoding": "hex",
    }
    packet["hmac_sha256"] = calculate_hmac(packet, hmac_key)

    print("Adaptive encryption complete")
    print("Algorithm:", packet["algorithm"])
    print("Packet ID:", packet["packet_id"])
    print("Connecting to gateway...")

    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(
            (json.dumps(packet) + "\n").encode("utf-8")
        )

        with sock.makefile("rb") as stream:
            raw_response = stream.readline(1_000_001)

    if not raw_response:
        raise RuntimeError("Gateway closed the connection without a response")

    response = json.loads(raw_response.decode("utf-8"))

    if response.get("status") != "SUCCESS":
        raise RuntimeError(
            "Gateway rejected the packet: "
            + response.get("error", "Unknown error")
        )

    recovered = response["plaintext"]
    print("\nGateway response received")
    print("Gateway:", response["receiver_id"])
    print("Decryption algorithm:", response["algorithm"])
    print("Recovered message:", recovered)
    print("Message matches:", recovered == message)

    if recovered != message:
        raise AssertionError("Sender/gateway message mismatch")

    print("\nTCP communication test PASSED")


if __name__ == "__main__":
    main()

