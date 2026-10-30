
"""Send encrypted sensor readings to the authenticated TCP gateway."""

import hashlib
import hmac
import json
import socket
import uuid
from datetime import datetime, timezone

from crypto.key_config import load_optional_hmac_key

HOST = "127.0.0.1"
PORT = 5000
SENDER_ID = "IOT-001"
GATEWAY_ID = "GATEWAY-001"


def calculate_hmac(packet, key):
    """Sign all packet fields except the signature itself."""
    content = {
        field: value
        for field, value in packet.items()
        if field != "hmac_sha256"
    }

    serialized = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hmac.new(key, serialized, hashlib.sha256).hexdigest()


def send_encrypted_sensor_reading(encrypted):
    """Forward ciphertext to the TCP gateway using the existing protocol."""
    hmac_key = load_optional_hmac_key()

    packet = {
        "packet_id": str(uuid.uuid4()),
        "sender_id": SENDER_ID,
        "receiver_id": GATEWAY_ID,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": encrypted["algorithm"],
        "ciphertext_hex": encrypted["ciphertext_hex"],
        "payload_encoding": encrypted["payload_encoding"],
    }
    packet["hmac_sha256"] = calculate_hmac(packet, hmac_key)

    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall((json.dumps(packet) + "\n").encode("utf-8"))

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

    return response
