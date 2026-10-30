
"""Local TCP gateway for the Adaptive IoT Crypto project."""

import hashlib
import hmac
import json
import socketserver
from datetime import datetime, timezone, timedelta
from threading import Lock

from crypto.crypto_manager import CryptoManager
from crypto.key_config import load_optional_hmac_key


HOST = "127.0.0.1"
PORT = 5000
GATEWAY_ID = "GATEWAY-001"

MAX_PACKET_BYTES = 1_000_000
MAX_PACKET_AGE = timedelta(minutes=5)
MAX_FUTURE_SKEW = timedelta(seconds=30)

crypto_manager = CryptoManager()
hmac_key = load_optional_hmac_key()

processed_packet_ids = set()
replay_lock = Lock()

REQUIRED_FIELDS = {
    "packet_id",
    "sender_id",
    "receiver_id",
    "timestamp_utc",
    "algorithm",
    "ciphertext_hex",
    "payload_encoding",
    "hmac_sha256",
}


def calculate_hmac(packet, key):
    """Calculate HMAC-SHA-256 over all packet fields except the HMAC."""
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


def validate_timestamp(timestamp_text):
    """Parse a timezone-aware timestamp and enforce freshness."""
    if not isinstance(timestamp_text, str):
        raise ValueError("Timestamp must be a string")

    try:
        packet_time = datetime.fromisoformat(
            timestamp_text.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("Invalid timestamp format") from exc

    if packet_time.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    packet_time = packet_time.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)

    if packet_time < now - MAX_PACKET_AGE:
        raise ValueError("Packet timestamp expired")

    if packet_time > now + MAX_FUTURE_SKEW:
        raise ValueError("Packet timestamp is in the future")

    return packet_time


class GatewayHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            # 1. Read one newline-delimited JSON packet.
            raw = self.rfile.readline(MAX_PACKET_BYTES + 1)

            if not raw:
                return

            if len(raw) > MAX_PACKET_BYTES or not raw.endswith(b"\n"):
                raise ValueError("Packet is too large or incomplete")

            try:
                packet = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Invalid JSON packet") from exc

            if not isinstance(packet, dict):
                raise ValueError("Packet must be a JSON object")

            # 2. Validate required fields.
            missing = REQUIRED_FIELDS - packet.keys()
            if missing:
                raise ValueError(
                    "Packet is missing required fields: "
                    + ", ".join(sorted(missing))
                )

            # Reject unexpected fields to keep the signed packet format strict.
            unexpected = packet.keys() - REQUIRED_FIELDS
            if unexpected:
                raise ValueError(
                    "Packet contains unexpected fields: "
                    + ", ".join(sorted(unexpected))
                )

            # 3. Validate basic metadata.
            if packet["receiver_id"] != GATEWAY_ID:
                raise ValueError("Incorrect receiver ID")

            for field in ("packet_id", "sender_id"):
                value = packet[field]
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"Invalid {field}")

            if packet["payload_encoding"] != "hex":
                raise ValueError("Unsupported payload encoding")

            if not isinstance(packet["algorithm"], str):
                raise ValueError("Invalid algorithm")

            if not isinstance(packet["ciphertext_hex"], str):
                raise ValueError("Invalid ciphertext")

            # 4. Authenticate the entire packet before trusting its contents.
            received_hmac = packet["hmac_sha256"]

            if (
                not isinstance(received_hmac, str)
                or len(received_hmac) != 64
            ):
                raise ValueError("Invalid authentication tag")

            expected_hmac = calculate_hmac(packet, hmac_key)

            if not hmac.compare_digest(received_hmac, expected_hmac):
                raise ValueError("Packet authentication failed")

            # 5. Validate freshness only after authenticating the timestamp.
            validate_timestamp(packet["timestamp_utc"])

            # 6. Decode ciphertext.
            try:
                ciphertext = bytes.fromhex(packet["ciphertext_hex"])
            except ValueError as exc:
                raise ValueError("Ciphertext is not valid hexadecimal") from exc

            if not ciphertext:
                raise ValueError("Empty ciphertext")

            # 7. Check for previously processed packet IDs.
            with replay_lock:
                if packet["packet_id"] in processed_packet_ids:
                    raise ValueError("Replayed packet rejected")

            # 8. Decrypt and authenticate the encrypted payload.
            plaintext = crypto_manager.decrypt(
                packet["algorithm"],
                ciphertext,
            )

            # 9. Mark the packet as processed only after successful decryption.
            with replay_lock:
                if packet["packet_id"] in processed_packet_ids:
                    raise ValueError("Replayed packet rejected")

                processed_packet_ids.add(packet["packet_id"])

            response = {
                "status": "SUCCESS",
                "packet_id": packet["packet_id"],
                "sender_id": packet["sender_id"],
                "receiver_id": GATEWAY_ID,
                "algorithm": packet["algorithm"],
                "plaintext": plaintext,
            }

        except Exception as exc:
            print(
                f"[GATEWAY ERROR] {type(exc).__name__}: {exc}",
                flush=True,
            )
            response = {
                "status": "ERROR",
                "error": f"{type(exc).__name__}: {exc}",
            }

        # Send one JSON response to the sender.
        self.wfile.write(
            (json.dumps(response) + "\n").encode("utf-8")
        )


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with ThreadedTCPServer((HOST, PORT), GatewayHandler) as server:
        print(f"TCP gateway listening on {HOST}:{PORT}")
        print("Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nGateway shutting down.")
