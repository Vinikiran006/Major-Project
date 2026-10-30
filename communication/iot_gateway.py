"""Local IoT sender/gateway simulation with basic replay protection.

This is a demonstration harness, not a production network protocol.
"""
from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict
import uuid


class IoTCommunicationSimulator:
    REQUIRED_PACKET_FIELDS = {
        "packet_id", "sender_id", "receiver_id", "timestamp_utc",
        "algorithm", "ciphertext_hex", "payload_encoding",
    }

    def __init__(self, adaptive_crypto, sender_id="IOT-001",
                 receiver_id="GATEWAY-001"):
        self.adaptive_crypto = adaptive_crypto
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.sent_packets = 0
        self.received_packets = 0
        self.processed_packet_ids = set()

    def send(self, context: Dict[str, Any], plaintext: str) -> Dict[str, Any]:
        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("plaintext must be a non-empty string")

        started = perf_counter()
        encrypted = self.adaptive_crypto.encrypt(context, plaintext)
        encryption_ms = (perf_counter() - started) * 1000
        ciphertext = encrypted.get("ciphertext")
        algorithm = encrypted.get("algorithm")
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise ValueError("encryption engine returned an invalid ciphertext")
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError("encryption engine returned no algorithm identifier")

        packet = {
            "packet_id": str(uuid.uuid4()),
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "algorithm": algorithm,
            "ciphertext_hex": bytes(ciphertext).hex(),
            "payload_encoding": "hex",
        }
        self.sent_packets += 1
        return {
            "packet": packet,
            "decision": {
                "algorithm": algorithm,
                "confidence": encrypted.get("confidence"),
                "probabilities": encrypted.get("probabilities", {}),
            },
            "encryption_ms": round(encryption_ms, 4),
            "plaintext_bytes": len(plaintext.encode("utf-8")),
            "ciphertext_bytes": len(ciphertext),
        }

    def receive(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(packet, dict):
            raise ValueError("packet must be a dictionary")

        missing = self.REQUIRED_PACKET_FIELDS.difference(packet.keys())
        if missing:
            raise ValueError(f"packet is missing required fields: {', '.join(sorted(missing))}")

        if packet["receiver_id"] != self.receiver_id:
            raise ValueError("packet receiver_id does not match this gateway")
        if not isinstance(packet["packet_id"], str) or not packet["packet_id"]:
            raise ValueError("packet_id must be a non-empty string")
        if packet["packet_id"] in self.processed_packet_ids:
            raise ValueError("replayed packet rejected: packet_id has already been processed")
        if packet["payload_encoding"] != "hex":
            raise ValueError("unsupported payload encoding")
        if not isinstance(packet["ciphertext_hex"], str) or not packet["ciphertext_hex"]:
            raise ValueError("ciphertext_hex must be a non-empty string")
        try:
            ciphertext = bytes.fromhex(packet["ciphertext_hex"])
        except ValueError as exc:
            raise ValueError("ciphertext_hex is not valid hexadecimal") from exc

        # Only mark a packet as processed after successful decryption. This prevents
        # a malformed/tampered packet from consuming an ID before it can be retried.
        started = perf_counter()
        plaintext = self.adaptive_crypto.decrypt(packet["algorithm"], ciphertext)
        decryption_ms = (perf_counter() - started) * 1000

        self.processed_packet_ids.add(packet["packet_id"])
        self.received_packets += 1
        return {
            "packet_id": packet["packet_id"],
            "sender_id": packet["sender_id"],
            "receiver_id": packet["receiver_id"],
            "algorithm": packet["algorithm"],
            "plaintext": plaintext,
            "decryption_ms": round(decryption_ms, 4),
            "received": True,
        }

    def transmit_and_receive(self, context: Dict[str, Any], plaintext: str) -> Dict[str, Any]:
        sent = self.send(context, plaintext)
        received = self.receive(sent["packet"])
        matches = received["plaintext"] == plaintext
        return {
            "packet": sent["packet"],
            "decision": sent["decision"],
            "metrics": {
                "encryption_ms": sent["encryption_ms"],
                "decryption_ms": received["decryption_ms"],
                "plaintext_bytes": sent["plaintext_bytes"],
                "ciphertext_bytes": sent["ciphertext_bytes"],
            },
            "sender": {"id": self.sender_id, "status": "ENCRYPTED"},
            "gateway": {
                "id": self.receiver_id,
                "status": "DECRYPTED" if received["received"] else "FAILED",
            },
            "received_plaintext": received["plaintext"],
            "message_matches": matches,
            "status": "SUCCESS" if matches else "MISMATCH",
            "counters": {"sent": self.sent_packets, "received": self.received_packets},
        }
