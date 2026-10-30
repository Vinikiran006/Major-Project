
"""Bridge sensor readings to the adaptive encryption engine."""

import json

from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine

context_engine = ContextEngine()
crypto_engine = AdaptiveCryptoEngine(
    model_path="models/adaptive_crypto_model_giftcofb_v2.pkl"
)


def encrypt_sensor_reading(reading):
    """Encrypt a sensor reading using adaptive algorithm selection."""

    # Temporary context values for development.
    # Replace these with real measurements when available.
    context = context_engine.process_context({
        "device_id": reading["device_id"],
        "battery": 80,
        "cpu_usage": 35,
        "memory_usage": 45,
        "latency": 35,
        "packet_loss": 1,
        "data_sensitivity": "MEDIUM",
        "threat_level": "LOW",
    })

    plaintext = json.dumps({
        "device_id": reading["device_id"],
        "temperature": reading["temperature"],
        "humidity": reading["humidity"],
        "received_at_utc": reading["received_at_utc"],
    }, separators=(",", ":"))

    result = crypto_engine.encrypt(context, plaintext)

    return {
        "device_id": reading["device_id"],
        "algorithm": result["algorithm"],
        "ciphertext_hex": result["ciphertext"].hex(),
        "payload_encoding": "hex",
    }
