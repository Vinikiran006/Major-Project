
import json
from datetime import datetime, timezone

from communication.sensor_crypto import (
    encrypt_sensor_reading,
    crypto_engine,
)

reading = {
    "device_id": "IOT-001",
    "temperature": 28.6,
    "humidity": 62.0,
    "received_at_utc": datetime.now(timezone.utc).isoformat(),
}

result = encrypt_sensor_reading(reading)

print("Selected algorithm:", result["algorithm"])
print("Ciphertext generated:", bool(result["ciphertext_hex"]))

# Decrypt using the same algorithm to verify the round trip.
plaintext = crypto_engine.decrypt(
    result["algorithm"],
    bytes.fromhex(result["ciphertext_hex"]),
)

recovered = json.loads(plaintext)

print("Recovered temperature:", recovered["temperature"])
print("Recovered humidity:", recovered["humidity"])
print("Message matches:", recovered == reading)
