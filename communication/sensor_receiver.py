
"""Receive temperature and humidity readings from an ESP32."""
from communication.sensor_crypto import encrypt_sensor_reading
from flask import Flask, jsonify, request
from datetime import datetime, timezone
from math import isfinite
from communication.sensor_tcp import send_encrypted_sensor_reading

app = Flask(__name__)


@app.route("/sensor", methods=["POST"])
def receive_sensor():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    device_id = data.get("device_id")
    temperature = data.get("temperature")
    humidity = data.get("humidity")

    if not isinstance(device_id, str) or not device_id.strip():
        return jsonify({"error": "device_id must be a non-empty string"}), 400

    # Reject booleans and non-numeric values.
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not isfinite(temperature)
    ):
        return jsonify({"error": "temperature must be a finite number"}), 400

    if (
        isinstance(humidity, bool)
        or not isinstance(humidity, (int, float))
        or not isfinite(humidity)
        or not 0 <= humidity <= 100
    ):
        return jsonify({"error": "humidity must be between 0 and 100"}), 400

    reading = {
        "device_id": device_id.strip(),
        "temperature": float(temperature),
        "humidity": float(humidity),
        "received_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    print("Received sensor reading:", reading, flush=True)

    try:
        encrypted = encrypt_sensor_reading(reading)
    except Exception:
        app.logger.exception("Sensor encryption failed")
        return jsonify({"error": "Sensor encryption failed"}), 500

    print("Encryption algorithm:", encrypted["algorithm"], flush=True)
    try:
        gateway_response = send_encrypted_sensor_reading(encrypted)
    except Exception:
        app.logger.exception("TCP gateway forwarding failed")
        return jsonify({
            "error": "Sensor was encrypted, but gateway forwarding failed"
        }), 502

    return jsonify({
        "status": "delivered",
        "device_id": encrypted["device_id"],
        "algorithm": encrypted["algorithm"],
        "gateway": gateway_response["receiver_id"],
        "gateway_status": gateway_response["status"],
        "decrypted_message": gateway_response["plaintext"],
    }), 200


if __name__ == "__main__":
    # Local development only. Use a trusted network for hardware testing.
    app.run(host="0.0.0.0", port=5001, debug=False)
