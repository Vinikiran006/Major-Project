from time import perf_counter
from flask import Flask, jsonify, render_template
from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine

app = Flask(__name__)

context_engine = ContextEngine()
adaptive_crypto = AdaptiveCryptoEngine(model_path="models/adaptive_crypto_model_giftcofb_v2.pkl")

SCENARIOS = [
    {
        "name": "NORMAL OPERATION",
        "battery": 80, "cpu_usage": 35, "memory_usage": 45,
        "latency": 35, "packet_loss": 1,
        "data_sensitivity": "MEDIUM", "threat_level": "LOW",
    },
    {
        "name": "LOW POWER",
        "battery": 10, "cpu_usage": 30, "memory_usage": 40,
        "latency": 40, "packet_loss": 1,
        "data_sensitivity": "LOW", "threat_level": "LOW",
    },
    {
        "name": "SECURITY ATTACK",
        "battery": 70, "cpu_usage": 85, "memory_usage": 88,
        "latency": 250, "packet_loss": 18,
        "data_sensitivity": "HIGH", "threat_level": "HIGH",
    },
    {
        "name": "RECOVERY",
        "battery": 65, "cpu_usage": 40, "memory_usage": 50,
        "latency": 45, "packet_loss": 2,
        "data_sensitivity": "MEDIUM", "threat_level": "LOW",
    },
]

DEVICE_MESSAGE = "Temperature=28.6C;Humidity=62%;Device=IOT-001"
current_scenario = 0
history = []
latest_snapshot = None


def build_context(state):
    raw_context = {
        "device_id": "IOT-001",
        "battery": state["battery"],
        "cpu_usage": state["cpu_usage"],
        "memory_usage": state["memory_usage"],
        "latency": state["latency"],
        "packet_loss": state["packet_loss"],
        "data_sensitivity": state["data_sensitivity"],
        "threat_level": state["threat_level"],
    }
    return context_engine.process_context(raw_context)


def run_scenario():
    """Run one encryption/decryption cycle and cache its result."""
    global latest_snapshot
    state = SCENARIOS[current_scenario]
    context = build_context(state)

    encryption_start = perf_counter()
    encrypted = adaptive_crypto.encrypt(context, DEVICE_MESSAGE)
    encryption_ms = (perf_counter() - encryption_start) * 1000

    algorithm = encrypted["algorithm"]
    ciphertext_bytes = encrypted["ciphertext"]

    decryption_start = perf_counter()
    decrypted = adaptive_crypto.decrypt(algorithm, ciphertext_bytes)
    decryption_ms = (perf_counter() - decryption_start) * 1000
    verified = decrypted == DEVICE_MESSAGE

    previous_algorithm = history[-1]["algorithm"] if history else None
    if previous_algorithm is None:
        switch = "INITIAL"
    elif previous_algorithm != algorithm:
        switch = f"{previous_algorithm} â†’ {algorithm}"
    else:
        switch = "UNCHANGED"

    history.append({
        "scenario": state["name"],
        "algorithm": algorithm,
        "confidence": round(float(encrypted["confidence"]), 2),
        "switch": switch,
        "verified": verified,
    })

    probabilities = {
        key: round(float(value), 2)
        for key, value in encrypted.get("probabilities", {}).items()
    }

    latest_snapshot = {
        "device_id": "IOT-001",
        "scenario": state["name"],
        "battery": state["battery"],
        "cpu_usage": state["cpu_usage"],
        "memory_usage": state["memory_usage"],
        "latency": state["latency"],
        "packet_loss": state["packet_loss"],
        "data_sensitivity": state["data_sensitivity"],
        "threat_level": state["threat_level"],
        "algorithm": algorithm,
        "confidence": round(float(encrypted["confidence"]), 2),
        "probabilities": probabilities,
        "ciphertext": ciphertext_bytes.hex(),
        "plaintext": DEVICE_MESSAGE,
        "decrypted_text": decrypted,
        "encryption_ms": round(encryption_ms, 4),
        "decryption_ms": round(decryption_ms, 4),
        "encryption_success": bool(ciphertext_bytes),
        "decryption_success": verified,
        "message_match": verified,
        "switch": switch,
        "history": history[-10:],
        "available_algorithms": adaptive_crypto.available_algorithms(),
    }
    return latest_snapshot


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status", methods=["GET"])
def status():
    # Read-only: refreshing/polling the dashboard does not encrypt again
    # or add duplicate history entries.
    if latest_snapshot is None:
        return jsonify(run_scenario())
    return jsonify(latest_snapshot)


@app.route("/api/next", methods=["POST"])
def next_scenario():
    global current_scenario
    current_scenario = (current_scenario + 1) % len(SCENARIOS)
    return jsonify(run_scenario())


@app.route("/api/reset", methods=["POST"])
def reset():
    global current_scenario, history, latest_snapshot
    current_scenario = 0
    history = []
    latest_snapshot = None
    return jsonify(run_scenario())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

