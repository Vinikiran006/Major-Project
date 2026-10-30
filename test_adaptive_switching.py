# ============================================================
# Adaptive IoT Security Framework
# Stage 5.2 - Dynamic Adaptive Switching
# ============================================================

from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine


# ============================================================
# Initialize
# ============================================================

context_engine = ContextEngine()

adaptive_crypto = AdaptiveCryptoEngine()


# ============================================================
# Simulated device states
# ============================================================

states = [

    {
        "name": "NORMAL OPERATION",

        "battery": 80,
        "cpu_usage": 35,
        "memory_usage": 45,
        "latency": 35,
        "packet_loss": 1,

        "data_sensitivity": "MEDIUM",
        "threat_level": "LOW"
    },

    {
        "name": "LOW POWER MODE",

        "battery": 10,
        "cpu_usage": 30,
        "memory_usage": 40,
        "latency": 40,
        "packet_loss": 1,

        "data_sensitivity": "LOW",
        "threat_level": "LOW"
    },

    {
        "name": "SECURITY ATTACK",

        "battery": 70,
        "cpu_usage": 85,
        "memory_usage": 88,
        "latency": 250,
        "packet_loss": 18,

        "data_sensitivity": "HIGH",
        "threat_level": "HIGH"
    },

    {
        "name": "RECOVERY",

        "battery": 65,
        "cpu_usage": 40,
        "memory_usage": 50,
        "latency": 45,
        "packet_loss": 2,

        "data_sensitivity": "MEDIUM",
        "threat_level": "LOW"
    }
]


# ============================================================
# Run adaptive simulation
# ============================================================

print()
print("=" * 75)
print("        ADAPTIVE IoT CRYPTOGRAPHY")
print("             LIVE SWITCHING DEMO")
print("=" * 75)


previous_algorithm = None


for step, state in enumerate(states, start=1):

    print()
    print("-" * 75)

    print(
        f"STEP {step}: "
        f"{state['name']}"
    )

    print("-" * 75)

    # --------------------------------------------------------
    # Build context
    # --------------------------------------------------------

    raw_context = {

        "device_id": "IOT-001",

        "battery":
            state["battery"],

        "cpu_usage":
            state["cpu_usage"],

        "memory_usage":
            state["memory_usage"],

        "latency":
            state["latency"],

        "packet_loss":
            state["packet_loss"],

        "data_sensitivity":
            state["data_sensitivity"],

        "threat_level":
            state["threat_level"]
    }

    context = (
        context_engine.process_context(
            raw_context
        )
    )

    # --------------------------------------------------------
    # Display context
    # --------------------------------------------------------

    print(
        f"Battery          : "
        f"{context['battery']}%"
    )

    print(
        f"CPU Usage        : "
        f"{context['cpu_usage']}%"
    )

    print(
        f"Memory Usage     : "
        f"{context['memory_usage']}%"
    )

    print(
        f"Latency          : "
        f"{context['latency']} ms"
    )

    print(
        f"Packet Loss      : "
        f"{context['packet_loss']}%"
    )

    print(
        f"Data Sensitivity : "
        f"{context['data_sensitivity']}"
    )

    print(
        f"Threat Level     : "
        f"{context['threat_level']}"
    )

    # --------------------------------------------------------
    # ML decision
    # --------------------------------------------------------

    result = adaptive_crypto.select_algorithm(
        context
    )

    algorithm = result["algorithm"]

    confidence = result["confidence"]

    print()
    print(
        f"ML Selected Algorithm : "
        f"{algorithm}"
    )

    print(
        f"Confidence             : "
        f"{confidence:.2f}%"
    )

    # --------------------------------------------------------
    # Detect algorithm change
    # --------------------------------------------------------

    if previous_algorithm is None:

        print(
            "Status                 : INITIAL SELECTION"
        )

    elif algorithm != previous_algorithm:

        print(
            f"Status                 : "
            f"ALGORITHM SWITCHED "
            f"{previous_algorithm} → {algorithm}"
        )

    else:

        print(
            "Status                 : "
            "ALGORITHM UNCHANGED"
        )

    # --------------------------------------------------------
    # Encrypt IoT data
    # --------------------------------------------------------

    message = (
        f"Device=IOT-001;"
        f"Temperature=28.6C;"
        f"Humidity=62%;"
        f"Step={step}"
    )

    encryption_result = (
        adaptive_crypto.encrypt(
            context,
            message
        )
    )

    # --------------------------------------------------------
    # Verify decryption
    # --------------------------------------------------------

    decrypted = (
        adaptive_crypto.decrypt(
            encryption_result["algorithm"],
            encryption_result["ciphertext"]
        )
    )

    if decrypted == message:

        print(
            "Encryption Status      : SUCCESS"
        )

    else:

        print(
            "Encryption Status      : FAILED"
        )

    previous_algorithm = algorithm


print()
print("=" * 75)
print("              SIMULATION COMPLETE")
print("=" * 75)