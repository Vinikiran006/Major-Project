
# ============================================================
# Adaptive IoT Security Framework
# Stage 5 - End-to-End Adaptive Encryption Test
# ============================================================

from simulation.device_simulator import IoTDeviceSimulator
from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine


# ============================================================
# Initialize components
# ============================================================

device = IoTDeviceSimulator()
context_engine = ContextEngine()
adaptive_crypto = AdaptiveCryptoEngine()


# ============================================================
# Test scenarios
# ============================================================

scenarios = {
    "Normal": device.normal_scenario(),
    "Low Battery": device.low_battery_scenario(),
    "Sensitive Data": device.sensitive_data_scenario(),
    "Network Attack": device.attack_scenario(),
}


# ============================================================
# Run adaptive encryption
# ============================================================

for name, raw_context in scenarios.items():

    print("\n")
    print("=" * 70)
    print(f"SCENARIO: {name}")
    print("=" * 70)

    # Process context
    context = context_engine.process_context(raw_context)

    print(f"\nBattery          : {context['battery']}%")
    print(f"CPU Usage        : {context['cpu_usage']}%")
    print(f"Memory Usage     : {context['memory_usage']}%")
    print(f"Latency          : {context['latency']} ms")
    print(f"Packet Loss      : {context['packet_loss']}%")
    print(f"Data Sensitivity : {context['data_sensitivity']}")
    print(f"Threat Level     : {context['threat_level']}")

    # IoT sensor message
    message = (
        f"Temperature=28.6C;"
        f"Humidity=62%;"
        f"Device={context['device_id']}"
    )

    print("\nOriginal Message:")
    print(message)

    # Adaptive encryption
    result = adaptive_crypto.encrypt(context, message)

    # Display the policy decision and ML prediction separately
    print("\nPolicy-Selected Algorithm:")
    print(result["policy_algorithm"])

    print("\nML-Predicted Algorithm:")
    print(result["ml_algorithm"])

    print(f"ML Confidence: {result['confidence']:.2f}%")

    # Display ciphertext
    print("\nCiphertext:")
    print(result["ciphertext"].hex())

    # Decryption verification uses the actual selected algorithm
    decrypted = adaptive_crypto.decrypt(
        result["algorithm"],
        result["ciphertext"],
    )

    print("\nDecrypted Message:")
    print(decrypted)

    # Verify round trip
    if decrypted == message:
        print("\nSTATUS: SUCCESS")
    else:
        print("\nSTATUS: FAILED")
        raise AssertionError(
            f"Decryption mismatch in scenario: {name}"
        )
