"""Run from the project root: python -m communication.test_iot_communication"""
from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine
from simulation.device_simulator import IoTDeviceSimulator
from communication.iot_gateway import IoTCommunicationSimulator


def main():
    print("=" * 68)
    print(" ADAPTIVE IOT CRYPTOGRAPHY - SENDER / GATEWAY COMMUNICATION TEST")
    print("=" * 68)

    simulator = IoTDeviceSimulator()
    context_engine = ContextEngine()
    crypto_engine = AdaptiveCryptoEngine(model_path="models/adaptive_crypto_model_giftcofb_v2.pkl")
    communication = IoTCommunicationSimulator(crypto_engine)

    scenarios = [
        ("NORMAL", simulator.normal_scenario()),
        ("LOW BATTERY", simulator.low_battery_scenario()),
        ("SENSITIVE DATA", simulator.sensitive_data_scenario()),
        ("ATTACK", simulator.attack_scenario()),
    ]

    message = "Temperature=28.6C;Humidity=62%;Device=IOT-001"

    for label, raw_context in scenarios:
        print(f"\n--- {label} ---")
        context = context_engine.process_context(raw_context)
        result = communication.transmit_and_receive(context, message)
        print(f"Selected algorithm : {result['decision']['algorithm']}")
        print(f"Sender             : {result['sender']['id']} ({result['sender']['status']})")
        print(f"Gateway            : {result['gateway']['id']} ({result['gateway']['status']})")
        print(f"Packet ID          : {result['packet']['packet_id']}")
        print(f"Ciphertext bytes   : {result['metrics']['ciphertext_bytes']}")
        print(f"Encryption time    : {result['metrics']['encryption_ms']:.4f} ms")
        print(f"Decryption time    : {result['metrics']['decryption_ms']:.4f} ms")
        print(f"Message matches    : {result['message_matches']}")
        print(f"Result             : {result['status']}")
        if not result["message_matches"]:
            raise AssertionError(f"Round-trip verification failed in {label}")

    print("\nAll local sender-to-gateway round-trip checks passed.")
    print("Note: this is a local simulation, not real network transport.")


if __name__ == "__main__":
    main()

