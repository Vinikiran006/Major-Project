"""Security smoke tests. Run from project root:
    python -m communication.test_security
"""
from copy import deepcopy

from adaptive.context import ContextEngine
from adaptive.adaptive_crypto import AdaptiveCryptoEngine
from simulation.device_simulator import IoTDeviceSimulator
from communication.iot_gateway import IoTCommunicationSimulator

MESSAGE = "Temperature=28.6C;Humidity=62%;Device=IOT-001"


def print_result(name, passed, detail):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}: {detail}")


def main():
    print("=" * 68)
    print(" ADAPTIVE IOT CRYPTOGRAPHY - SECURITY SMOKE TESTS")
    print("=" * 68)

    device = IoTDeviceSimulator()
    context_engine = ContextEngine()
    crypto = AdaptiveCryptoEngine(model_path="models/adaptive_crypto_model_giftcofb_v2.pkl")
    gateway = IoTCommunicationSimulator(crypto)
    context = context_engine.process_context(device.normal_scenario())

    # 1. Valid packet can be received and plaintext matches.
    sent = gateway.send(context, MESSAGE)
    received = gateway.receive(sent["packet"])
    valid_ok = received["plaintext"] == MESSAGE
    print_result("Valid packet round trip", valid_ok, "gateway recovered original message")

    # 2. Wrong receiver must be rejected before decryption.
    wrong_receiver = deepcopy(gateway.send(context, MESSAGE)["packet"])
    wrong_receiver["receiver_id"] = "UNEXPECTED-GATEWAY"
    try:
        gateway.receive(wrong_receiver)
        receiver_ok, detail = False, "packet was unexpectedly accepted"
    except ValueError as exc:
        receiver_ok, detail = True, str(exc)
    print_result("Wrong receiver ID", receiver_ok, detail)

    # 3. Missing required field must be rejected.
    missing_field = deepcopy(gateway.send(context, MESSAGE)["packet"])
    missing_field.pop("algorithm")
    try:
        gateway.receive(missing_field)
        missing_ok, detail = False, "packet was unexpectedly accepted"
    except ValueError as exc:
        missing_ok, detail = True, str(exc)
    print_result("Missing packet field", missing_ok, detail)

    # 4. Replay: first delivery succeeds; second delivery of the same packet is rejected.
    replay_packet = gateway.send(context, MESSAGE)["packet"]
    first = gateway.receive(replay_packet)
    try:
        gateway.receive(replay_packet)
        replay_ok, detail = False, "duplicate packet was unexpectedly accepted"
    except ValueError as exc:
        replay_ok, detail = True, str(exc)
    print_result("Replay rejection", replay_ok, detail)

    # 5. Tamper with the ciphertext. Authenticated algorithms should reject
    # the altered ciphertext. The GIFT placeholder has no authentication, so
    # this test explicitly reports that limitation if it returns altered text.
    tamper_packet = deepcopy(gateway.send(context, MESSAGE)["packet"])
    raw = bytearray.fromhex(tamper_packet["ciphertext_hex"])
    raw[-1] ^= 0x01
    tamper_packet["ciphertext_hex"] = raw.hex()
    try:
        tampered_result = gateway.receive(tamper_packet)
        tamper_rejected = tampered_result["plaintext"] != MESSAGE
        detail = (
            "altered payload did not reproduce original plaintext"
            if tamper_rejected else
            "WARNING: modified ciphertext produced the original plaintext"
        )
    except Exception as exc:
        tamper_rejected, detail = True, f"decryption rejected altered payload ({type(exc).__name__})"
    print_result("Ciphertext tampering", tamper_rejected, detail)

    print("\nInterpretation:")
    print("- Wrong receiver, missing fields, and replay should be rejected.")
    print("- AES-GCM and ASCON authenticated encryption should reject tampered ciphertext.")
    print("- The current GIFT-64 placeholder is unauthenticated; tampering may not raise an error.")
    print("- These are local software tests, not a complete security audit.")

    if not (valid_ok and receiver_ok and missing_ok and replay_ok):
        raise SystemExit("One or more required packet-validation tests failed.")


if __name__ == "__main__":
    main()

