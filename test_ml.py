from simulation.device_simulator import IoTDeviceSimulator
from adaptive.context import ContextEngine
from ml.predictor import CryptoDecisionEngine


device = IoTDeviceSimulator()

context_engine = ContextEngine()

decision_engine = CryptoDecisionEngine()


scenarios = {
    "Normal":
        device.normal_scenario(),

    "Low Battery":
        device.low_battery_scenario(),

    "Sensitive Data":
        device.sensitive_data_scenario(),

    "Network Attack":
        device.attack_scenario()
}


for name, raw_context in scenarios.items():

    context = (
        context_engine.process_context(
            raw_context
        )
    )

    result = (
        decision_engine.predict(
            context
        )
    )

    print("\n" + "=" * 60)

    print(
        f"SCENARIO: {name}"
    )

    print("=" * 60)

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

    print("\nML DECISION")

    print(
        f"Selected Algorithm : "
        f"{result['algorithm']}"
    )

    print(
        f"Confidence         : "
        f"{result['confidence']:.2f}%"
    )

    print("\nClass Probabilities:")

    for algorithm, probability in (
        result["probabilities"].items()
    ):

        print(
            f"{algorithm:<12}: "
            f"{probability:.2f}%"
        )