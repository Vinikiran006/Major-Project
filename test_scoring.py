from simulation.device_simulator import IoTDeviceSimulator
from adaptive.context import ContextEngine
from evaluation.scoring import AdaptiveScorer


device = IoTDeviceSimulator()

context_engine = ContextEngine()

scorer = AdaptiveScorer()


scenarios = {
    "Normal": device.normal_scenario(),
    "Low Battery": device.low_battery_scenario(),
    "Sensitive Data": device.sensitive_data_scenario(),
    "Network Attack": device.attack_scenario()
}


for name, raw_context in scenarios.items():

    context = context_engine.process_context(
        raw_context
    )

    result = scorer.select_algorithm(
        context
    )

    print("\n" + "=" * 60)

    print(f"SCENARIO: {name}")

    print("=" * 60)

    print(
        f"Battery          : "
        f"{context['battery']}%"
    )

    print(
        f"Data Sensitivity : "
        f"{context['data_sensitivity']}"
    )

    print(
        f"Threat Level     : "
        f"{context['threat_level']}"
    )

    print(
        f"Network Status   : "
        f"{context['network_status']}"
    )

    print(
        f"\nSecurity Requirement : "
        f"{result['security_requirement']:.2f}"
    )

    print(
        f"Resource Pressure    : "
        f"{result['resource_pressure']:.2f}"
    )

    print("\nAlgorithm Scores:")

    for algorithm, score in result["scores"].items():

        print(
            f"{algorithm:<12} : "
            f"{score:.4f}"
        )

    print(
        f"\nSELECTED ALGORITHM : "
        f"{result['selected_algorithm']}"
    )