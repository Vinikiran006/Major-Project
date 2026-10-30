# ============================================================
# Adaptive IoT Security Framework
# Adaptive Algorithm Scoring
# ============================================================


class AdaptiveScorer:

    def __init__(self):
        # Initial policy assumptions; validate using device benchmarks.
        self.resource_cost = {
            "GIFT-COFB-128": 0.30,
            "ASCON-128": 0.40,
            "AES-128": 0.70,
        }

        # Policy scores, not formal security-strength measurements.
        self.security_capability = {
            "GIFT-COFB-128": 0.80,
            "ASCON-128": 0.80,
            "AES-128": 1.00,
        }

    def calculate_security_requirement(self, context):
        score = 0.0

        sensitivity = context["data_sensitivity"]
        if sensitivity == "LOW":
            score += 0.10
        elif sensitivity == "MEDIUM":
            score += 0.30
        elif sensitivity == "HIGH":
            score += 0.50

        threat = context["threat_level"]
        if threat == "LOW":
            score += 0.10
        elif threat == "MEDIUM":
            score += 0.30
        elif threat == "HIGH":
            score += 0.50

        network = context["network_status"]
        if network == "NORMAL":
            score += 0.00
        elif network == "UNSTABLE":
            score += 0.10
        elif network == "POOR":
            score += 0.20

        return min(score, 1.0)

    def calculate_resource_pressure(self, context):
        pressure = 0.0

        battery = context["battery"]
        if battery <= 15:
            pressure += 0.50
        elif battery <= 30:
            pressure += 0.35
        elif battery <= 50:
            pressure += 0.20
        else:
            pressure += 0.05

        cpu = context["cpu_usage"]
        if cpu >= 80:
            pressure += 0.25
        elif cpu >= 60:
            pressure += 0.15
        else:
            pressure += 0.05

        memory = context["memory_usage"]
        if memory >= 80:
            pressure += 0.25
        elif memory >= 60:
            pressure += 0.15
        else:
            pressure += 0.05

        return min(pressure, 1.0)

    def score_algorithm(
        self, algorithm, security_requirement, resource_pressure
    ):
        security = self.security_capability[algorithm]
        resource = self.resource_cost[algorithm]

        security_deficit = max(security_requirement - security, 0)
        security_margin = max(security - security_requirement, 0)
        resource_penalty = resource * resource_pressure

        return (
            security_deficit * 5.0
            + security_margin * 0.20
            + resource_penalty
        )

    def select_algorithm(self, context):
        security_requirement = self.calculate_security_requirement(context)
        resource_pressure = self.calculate_resource_pressure(context)

        if security_requirement <= 0.30 and resource_pressure >= 0.40:
            selected_algorithm = "GIFT-COFB-128"
        elif security_requirement > 0.60:
            selected_algorithm = "AES-128"
        else:
            selected_algorithm = "ASCON-128"

        scores = {
            algorithm: self.score_algorithm(
                algorithm, security_requirement, resource_pressure
            )
            for algorithm in self.resource_cost
        }

        return {
            "selected_algorithm": selected_algorithm,
            "security_requirement": security_requirement,
            "resource_pressure": resource_pressure,
            "scores": scores,
        }
