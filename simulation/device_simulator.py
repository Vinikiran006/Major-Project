# ============================================================
# Adaptive IoT Security Framework
# Stage 1 - IoT Device Simulator
# ============================================================

import random


class IoTDeviceSimulator:

    def __init__(self, device_id="IOT-001"):
        self.device_id = device_id

    # --------------------------------------------------------
    # Random simulation
    # --------------------------------------------------------

    def generate_context(self):

        return {
            "device_id": self.device_id,

            # Device conditions
            "battery": random.randint(5, 100),
            "cpu_usage": random.randint(10, 95),
            "memory_usage": random.randint(20, 90),

            # Network conditions
            "latency": random.randint(10, 300),
            "packet_loss": round(random.uniform(0, 20), 2),

            # Security context
            "data_sensitivity": random.choice([
                "LOW",
                "MEDIUM",
                "HIGH"
            ]),

            "threat_level": random.choice([
                "LOW",
                "MEDIUM",
                "HIGH"
            ])
        }

    # --------------------------------------------------------
    # Scenario 1 - Normal IoT operation
    # --------------------------------------------------------

    def normal_scenario(self):

        return {
            "device_id": self.device_id,

            "battery": 80,
            "cpu_usage": 35,
            "memory_usage": 45,

            "latency": 35,
            "packet_loss": 1,

            "data_sensitivity": "MEDIUM",
            "threat_level": "LOW"
        }

    # --------------------------------------------------------
    # Scenario 2 - Low battery
    # --------------------------------------------------------

    def low_battery_scenario(self):

        return {
            "device_id": self.device_id,

            "battery": 10,
            "cpu_usage": 35,
            "memory_usage": 45,

            "latency": 35,
            "packet_loss": 1,

            "data_sensitivity": "LOW",
            "threat_level": "LOW"
        }

    # --------------------------------------------------------
    # Scenario 3 - Sensitive data
    # --------------------------------------------------------

    def sensitive_data_scenario(self):

        return {
            "device_id": self.device_id,

            "battery": 85,
            "cpu_usage": 40,
            "memory_usage": 50,

            "latency": 40,
            "packet_loss": 1,

            "data_sensitivity": "HIGH",
            "threat_level": "LOW"
        }

    # --------------------------------------------------------
    # Scenario 4 - Network attack
    # --------------------------------------------------------

    def attack_scenario(self):

        return {
            "device_id": self.device_id,

            "battery": 75,
            "cpu_usage": 85,
            "memory_usage": 88,

            "latency": 250,
            "packet_loss": 18,

            "data_sensitivity": "HIGH",
            "threat_level": "HIGH"
        }