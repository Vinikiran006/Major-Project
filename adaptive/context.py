# ============================================================
# Adaptive IoT Security Framework
# Stage 1 - Context Engine
# ============================================================

from config import (
    BATTERY_HIGH,
    BATTERY_MEDIUM,
    BATTERY_LOW,

    LATENCY_NORMAL,
    LATENCY_UNSTABLE,

    PACKET_LOSS_NORMAL,
    PACKET_LOSS_UNSTABLE,

    CPU_HIGH,
    MEMORY_HIGH
)


class ContextEngine:

    # --------------------------------------------------------
    # Battery classification
    # --------------------------------------------------------

    def classify_battery(self, battery):

        if battery > BATTERY_HIGH:
            return "HIGH"

        elif battery > BATTERY_MEDIUM:
            return "MEDIUM"

        elif battery > BATTERY_LOW:
            return "LOW"

        else:
            return "CRITICAL"

    # --------------------------------------------------------
    # Network classification
    # --------------------------------------------------------

    def classify_network(self, latency, packet_loss):

        if (
            latency <= LATENCY_NORMAL
            and packet_loss <= PACKET_LOSS_NORMAL
        ):
            return "NORMAL"

        elif (
            latency <= LATENCY_UNSTABLE
            and packet_loss <= PACKET_LOSS_UNSTABLE
        ):
            return "UNSTABLE"

        else:
            return "POOR"

    # --------------------------------------------------------
    # CPU and memory classification
    # --------------------------------------------------------

    def classify_resources(self, cpu_usage, memory_usage):

        if (
            cpu_usage >= CPU_HIGH
            or memory_usage >= MEMORY_HIGH
        ):
            return "HIGH"

        return "NORMAL"

    # --------------------------------------------------------
    # Process complete device context
    # --------------------------------------------------------

    def process_context(self, raw_context):

        battery_status = self.classify_battery(
            raw_context["battery"]
        )

        network_status = self.classify_network(
            raw_context["latency"],
            raw_context["packet_loss"]
        )

        resource_status = self.classify_resources(
            raw_context["cpu_usage"],
            raw_context["memory_usage"]
        )

        return {
            **raw_context,

            "battery_status": battery_status,
            "network_status": network_status,
            "resource_status": resource_status
        }