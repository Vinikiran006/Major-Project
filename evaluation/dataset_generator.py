import random
import pandas as pd

from simulation.device_simulator import IoTDeviceSimulator
from adaptive.context import ContextEngine
from evaluation.benchmark import CryptoBenchmark
from evaluation.scoring import AdaptiveScorer


class DatasetGenerator:
    def __init__(self):
        self.device = IoTDeviceSimulator()
        self.context_engine = ContextEngine()
        self.benchmark = CryptoBenchmark()
        self.scorer = AdaptiveScorer()

    def generate_training_context(self):
        scenario = random.choice([
            "LOW_POWER",
            "BALANCED",
            "HIGH_SECURITY",
        ])

        if scenario == "LOW_POWER":
            return {
                "device_id": self.device.device_id,
                "battery": random.randint(5, 20),
                "cpu_usage": random.randint(15, 50),
                "memory_usage": random.randint(20, 60),
                "latency": random.randint(20, 100),
                "packet_loss": round(random.uniform(0, 5), 2),
                "data_sensitivity": random.choice(
                    ["LOW", "LOW", "MEDIUM"]
                ),
                "threat_level": random.choice(
                    ["LOW", "LOW", "MEDIUM"]
                ),
            }

        if scenario == "BALANCED":
            return {
                "device_id": self.device.device_id,
                "battery": random.randint(25, 80),
                "cpu_usage": random.randint(20, 70),
                "memory_usage": random.randint(30, 70),
                "latency": random.randint(20, 150),
                "packet_loss": round(random.uniform(0, 8), 2),
                "data_sensitivity": random.choice(
                    ["LOW", "MEDIUM", "MEDIUM"]
                ),
                "threat_level": random.choice(
                    ["LOW", "LOW", "MEDIUM"]
                ),
            }

        return {
            "device_id": self.device.device_id,
            "battery": random.randint(40, 100),
            "cpu_usage": random.randint(40, 95),
            "memory_usage": random.randint(40, 95),
            "latency": random.randint(100, 300),
            "packet_loss": round(random.uniform(5, 20), 2),
            "data_sensitivity": random.choice(
                ["HIGH", "HIGH", "MEDIUM"]
            ),
            "threat_level": random.choice(
                ["HIGH", "HIGH", "MEDIUM"]
            ),
        }

    def generate_dataset(self, number_of_samples=100):
        dataset = []

        for i in range(number_of_samples):
            print(
                f"Generating sample {i + 1}/{number_of_samples}"
            )

            raw_context = self.generate_training_context()
            context = self.context_engine.process_context(raw_context)

            message = (
                f"device={context['device_id']};"
                f"battery={context['battery']};"
                f"temperature={random.uniform(20, 40):.2f};"
                f"humidity={random.uniform(30, 80):.2f}"
            )

            results = self.benchmark.benchmark_all(
                message,
                runs=3,
                warmups=1,
            )

            decision = self.scorer.select_algorithm(context)

            row = {
                "battery": context["battery"],
                "cpu_usage": context["cpu_usage"],
                "memory_usage": context["memory_usage"],
                "latency": context["latency"],
                "packet_loss": context["packet_loss"],
                "network_status": context["network_status"],
                "data_sensitivity": context["data_sensitivity"],
                "threat_level": context["threat_level"],

                "giftcofb_encryption_time_ms":
                    results["GIFT-COFB-128"]["encryption_time_ms"],
                "ascon_encryption_time_ms":
                    results["ASCON-128"]["encryption_time_ms"],
                "aes_encryption_time_ms":
                    results["AES-128"]["encryption_time_ms"],

                "giftcofb_decryption_time_ms":
                    results["GIFT-COFB-128"]["decryption_time_ms"],
                "ascon_decryption_time_ms":
                    results["ASCON-128"]["decryption_time_ms"],
                "aes_decryption_time_ms":
                    results["AES-128"]["decryption_time_ms"],

                "giftcofb_throughput_mb_s":
                    results["GIFT-COFB-128"]["encryption_throughput_mb_s"],
                "ascon_throughput_mb_s":
                    results["ASCON-128"]["encryption_throughput_mb_s"],
                "aes_throughput_mb_s":
                    results["AES-128"]["encryption_throughput_mb_s"],

                "giftcofb_ciphertext_size_bytes":
                    results["GIFT-COFB-128"]["ciphertext_size_bytes"],
                "ascon_ciphertext_size_bytes":
                    results["ASCON-128"]["ciphertext_size_bytes"],
                "aes_ciphertext_size_bytes":
                    results["AES-128"]["ciphertext_size_bytes"],

                "best_algorithm": decision["selected_algorithm"],
                "security_requirement": decision["security_requirement"],
                "resource_pressure": decision["resource_pressure"],

                "giftcofb_score":
                    decision["scores"]["GIFT-COFB-128"],
                "ascon_score":
                    decision["scores"]["ASCON-128"],
                "aes_score":
                    decision["scores"]["AES-128"],
            }

            dataset.append(row)

        return pd.DataFrame(dataset)


if __name__ == "__main__":
    generator = DatasetGenerator()
    df = generator.generate_dataset(number_of_samples=3000)

    output_path = "data/adaptive_crypto_dataset_giftcofb.csv"
    df.to_csv(output_path, index=False)

    print("\nNew dataset generated successfully.")
    print(f"Saved to: {output_path}")
    print("Dataset shape:", df.shape)
    print("\nAlgorithm distribution:")
    print(df["best_algorithm"].value_counts())
