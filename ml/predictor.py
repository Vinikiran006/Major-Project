# ============================================================
# Adaptive IoT Security Framework
# Stage 4 - ML Prediction Engine
# ============================================================

import joblib
import pandas as pd


class CryptoDecisionEngine:

    def __init__(
        self,
        model_path="models/adaptive_crypto_model_giftcofb_v2.pkl"
    ):

        self.model = joblib.load(
            model_path
        )

    def predict(self, context):

        data = pd.DataFrame([
            {
                "battery":
                    context["battery"],

                "cpu_usage":
                    context["cpu_usage"],

                "memory_usage":
                    context["memory_usage"],

                "latency":
                    context["latency"],

                "packet_loss":
                    context["packet_loss"],

                "network_status": context["network_status"],

                "data_sensitivity":
                    context["data_sensitivity"],

                "threat_level":
                    context["threat_level"]
            }
        ])

        prediction = self.model.predict(
            data
        )[0]

        probabilities = (
            self.model.predict_proba(data)[0]
        )

        classes = (
            self.model
            .named_steps["classifier"]
            .classes_
        )

        confidence = (
            max(probabilities) * 100
        )

        probability_map = {
            algorithm: probability * 100
            for algorithm, probability
            in zip(classes, probabilities)
        }

        return {
            "algorithm": prediction,
            "confidence": confidence,
            "probabilities": probability_map
        }