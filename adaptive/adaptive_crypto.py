
# ============================================================
# Adaptive IoT Security Framework
# Stage 5 - Adaptive Crypto Engine
# ============================================================

from ml.predictor import CryptoDecisionEngine
from crypto.crypto_manager import CryptoManager
from evaluation.scoring import AdaptiveScorer


class AdaptiveCryptoEngine:

    def __init__(
        self,
        model_path="models/adaptive_crypto_model_giftcofb_v2.pkl"
    ):
        # ML prediction engine
        self.ml_engine = CryptoDecisionEngine(model_path)

        # Authoritative policy-based selection
        self.scorer = AdaptiveScorer()

        # Cryptographic execution layer
        self.crypto_manager = CryptoManager()

    # ========================================================
    # Select algorithm using policy and retain ML prediction
    # ========================================================

    def select_algorithm(self, context):
        ml_decision = self.ml_engine.predict(context)
        policy_decision = self.scorer.select_algorithm(context)

        selected_algorithm = policy_decision["selected_algorithm"]
        available = self.crypto_manager.available_algorithms()

        if selected_algorithm not in available:
            raise ValueError(
                f"Policy-selected algorithm '{selected_algorithm}' "
                "is unavailable. Refusing silent fallback."
            )

        return {
            "algorithm": selected_algorithm,
            "policy_algorithm": selected_algorithm,
            "ml_algorithm": ml_decision["algorithm"],
            "confidence": float(ml_decision["confidence"]),
            "probabilities": {
                name: float(probability)
                for name, probability
                in ml_decision["probabilities"].items()
            },
            "security_requirement": policy_decision[
                "security_requirement"
            ],
            "resource_pressure": policy_decision["resource_pressure"],
        }

    # ========================================================
    # Encrypt using policy-selected algorithm
    # ========================================================

    def encrypt(self, context, plaintext):
        decision = self.select_algorithm(context)
        algorithm = decision["algorithm"]

        ciphertext = self.crypto_manager.encrypt(
            algorithm,
            plaintext
        )

        return {
            **decision,
            "ciphertext": ciphertext
        }

    # ========================================================
    # Decrypt using the algorithm used for encryption
    # ========================================================

    def decrypt(self, algorithm, ciphertext):
        return self.crypto_manager.decrypt(
            algorithm,
            ciphertext
        )

    # ========================================================
    # Available algorithms
    # ========================================================

    def available_algorithms(self):
        return self.crypto_manager.available_algorithms()
