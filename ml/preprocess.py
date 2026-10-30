# ============================================================
# Adaptive IoT Security Framework
# Stage 4 - ML Preprocessing
# ============================================================

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder


FEATURE_COLUMNS = [
    "battery",
    "cpu_usage",
    "memory_usage",
    "latency",
    "packet_loss",
    "network_status",
    "data_sensitivity",
    "threat_level"
]

TARGET_COLUMN = "best_algorithm"


NUMERIC_FEATURES = [
    "battery",
    "cpu_usage",
    "memory_usage",
    "latency",
    "packet_loss"
]

CATEGORICAL_FEATURES = [
    "network_status",
    "data_sensitivity",
    "threat_level"
]

def load_dataset(path):

    df = pd.read_csv(path)

    return df


def create_preprocessor():

    preprocessor = ColumnTransformer(
        transformers=[

            (
                "numeric",
                "passthrough",
                NUMERIC_FEATURES
            ),

            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                CATEGORICAL_FEATURES
            )
        ]
    )

    return preprocessor


def prepare_data(df):

    X = df[FEATURE_COLUMNS]

    y = df[TARGET_COLUMN]

    return X, y