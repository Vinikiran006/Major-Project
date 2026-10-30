# ============================================================
# Adaptive IoT Security Framework
# Stage 4 - Random Forest Training
# ============================================================

import os

import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

from ml.preprocess import (
    load_dataset,
    create_preprocessor,
    prepare_data
)


DATASET_PATH = (
    "data/adaptive_crypto_dataset_giftcofb.csv"
)

MODEL_PATH = "models/adaptive_crypto_model_giftcofb_v2.pkl"

def main():

    print("=" * 60)
    print("     ADAPTIVE IoT CRYPTOGRAPHY - ML TRAINING")
    print("=" * 60)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    df = load_dataset(
        DATASET_PATH
    )

    print(
        f"\nDataset shape: {df.shape}"
    )

    print("\nClass distribution:")

    print(
        df["best_algorithm"].value_counts()
    )

    # --------------------------------------------------------
    # Prepare features
    # --------------------------------------------------------

    X, y = prepare_data(df)

    # --------------------------------------------------------
    # Train / test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y
        )
    )

    print(
        f"\nTraining samples: {len(X_train)}"
    )

    print(
        f"Testing samples : {len(X_test)}"
    )

    # --------------------------------------------------------
    # Preprocessor
    # --------------------------------------------------------

    preprocessor = create_preprocessor()

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    classifier = RandomForestClassifier(

        n_estimators=200,

        max_depth=12,

        min_samples_split=5,

        min_samples_leaf=2,

        class_weight="balanced",

        random_state=42,

        n_jobs=-1
    )

    # --------------------------------------------------------
    # Complete pipeline
    # --------------------------------------------------------

    model = Pipeline(
        steps=[

            (
                "preprocessor",
                preprocessor
            ),

            (
                "classifier",
                classifier
            )
        ]
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    print("\nTraining Random Forest...")

    model.fit(
        X_train,
        y_train
    )

    print("Training completed.")

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    print("\nClassification Report:")
    print()

    print(
        classification_report(
            y_test,
            predictions
        )
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    os.makedirs(
        "models",
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        f"\nModel saved to: {MODEL_PATH}"
    )


if __name__ == "__main__":

    main()