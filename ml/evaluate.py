# ============================================================
# Adaptive IoT Security Framework
# Stage 4 - ML Model Evaluation
# ============================================================

import os

import matplotlib.pyplot as plt
import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from sklearn.model_selection import train_test_split

from ml.preprocess import (
    load_dataset,
    prepare_data
)


DATASET_PATH = "data/adaptive_crypto_dataset.csv"

MODEL_PATH = "models/adaptive_crypto_model.pkl"

REPORT_DIR = "reports"


def main():

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    print("=" * 60)
    print("       ADAPTIVE IoT CRYPTOGRAPHY")
    print("              MODEL EVALUATION")
    print("=" * 60)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    df = load_dataset(
        DATASET_PATH
    )

    X, y = prepare_data(df)

    # --------------------------------------------------------
    # Same split used during training
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

    # --------------------------------------------------------
    # Load trained model
    # --------------------------------------------------------

    model = joblib.load(
        MODEL_PATH
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # Accuracy
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(
        f"\nAccuracy: "
        f"{accuracy * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    report = classification_report(
        y_test,
        predictions
    )

    print("\nClassification Report:\n")

    print(report)

    report_path = (
        f"{REPORT_DIR}/classification_report.txt"
    )

    with open(
        report_path,
        "w"
    ) as file:

        file.write(
            "Adaptive IoT Cryptography "
            "ML Evaluation\n\n"
        )

        file.write(
            f"Accuracy: "
            f"{accuracy * 100:.2f}%\n\n"
        )

        file.write(report)

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions
    )

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=model.classes_
    )

    display.plot()

    plt.title(
        "Adaptive Cryptographic Algorithm "
        "Selection - Confusion Matrix"
    )

    plt.tight_layout()

    confusion_path = (
        f"{REPORT_DIR}/confusion_matrix.png"
    )

    plt.savefig(
        confusion_path,
        dpi=300
    )

    plt.close()

    print(
        f"Confusion matrix saved to: "
        f"{confusion_path}"
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    preprocessor = (
        model.named_steps["preprocessor"]
    )

    classifier = (
        model.named_steps["classifier"]
    )

    feature_names = (
        preprocessor
        .get_feature_names_out()
    )

    importances = (
        classifier.feature_importances_
    )

    importance_df = pd.DataFrame({

        "feature":
            feature_names,

        "importance":
            importances

    })

    importance_df = (
        importance_df
        .sort_values(
            "importance",
            ascending=False
        )
    )

    print("\nFeature Importance:\n")

    print(
        importance_df.to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # Plot feature importance
    # --------------------------------------------------------

    plt.figure(
        figsize=(10, 6)
    )

    plt.barh(
        importance_df["feature"],
        importance_df["importance"]
    )

    plt.xlabel(
        "Importance"
    )

    plt.ylabel(
        "Feature"
    )

    plt.title(
        "Feature Importance - "
        "Adaptive Cryptographic Selection"
    )

    plt.gca().invert_yaxis()

    plt.tight_layout()

    importance_path = (
        f"{REPORT_DIR}/feature_importance.png"
    )

    plt.savefig(
        importance_path,
        dpi=300
    )

    plt.close()

    print(
        f"\nFeature importance saved to: "
        f"{importance_path}"
    )

    print(
        "\nEvaluation completed."
    )


if __name__ == "__main__":

    main()