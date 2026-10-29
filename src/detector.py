import os
import torch
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from sklearn.model_selection import train_test_split
from tabpfn import TabPFNClassifier

load_dotenv()

# Lock PyTorch CPU threads to the 4 physical P-cores on your i5-12450H
torch.set_num_threads(4)

class PhantomDetector:
    def __init__(self, model_path: str = None):
        """
        Initializes TabPFN-3.5 locally using the downloaded .safetensors weights.
        """
        self.model_path = model_path or os.getenv(
            "TABPFN_MODEL_PATH", "models/tabpfn-v3.5-fast-20260909.safetensors"
        )
        print(f"👻 Initializing TabPFN-3.5 engine from: {self.model_path}")
        
        # Instantiate TabPFN Classifier
        # If local weights exist, it uses them; otherwise uses default local weights
        if os.path.exists(self.model_path):
            self.model = TabPFNClassifier(model_path=self.model_path, device="cpu")
        else:
            print("⚠️ Local weight path not detected, loading default local TabPFN configuration...")
            self.model = TabPFNClassifier(device="cpu")
            
        self.features = [
            "cpu_utilization_pct",
            "memory_utilization_pct",
            "network_out_gb",
            "active_connections",
            "uptime_hours",
            "hourly_cost_usd"
        ]

    def train_and_detect(self, csv_path: str = "data/telemetry_billing.csv") -> pd.DataFrame:
        """
        Runs TabPFN inference over the tabular telemetry data to spot zombie instances
        and resource leaks.
        """
        df = pd.read_csv(csv_path)
        print(f"📊 Loaded {len(df)} records from {csv_path}")

        X = df[self.features].copy()
        y = df["is_ghost"].values

        # Split into training baseline and evaluation set
        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X, y, df.index, test_size=0.5, random_state=42, stratify=y
        )

        print("⚡ Fitting TabPFN-3.5 on baseline server signatures...")
        self.model.fit(X_train, y_train)

        print("🔮 Predicting anomaly probabilities on active infrastructure...")
        # Get class probabilities: [P(healthy), P(ghost)]
        proba = self.model.predict_proba(X_test)
        ghost_probabilities = proba[:, 1]

        # Attach TabPFN confidence scores back to test rows
        results_df = df.loc[idx_test].copy()
        results_df["ghost_confidence"] = np.round(ghost_probabilities, 4)
        
        # Rank by highest probability of being a ghost/zombie
        flagged_anomalies = results_df[results_df["ghost_confidence"] > 0.65].sort_values(
            by="ghost_confidence", ascending=False
        )

        print(f"🎯 Detection Complete: Flagged {len(flagged_anomalies)} high-confidence ghost resources.")
        return flagged_anomalies

if __name__ == "__main__":
    detector = PhantomDetector()
    anomalies = detector.train_and_detect()
    print("\n--- TOP DETECTED PHANTOMS (Sample Preview) ---")
    cols_to_show = ["resource_id", "instance_type", "ghost_confidence", "hourly_cost_usd", "cpu_utilization_pct", "anomaly_type"]
    print(anomalies[cols_to_show].head(5).to_string(index=False))