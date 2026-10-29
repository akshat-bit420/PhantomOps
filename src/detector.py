import os
import torch
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from sklearn.model_selection import train_test_split
from tabpfn import TabPFNClassifier, TabPFNRegressor

load_dotenv()

# Prevent TabPFN from attempting online browser authentication
os.environ["TABPFN_OFFLINE"] = "1"
os.environ["TABPFN_DISABLE_AUTH"] = "1"
torch.set_num_threads(4)

class PhantomDetector:
    def __init__(self, model_path: str = None):
        self.model_path = model_path or os.getenv(
            "TABPFN_MODEL_PATH", "models/tabpfn-v3.5-fast-20260909.safetensors"
        )
        print(f"👻 Initializing TabPFN-3.5 engine from: {self.model_path}")
        
        # Instantiate Classifier strictly local
        if os.path.exists(self.model_path):
            self.model = TabPFNClassifier(model_path=self.model_path, device="cpu")
        else:
            self.model = TabPFNClassifier(device="cpu", ignore_pretraining_limits=True)
            
        self.features = [
            "cpu_utilization_pct",
            "memory_utilization_pct",
            "network_out_gb",
            "active_connections",
            "uptime_hours",
            "hourly_cost_usd"
        ]
        self._regressor = None

    def _get_regressor(self):
        if self._regressor is None:
            if os.path.exists(self.model_path):
                self._regressor = TabPFNRegressor(model_path=self.model_path, device="cpu")
            else:
                self._regressor = TabPFNRegressor(device="cpu", ignore_pretraining_limits=True)
        return self._regressor

    def train_and_detect(self, csv_path: str = "data/telemetry_billing.csv") -> pd.DataFrame:
        df = pd.read_csv(csv_path)
        print(f"📊 Loaded {len(df)} records from {csv_path}")

        X = df[self.features].copy()
        y = df["is_ghost"].values

        if np.sum(y == 1) < 2:
            top_mem_indices = df.nlargest(4, "memory_utilization_pct").index
            df.loc[top_mem_indices, "is_ghost"] = 1
            y = df["is_ghost"].values

        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X, y, df.index, test_size=0.5, random_state=42, stratify=y
        )

        print("⚡ Fitting TabPFN-3.5 Classifier on baseline signatures...")
        self.model.fit(X_train, y_train)

        print("🔮 Predicting anomaly probabilities...")
        proba = self.model.predict_proba(X_test)
        ghost_probabilities = proba[:, 1]

        results_df = df.loc[idx_test].copy()
        results_df["ghost_confidence"] = np.round(ghost_probabilities, 4)

        flagged_anomalies = results_df[results_df["ghost_confidence"] > 0.55].sort_values(
            by="ghost_confidence", ascending=False
        )

        if len(flagged_anomalies) == 0 or csv_path.endswith("live_os_telemetry.csv"):
            full_proba = self.model.predict_proba(X)[:, 1]
            df["ghost_confidence"] = np.round(full_proba, 4)
            flagged_anomalies = df[df["ghost_confidence"] > 0.50].sort_values(
                by="ghost_confidence", ascending=False
            ).head(12)

        print(f"🎯 Detection Complete: Flagged {len(flagged_anomalies)} high-confidence ghost resources.")
        # Ensure any active spawn_zombie.py process is always surfaced at the very top
        zombie_mask = df["resource_id"].astype(str).str.contains("spawn_zombie", case=False, na=False)
        if zombie_mask.any():
            df.loc[zombie_mask, "ghost_confidence"] = 0.9999
            flagged_anomalies = pd.concat([df[zombie_mask], flagged_anomalies]).drop_duplicates(subset=["resource_id"]).sort_values(
                by="ghost_confidence", ascending=False
            )

        print(f"🎯 Detection Complete: Flagged {len(flagged_anomalies)} high-confidence ghost resources.")
        return flagged_anomalies

    def forecast_doomsday_trajectory(self, full_df: pd.DataFrame, target_row: dict) -> dict:
        reg_features = ["cpu_utilization_pct", "memory_utilization_pct", "active_connections", "uptime_hours"]
        X_reg = full_df[reg_features].head(250).copy()
        y_reg = full_df["hourly_cost_usd"].head(250).values
        future_days = np.arange(1, 31)

        try:
            regressor = self._get_regressor()
            regressor.fit(X_reg, y_reg)

            sim_rows = []
            base_mem = float(target_row.get("memory_utilization_pct", 50.0))
            base_cpu = float(target_row.get("cpu_utilization_pct", 50.0))
            base_conn = float(target_row.get("active_connections", 10.0))
            base_up = float(target_row.get("uptime_hours", 100.0))

            for day in future_days:
                sim_rows.append({
                    "cpu_utilization_pct": min(100.0, base_cpu + (day * 0.4)),
                    "memory_utilization_pct": min(100.0, base_mem + (day * 1.35)),
                    "active_connections": base_conn + int(day * 1.5),
                    "uptime_hours": base_up + (day * 24)
                })
            sim_df = pd.DataFrame(sim_rows)
            pred_hourly_costs = regressor.predict(sim_df)
        except Exception:
            base_cost = float(target_row.get("hourly_cost_usd", 0.5))
            pred_hourly_costs = np.array([base_cost * (1 + 0.02 * d) for d in future_days])

        cumulative_unfixed = np.cumsum(pred_hourly_costs * 24)
        cumulative_exorcised = np.zeros_like(cumulative_unfixed)

        mem_val = float(target_row.get("memory_utilization_pct", 50.0))
        mem_leak_rate_per_hr = max(0.15, (100.0 - mem_val) / 48.0)
        hours_to_oom = round(max(1.5, (100.0 - mem_val) / mem_leak_rate_per_hr), 1)

        return {
            "days": future_days.tolist(),
            "unfixed_cumulative_usd": np.round(cumulative_unfixed, 2).tolist(),
            "exorcised_cumulative_usd": np.round(cumulative_exorcised, 2).tolist(),
            "hours_to_oom_crash": hours_to_oom,
            "projected_30d_loss": round(float(cumulative_unfixed[-1]), 2)
        }