import os
import random
import numpy as np
import pandas as pd

def generate_telemetry_dataset(num_records: int = 600, output_path: str = "data/telemetry_billing.csv") -> pd.DataFrame:
    """
    Generates realistic cloud infrastructure telemetry logs with injected
    'Ghost in the Machine' anomalies (zombie workloads, memory leakers, rogue cost spikes).
    """
    np.random.seed(42)
    random.seed(42)
    
    records = []
    instance_types = ["c6i.xlarge", "m6i.2xlarge", "g5.2xlarge", "t3.medium", "r6i.xlarge"]
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]
    departments = ["production-api", "ml-training", "analytics-pipeline", "staging-dev"]

    for i in range(num_records):
        inst_type = random.choice(instance_types)
        
        # Base pricing per hour
        base_cost = {
            "t3.medium": 0.0416,
            "c6i.xlarge": 0.17,
            "m6i.2xlarge": 0.384,
            "r6i.xlarge": 0.504,
            "g5.2xlarge": 1.212
        }[inst_type]

        # Normal operational distribution
        cpu_pct = float(np.clip(np.random.normal(48, 15), 5.0, 95.0))
        memory_pct = float(np.clip(np.random.normal(55, 12), 10.0, 90.0))
        network_out_gb = float(np.clip(np.random.exponential(8.5), 0.1, 45.0))
        active_connections = int(np.clip(np.random.poisson(120), 5, 450))
        hourly_cost_usd = float(base_cost * np.random.uniform(0.98, 1.05))
        uptime_hours = int(np.random.uniform(12, 720))
        is_ghost = 0  # 0: Healthy, 1: Ghost/Zombie anomaly
        anomaly_type = "healthy"

        # --- Injecting Spooky Ghost In The Machine Anomalies (~5% of data) ---
        if i % 35 == 0:
            is_ghost = 1
            anomaly_flavor = random.choice(["zombie_gpu", "phantom_leaker", "cryptojack_spike", "defunct_daemon"])
            
            if anomaly_flavor == "zombie_gpu":
                # High cost GPU instance abandoned with 0 traffic and 0 CPU for hundreds of hours
                inst_type = "g5.2xlarge"
                cpu_pct = float(np.random.uniform(0.1, 1.2))
                active_connections = 0
                network_out_gb = 0.01
                uptime_hours = int(np.random.uniform(300, 1200))
                hourly_cost_usd = 2.45  # Overprovisioned attached storage
                anomaly_type = "zombie_abandoned_gpu"

            elif anomaly_flavor == "phantom_leaker":
                # Zombie process holding locked memory at 99.8% with zero connection work
                cpu_pct = float(np.random.uniform(2.0, 5.0))
                memory_pct = float(np.random.uniform(98.5, 99.9))
                active_connections = int(np.random.uniform(0, 2))
                network_out_gb = 0.05
                anomaly_type = "phantom_memory_leak"

            elif anomaly_flavor == "cryptojack_spike":
                # Sudden 100% CPU lock with zero external connections on cheap node
                inst_type = "t3.medium"
                cpu_pct = 99.9
                active_connections = 1
                network_out_gb = 0.02
                hourly_cost_usd = 0.85  # CPU credit burst exhaustion penalty
                anomaly_type = "rogue_process_spike"

            elif anomaly_flavor == "defunct_daemon":
                # Defunct parentless process holding thread descriptors
                cpu_pct = 0.0
                memory_pct = float(np.random.uniform(40.0, 65.0))
                active_connections = 0
                uptime_hours = int(np.random.uniform(500, 2000))
                anomaly_type = "defunct_orphan_process"

        records.append({
            "resource_id": f"inst-{10000 + i}",
            "instance_type": inst_type,
            "department": random.choice(departments),
            "region": random.choice(regions),
            "cpu_utilization_pct": round(cpu_pct, 2),
            "memory_utilization_pct": round(memory_pct, 2),
            "network_out_gb": round(network_out_gb, 2),
            "active_connections": active_connections,
            "uptime_hours": uptime_hours,
            "hourly_cost_usd": round(hourly_cost_usd, 4),
            "is_ghost": is_ghost,
            "anomaly_type": anomaly_type
        })

    df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} cloud infrastructure records -> {output_path}")
    print(f"Injected Ghost Anomalies: {df['is_ghost'].sum()} instances.")
    return df

if __name__ == "__main__":
    generate_telemetry_dataset()