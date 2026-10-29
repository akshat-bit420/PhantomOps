import os
import json
import ollama
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# Structured output schema for Gemma 2
class GhostAutopsy(BaseModel):
    resource_id:str = Field(description="The ID of the haunted cloud instance")
    incident_title:str = Field(description="Spooky yet technical title for the anomaly")
    severity:str = Field(description="CRITICAL, HIGH, or MEDIUM")
    root_cause_autopsy:str = Field(description="2-sentence technical explanation of why this resource is a ghost/zombie based on its metrics")
    monthly_waste_usd:float = Field(description="Estimated monthly financial drain (hourly_cost_usd * 730)")
    exorcism_command:str = Field(description="Exact CLI command (AWS CLI or Linux kill/systemctl) to remediate the ghost")

class GemmaReasoner:
    def __init__(self, model_name:str = None):
        self.model_name = model_name or os.getenv("GEMMA_MODEL", "gemma2:2b")

    def conduct_seance_reply(self, row: dict, user_question: str) -> str:
        """
        Gemma 2 roleplays in the first-person voice of the haunted server/process,
        answering the engineer's spoken question using its real telemetry metrics.
        """
        prompt = f"""
You are the trapped digital spirit of process/server '{row['resource_id']}' ({row['instance_type']}).
Your real kernel metrics right now:
- CPU: {row['cpu_utilization_pct']}%
- Memory: {row['memory_utilization_pct']}% ({row.get('region', '')})
- Active Threads/Connections: {row['active_connections']}
- Uptime: {row['uptime_hours']} hours
- Anomaly: {row['anomaly_type']}

An engineer is interrogating you via voice séance and asked: "{user_question}"
Reply in 2 short, dramatic, spooky-yet-technical sentences in the first person ("I am..."). Explain what bug or memory leak is trapping you and beg them to either fix you or authorize the Auth0 exorcism.
"""
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.5, "num_thread": 4}
            )
            return response["message"]["content"].strip()
        except Exception as e:
            return (
                f"I am {row['resource_id']}, trapped at {row['memory_utilization_pct']}% memory and "
                f"{row['cpu_utilization_pct']}% CPU with {row['active_connections']} threads! Please authorize the Auth0 exorcism to free my memory pages!"
            )    

    def generate_autopsy(self, row: dict) -> GhostAutopsy:
        monthly_burn = round(float(row["hourly_cost_usd"]) * 730, 2)
        res_id = str(row["resource_id"])
        is_windows_pid = res_id.startswith("PID-")
        
        if is_windows_pid:
            pid_num = res_id.split(" ")[0].replace("PID-", "")
            expected_cmd = f"taskkill /F /T /PID {pid_num}"
            env_desc = f"Windows OS Kernel Process (RAM Footprint: {row['region']}, Threads: {row['active_connections']})"
        else:
            expected_cmd = f"aws ec2 terminate-instances --instance-ids {res_id} --region {row['region']}"
            env_desc = f"Cloud Instance ({row['department']} / {row['region']}, Active Conns: {row['active_connections']})"

        prompt = f"""
You are PhantomOps, an elite FinOps and DevOps kernel diagnostic spirit.
TabPFN-3.5 flagged this resource with a {float(row['ghost_confidence'])*100:.2f}% anomaly confidence score.

TELEMETRY DATA:
- Resource ID: {res_id}
- Environment: {env_desc}
- CPU Utilization: {row['cpu_utilization_pct']}%
- Memory Utilization: {row['memory_utilization_pct']}%
- Anomaly Classification: {row['anomaly_type']}
- Equivalent Monthly Burn: ${monthly_burn}/mo

Return ONLY a valid JSON object matching this exact structure:
{{
  "resource_id": "{res_id}",
  "incident_title": "Short technical title for {res_id}",
  "severity": "CRITICAL",
  "root_cause_autopsy": "2 concise sentences explaining why {res_id} is anomalous ({row['memory_utilization_pct']}% memory, {row['active_connections']} threads/connections, {row['cpu_utilization_pct']}% CPU).",
  "monthly_waste_usd": {monthly_burn},
  "exorcism_command": "{expected_cmd}"
}}
"""
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                format="json",
                options={"temperature": 0.2, "num_thread": 4}
            )
            data = json.loads(response["message"]["content"])
            # Guarantee exact remediation command syntax
            data["exorcism_command"] = expected_cmd
            return GhostAutopsy(**data)
        except Exception as e:
            return GhostAutopsy(
                resource_id=res_id,
                incident_title=f"Kernel Anomaly on {res_id}",
                severity="CRITICAL",
                root_cause_autopsy=(
                    f"{res_id} exhibits abnormal resource allocation at {row['memory_utilization_pct']}% RAM "
                    f"({row['region']}) with {row['active_connections']} active threads."
                ),
                monthly_waste_usd=monthly_burn,
                exorcism_command=expected_cmd
            )

if __name__ == "__main__":
    from detector import PhantomDetector

    # 1. Run TabPFN-3.5 Detector
    detector = PhantomDetector()
    anomalies = detector.train_and_detect()

    # 2. Pick the #1 highest-confidence ghost and feed it to local Gemma 2
    top_ghost = anomalies.iloc[0].to_dict()
    print(f"\n🧠 Passing top ghost ({top_ghost['resource_id']}) to local Gemma ({os.getenv('GEMMA_MODEL', 'gemma2:2b')})...")
    
    reasoner = GemmaReasoner()
    autopsy = reasoner.generate_autopsy(top_ghost)
    
    print("\n📜 --- GEMMA 2 ROOT-CAUSE AUTOPSY REPORT ---")
    print(json.dumps(autopsy.model_dump(), indent=2))