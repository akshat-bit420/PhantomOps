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

    def generate_autopsy(self, row: dict) -> GhostAutopsy:
        """
        Passes a single anomalous row detected by TabPFN-3.5 into local Gemma 2
        to synthesize a structured technical autopsy and remediation command.
        """
        monthly_burn = round(float(row["hourly_cost_usd"]) * 730, 2)
        
        prompt = f"""
You are PhantomOps, an elite FinOps and DevOps kernel diagnostic spirit.
TabPFN-3.5 flagged this cloud infrastructure resource with a {float(row['ghost_confidence'])*100:.2f}% anomaly confidence score.

TELEMETRY DATA:
- Resource ID: {row['resource_id']}
- Instance Type: {row['instance_type']}
- Department: {row['department']} ({row['region']})
- CPU Utilization: {row['cpu_utilization_pct']}%
- Memory Utilization: {row['memory_utilization_pct']}%
- Network Out: {row['network_out_gb']} GB
- Active Connections: {row['active_connections']}
- Uptime: {row['uptime_hours']} hours
- Hourly Cost: ${row['hourly_cost_usd']}/hr (Est. Monthly Burn: ${monthly_burn}/mo)

Return ONLY a valid JSON object matching this exact structure:
{{
  "resource_id": "{row['resource_id']}",
  "incident_title": "Short spooky technical title",
  "severity": "CRITICAL",
  "root_cause_autopsy": "2 concise sentences explaining the exact metric mismatch (e.g. high cost/memory with zero connections or 99% CPU spike).",
  "monthly_waste_usd": {monthly_burn},
  "exorcism_command": "Exact AWS CLI or bash command to terminate or fix {row['resource_id']}"
}}
"""
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                format="json",
                options={
                    "temperature": 0.2,
                    "num_thread": 4  # Locked to your 4 P-cores
                }
            )
            raw_json = response["message"]["content"]
            data = json.loads(raw_json)
            return GhostAutopsy(**data)
            
        except Exception as e:
            # Fallback if Ollama isn't running or JSON slightly drifts
            print(f"⚠️ Gemma inference fallback triggered: {e}")
            return GhostAutopsy(
                resource_id=str(row["resource_id"]),
                incident_title=f"Haunted {row['instance_type']} Anomaly",
                severity="CRITICAL",
                root_cause_autopsy=(
                    f"Resource {row['resource_id']} exhibits severe metric divergence with "
                    f"{row['cpu_utilization_pct']}% CPU, {row['memory_utilization_pct']}% RAM, and {row['active_connections']} active connections."
                ),
                monthly_waste_usd=monthly_burn,
                exorcism_command=f"aws ec2 terminate-instances --instance-ids {row['resource_id']} --region {row['region']}"
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