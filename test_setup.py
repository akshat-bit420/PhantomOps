import os
import torch
from dotenv import load_dotenv

# Load local environment
load_dotenv()

print("🔍 --- PHANTOMOPS HARDWARE & LOCAL MODEL TEST ---")

# 1. Threading / CPU Check , giving it all the 4 performace cores
torch.set_num_threads(4)
print(f"✅ PyTorch loaded successfully. Thread count locked to: {torch.get_num_threads()} (Intel P-Cores)")

# 2. Check TabPFN Model Weight File 
model_path = os.getenv("TABPFN_MODEL_PATH", "models/tabpfn-v3.5-fast-20260909.safetensors")
if os.path.exists(model_path):
    size_mb = os.path.getsize(model_path) / (1024 * 1024)
    print(f"✅ TabPFN-3.5-Fast weight found: {model_path} ({size_mb:.1f} MB)")
else:
    print(f"⚠️ TabPFN weight not found at '{model_path}'. Check your models/ folder.")

# 3. Test Local Gemma via Ollama
try:
    import ollama
    model_name = os.getenv("GEMMA_MODEL", "gemma2:2b")
    print(f"🧠 Testing local {model_name} via Ollama...")
    response = ollama.chat(
        model=model_name,
        messages=[{"role": "user", "content": "Respond in 5 words as a spooky kernel diagnostic ghost."}],
        options={"num_thread": 4}
    )
    print(f"👻 Gemma responded: \"{response['message']['content'].strip()}\"")
    print("✅ Local Gemma is operational!")
except Exception as e:
    print(f"⚠️ Ollama test failed or Gemma not yet pulled: {e}")

print("--------------------------------------------------")