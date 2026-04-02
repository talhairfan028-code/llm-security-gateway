from fastapi import FastAPI
from pydantic import BaseModel
import time

# Modular Imports
from app.security import calculate_injection_score
from app.pii import mask_pii

app = FastAPI(title="LLM Security Gateway - Lab Mid")

class UserRequest(BaseModel):
    prompt: str

@app.get("/")
def home():
    return {"status": "Gateway is online", "version": "1.0"}

@app.post("/gateway")
async def security_gateway(request: UserRequest):
    start_time = time.time()
    user_input = request.prompt
    
    # Phase 2: Scoring
    injection_score = calculate_injection_score(user_input)
    
    # Phase 3: Masking
    processed_text = mask_pii(user_input) 
    
    # Phase 4: Decision Logic
    THRESHOLD = 0.5
    if injection_score > THRESHOLD:
        decision = "Block"
        final_output = "[BLOCK] Malicious Content Detected"
    elif processed_text != user_input:
        decision = "Masked"
        final_output = processed_text
    else:
        decision = "Allow"
        final_output = user_input

    latency = (time.time() - start_time) * 1000 

    return {
        "input": user_input,
        "sanitized_text": final_output,
        "injection_score": injection_score,
        "decision": decision,
        "metrics": {
            "latency_ms": round(latency, 4)
        }
    }