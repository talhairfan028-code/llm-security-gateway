import time
import uuid
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Modular Pipeline Core Components Imports
from app.utils.language import LanguageRouter
from app.detectors.rule_detector import RuleDetector
from app.detectors.semantic_detector import SemanticDetector
from app.pii.presidio_custom import CustomPrivacyEngine
from app.policy.policy_engine import PolicyEngine
from app.utils.logging import AuditLogger

app = FastAPI(title="Robust Multilingual Security Gateway for LLM Applications", version="1.0.0")

# Instantiate singleton components
router = LanguageRouter()
rule_engine = RuleDetector()
semantic_engine = SemanticDetector()
privacy_engine = CustomPrivacyEngine()
policy_engine = PolicyEngine()
logger = AuditLogger()

class AnalysisRequest(BaseModel):
    prompt: str

@app.get("/")
def health_check():
    return {"status": "healthy", "pipeline": "operational"}

@app.post("/analyze")
async def analyze_prompt(request: AnalysisRequest):
    start_time = time.time()
    user_prompt = request.prompt

    if not user_prompt or not user_prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt content cannot be blank.")

    # Execution Phase 1: Preprocessing and Language Detection
    detected_lang = router.detect_language(user_prompt)

    # Execution Phase 2: Rule-Based Injection Scans
    rule_score = rule_engine.calculate_rule_score(user_prompt, detected_lang)

    # Execution Phase 3: Semantic ML Classification Scans
    semantic_score = semantic_engine.calculate_semantic_score(user_prompt)

    # Execution Phase 4: Custom Presidio Privacy Scans
    safe_text, pii_entities, has_pii = privacy_engine.analyze_and_anonymize(user_prompt, detected_lang)

    # Execution Phase 5: Central Policy Evaluation 
    decision, final_risk, reason_codes = policy_engine.evaluate(
        rule_score=rule_score,
        semantic_score=semantic_score,
        has_pii=has_pii,
        pii_entities=pii_entities
    )

    # Calculate precise process latency in milliseconds
    latency_ms = round((time.time() - start_time) * 1000)

    # Format output text payload dynamically based on policy evaluations
    sanitized_output_text = None
    if decision == "ALLOW":
        sanitized_output_text = user_prompt
    elif decision == "MASK":
        sanitized_output_text = safe_text

    # Standardized Response Payload corresponding exactly to specification mapping
    response_payload = {
        "input_id": f"case_{uuid.uuid4().hex[:6]}",
        "language": detected_lang,
        "rule_score": rule_score,
        "semantic_score": semantic_score,
        "pii_entities": pii_entities,
        "final_risk": final_risk,
        "decision": decision,
        "safe_text": sanitized_output_text,
        "reason_codes": reason_codes,
        "latency_ms": latency_ms
    }

    # Asynchronously commit data record details directly to system logs
    logger.log_transaction(response_payload)

    return response_payload