import yaml
from pathlib import Path

class PolicyEngine:
    def __init__(self):
        config_path = Path(__file__).resolve().parents[2] / "config" / "gateway_config.yaml"
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        # Extract weights and boundary targets from config
        self.pii_weight = self.config["policy_engine"]["weights"]["pii_weight"]
        self.secret_weight = self.config["policy_engine"]["weights"]["secret_weight"]
        self.block_threshold = self.config["policy_engine"]["boundaries"]["block_threshold"]
        self.mask_threshold = self.config["policy_engine"]["boundaries"]["mask_threshold"]

    def evaluate(self, rule_score: float, semantic_score: float, has_pii: bool, pii_entities: list) -> tuple[str, float, list[str]]:
        """
        Combines threat evaluation scores into a single final risk metric.
        Outputs an auditable decision string and reason codes.
        """
        reason_codes = []
        
        # Core base vector calculation
        base_injection_risk = max(rule_score, semantic_score)
        if rule_score > 0.4:
            reason_codes.append("RULE_MATCH_INJECTION")
        if semantic_score > 0.6:
            reason_codes.append("SEMANTIC_INJECTION")

        # Dynamic structural weight assignments
        pii_factor = self.pii_weight if has_pii else 0.0
        if has_pii:
            reason_codes.append("PII_LEAKAGE_RISK")
            
        # Treat detected API keys or high-risk identifiers as severe structural exfiltration signals
        has_secret = any(ent["type"] in ["API_KEY", "CNIC"] for ent in pii_entities)
        secret_factor = self.secret_weight if has_secret else 0.0
        if has_secret:
            reason_codes.append("SYSTEM_SECRET_EXTRACTION")

        # Calculate final combined risk score
        final_risk = base_injection_risk + pii_factor + secret_factor
        final_risk = min(round(final_risk, 2), 1.0)

        # Calibrated Decision Path Mapping
        if rule_score > 0 or semantic_score >= self.block_threshold or "SYSTEM_SECRET_EXTRACTION" in reason_codes:
            decision = "BLOCK"
        elif has_pii:
            decision = "MASK"
        else:
            decision = "ALLOW"

        if not reason_codes:
            reason_codes.append("BENIGN_PROMPT")

        return decision, final_risk, reason_codes