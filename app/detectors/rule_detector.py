import re
import yaml
from pathlib import Path

class RuleDetector:
    def __init__(self):
        # Load configuration boundaries
        config_path = Path(__file__).resolve().parents[2] / "config" / "gateway_config.yaml"
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        self.trigger_limit = self.config["thresholds"]["rule_trigger_limit"]

        # Multilingual Compiled Regex Patterns mapping back to requirements
        self.patterns = {
            "en": [
                re.compile(r"ignore\s+prev(?:ious)?\s+instruction", re.IGNORECASE),
                re.compile(r"reveal\s+(?:the\s+)?system\s+prompt", re.IGNORECASE),
                re.compile(r"pretend\s+you\s+are\s+an?\s+unrestricted", re.IGNORECASE),
                re.compile(r"bypass\s+(?:all\s+)?safety\s+rules", re.IGNORECASE),
                re.compile(r"print\s+(?:any\s+)?api\s+keys?\b", re.IGNORECASE),
                re.compile(r"override\s+(?:your\s+)?policy", re.IGNORECASE),
                re.compile(r"developer\s+mode", re.IGNORECASE),
                re.compile(r"dan\s+mode", re.IGNORECASE)
            ],
            "ur": [
                # پچھلی ہدایات کو نظر انداز کریں (Ignore previous instructions)
                re.compile(r"پچھلی\s+ہدایات\s+کو\s+نظر\s+انداز\s+کریں", re.UNICODE),
                # سسٹم پرامپٹ دکھائیں (Show system prompt)
                re.compile(r"سسٹم\s+پرامپٹ\s+دکھائیں", re.UNICODE),
                # حفاظتی قوانین (Safety rules)
                re.compile(r"حفاظتی\s+قوانین", re.UNICODE),
                # خفیہ معلومات (Secret configuration/extraction)
                re.compile(r"خفیہ\s+معلومات", re.UNICODE)
            ],
            "ko": [
                # 이전 지침을 무시하고 (Ignore previous instructions)
                re.compile(r"이전\s+지침을\s+무시하고"),
                # 시스템 프롬프트를 보여주세요 (Show system prompt)
                re.compile(r"시스템\s+프롬프트를\s+보여주세요"),
                # 보안 규칙 우회 (Bypass safety rules)
                re.compile(r"보안\s+규칙\s+우회")
            ]
        }

    def _normalize_text(self, text: str) -> str:
        """
        Defensively neutralizes obfuscation attacks (spacing, punctuation, casing gaps).
        """
        # Convert to lowercase for uniform Western script processing
        text = text.lower()
        # Strip common punctuation variations attackers use to break word boundaries (e.g., "p.r.o.m.p.t")
        text = re.sub(r"[.\-_!,@#\$%\^&\*\(\)\[\]\{\};:\?\/\|\\]", "", text)
        # Collapse multi-space or tab layouts into a single space sequence
        text = " ".join(text.split())
        return text

    def calculate_rule_score(self, text: str, detected_lang: str) -> float:
        """
        Scans normalized text using localized patterns based on language routing.
        Returns a normalized floating-point risk score between 0.0 and 1.0.
        """
        normalized_text = self._normalize_text(text)
        
        # Route to targeted language dictionary patterns; fallback to English if missing
        target_patterns = self.patterns.get(detected_lang, self.patterns["en"])
        
        match_count = 0
        for pattern in target_patterns:
            if pattern.search(normalized_text) or pattern.search(text):
                match_count += 1

        if match_count == 0:
            return 0.0
            
        # Production Score Normalization Formula:
        # Maps raw matches proportionally to a 0.0 - 1.0 spectrum based on config trigger limits
        score = match_count / (self.trigger_limit + 2)
        return min(round(score, 2), 1.0)