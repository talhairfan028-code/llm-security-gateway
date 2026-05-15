import yaml
import re
from pathlib import Path
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

class CustomPrivacyEngine:
    def __init__(self):
        # Load centralized gateway threshold rules
        config_path = Path(__file__).resolve().parents[2] / "config" / "gateway_config.yaml"
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        self.min_threshold = self.config["thresholds"]["pii_confidence_threshold"]
        
        # 1. Initialize Registry and Build Custom Recognizers
        self.registry = RecognizerRegistry()
        self.registry.load_predefined_recognizers()
        self._add_custom_local_recognizers()
        
        # Instantiate Engines
        self.analyzer = AnalyzerEngine(registry=self.registry)
        self.anonymizer = AnonymizerEngine()

    def _add_custom_local_recognizers(self):
        """
        Constructs and registers localized and contextual pattern recognizers.
        Fulfills Custom Recognizer and Context-Aware Scoring requirements.
        """
        # Pakistani CNIC Pattern (e.g., 35202-1234567-1)
        cnic_pattern = Pattern(name="cnic_pattern", regex=r"\b\d{5}-\d{7}-\d{1}\b", score=0.7)
        cnic_recognizer = PatternRecognizer(
            supported_entity="CNIC",
            patterns=[cnic_pattern],
            context=["cnic", "identity", "card", "shanaxti", "number"]
        )
        
        # University Student Registration ID Pattern (e.g., FA21-BCS-123)
        student_pattern = Pattern(name="student_id_pattern", regex=r"\b[a-zA-Z]{2}\d{2}-[a-zA-Z]{3}-\d{3}\b", score=0.75)
        student_recognizer = PatternRecognizer(
            supported_entity="STUDENT_ID",
            patterns=[student_pattern],
            context=["student", "registration", "roll", "comsats", "id"]
        )

        # Generic High-Value Secret API Key Pattern
        api_key_pattern = Pattern(name="api_key_pattern", regex=r"\b(?:sk-[a-zA-Z0-9]{32,48}|api[-_]?[key_.]*[a-zA-Z0-9]{16,40})\b", score=0.8)
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern],
            context=["api", "key", "token", "secret", "password"]
        )

        # Register custom implementations into Presidio ecosystem
        self.registry.add_recognizer(cnic_recognizer)
        self.registry.add_recognizer(student_recognizer)
        self.registry.add_recognizer(api_key_recognizer)

    def analyze_and_anonymize(self, text: str, lang: str = "en") -> tuple[str, list, bool]:
        """
        Executes analysis, performs composite entity verification, calibrates confidence scales, 
        and structuralizes uniform placeholder masking.
        """
        # Define comprehensive active monitoring target list
        target_entities = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CNIC", "STUDENT_ID", "API_KEY"]
        
        # Standard Presidio Language Fallback Protection
        analysis_lang = lang if lang in ["en"] else "en"
        
        # Step A: Perform standard analysis pass
        analysis_results = self.analyzer.analyze(
            text=text,
            entities=target_entities,
            language=analysis_lang,
            score_threshold=self.min_threshold
        )
        
        # Step B: Composite Entity Detection & Confidence Calibration Logic
        detected_types = {res.entity_type for res in analysis_results}
        calibrated_results = []
        has_high_risk_pii = False

        # If a structural combination occurs (e.g., STUDENT_ID + EMAIL_ADDRESS), scale up risk confidence
        is_composite_breach = "STUDENT_ID" in detected_types and "EMAIL_ADDRESS" in detected_types
        
        for res in analysis_results:
            if is_composite_breach:
                res.score = min(res.score + 0.15, 1.0)  # Elevate confidence due to compound risk context
            
            # Identify if individual structural indicators represent definitive leakage threats
            if res.score >= 0.75 or res.entity_type in ["CNIC", "API_KEY"]:
                has_high_risk_pii = True
                
            calibrated_results.append(res)

        # Step C: Formulate Anonymizer Mapping Block matching explicit PDF instructions
        # Maps internal Presidio definitions cleanly to specified output brackets
        anonymizer_operators = {
            "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "CNIC": OperatorConfig("replace", {"new_value": "<CNIC>"}),
            "STUDENT_ID": OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
            "API_KEY": OperatorConfig("replace", {"new_value": "<API_KEY>"})
        }

        anonymized_payload = self.anonymizer.anonymize(
            text=text,
            analyzer_results=calibrated_results,
            operators=anonymizer_operators
        )

        # Convert back into clean list formats for downstream logging payloads
        serializable_entities = [
            {"type": res.entity_type, "score": round(res.score, 2), "start": res.start, "end": res.end}
            for res in calibrated_results
        ]

        return anonymized_payload.text, serializable_entities, has_high_risk_pii