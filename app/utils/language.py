import yaml
from pathlib import Path
from langdetect import detect_langs, DetectorFactory


DetectorFactory.seed = 42

class LanguageRouter:
    def __init__(self):
        # Dynamically map config path relative to this utility file
        config_path = Path(__file__).resolve().parents[2] / "config" / "gateway_config.yaml"
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        self.supported_languages = self.config["languages"]["supported"]
        self.fallback_language = self.config["languages"]["fallback"]

    def detect_language(self, text: str) -> str:
        """
        Analyzes the text string to determine the language.
        Returns 'en', 'ur', or 'ko' if supported; otherwise defaults to fallback.
        """
        if not text or not text.strip():
            return self.fallback_language

        try:
            # Gather predictions with probabilities
            predictions = detect_langs(text)
            best_match = predictions[0]
            
            lang_code = best_match.lang
            confidence = best_match.prob

            # Route to fallback if confidence is poor or language is unsupported
            if lang_code in self.supported_languages and confidence > 0.5:
                return lang_code
            
            # Simple fallback check for character sets (Urdu / Arabic text check)
            # If the text contains native Arabic script characters, default to Urdu
            if any(u'\u0600' <= char <= u'\u06FF' for char in text):
                return "ur"
                
            return self.fallback_language
        except Exception:
            
            return self.fallback_language