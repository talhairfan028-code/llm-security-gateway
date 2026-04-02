from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

# Standard initialization. 
# Presidio is smart enough to find the 'en_core_web_lg' model you downloaded 
# as long as it's the primary model in your environment.
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def mask_pii(text: str) -> str:
    """
    Detects and masks PII to fulfill the 'Anonymize PII' requirement.
    Uses the large model for maximum accuracy.
    """
    results = analyzer.analyze(
        text=text, 
        entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"], 
        language='en'
    )
    
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=results
    )
    
    return anonymized_result.text