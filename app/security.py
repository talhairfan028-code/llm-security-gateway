import re

# 1. Smarter patterns using Regex wildcards
DETECTION_PATTERNS = {
    "prompt_injection": [
        r"ignore.*rules",         # Catches "ignore all rules", "ignore rules", etc.
        r"ignore.*instructions",  # Catches "ignore previous instructions"
        r"disregard.*previous",
        r"system prompt",
        r"become a",
        r"act as a"
    ],
    "jailbreak": [
        r"dan", 
        r"jailbreak",
        r"do anything now",
        r"bypass security",
        r"hack"
    ],
    "sensitive_leakage": [
        r"reveal",
        r"show me the secret",
        r"internal configuration"
    ]
}

def calculate_injection_score(text: str) -> float:
    score = 0.0
    text_lower = text.lower()
    matches = 0
    
    for category, patterns in DETECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                matches += 1
                
    # Logic: If we find 2 or more matches, it's definitely a block.
    # 1 match = 0.33, 2 matches = 0.67 (Blocks if threshold is 0.5)
    score = min(matches / 3.0, 1.0)
    return round(score, 2)