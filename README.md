# SecureGate: A Modular LLM Security Gateway

This is my Lab Mid project for the Artificial Intelligence (CSC 262) course at COMSATS. I built this because even though LLMs are smart, they are incredibly vulnerable to prompt injections and leaking private data (PII). 

This gateway sits between the user and the LLM, acting as a "security guard" that cleans and checks every message.

## How it Works
The logic is split into a modular pipeline:
1. **API Layer:** Built with FastAPI for high performance.
2. **Injection Detection:** Uses Regex patterns to catch "Ignore rules" or "DAN" style attacks.
3. **PII Masking:** Uses Microsoft Presidio + Spacy (`en_core_web_lg`) to find and anonymize names, emails, and phone numbers.
4. **Decision Engine:** If the "Risk Score" hits 0.3 or higher, the request is blocked before it ever touches the AI.

## The Scoring Logic
I used a simple but effective math formula for the risk assessment:
`Score = (Number of matches) / 3.0`

If a user tries to be sneaky (like saying "h.a.c.k"), the system catches the pattern and blocks the query immediately to save on latency.

## Setup Instructions
1. Clone the repo.
2. Create a virtual environment: `python -m venv venv`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the server: `uvicorn app.main:app --reload`

## Testing Results
I ran several tests to calibrate the thresholds. The gateway typically adds only ~10ms to normal queries, while PII masking takes about 150ms due to the heavy Spacy model.
