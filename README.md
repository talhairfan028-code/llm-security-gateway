# Multilayered Hybrid LLM Security Gateway

An asynchronous, defense-in-depth security proxy engineered to intercept, evaluate, and neutralize adversarial prompt injections, systemic jailbreaks, and Personally Identifiable Information (PII) leaks in real time before payloads reach downstream Large Language Models (LLMs).

This repository represents the final project submission for the **Artificial Intelligence & Cyber Security Lab** at **COMSATS University Islamabad, Wah Campus**.

---

## 🚀 Key Enhancements (Final vs. Midterm Baseline)
* **Deterministic to Statistical Transformation:** Replaced simple keyword-matching limits with a localized machine learning text classification pipeline (TF-IDF + Regularized Logistic Regression) running entirely offline to preserve data privacy.
* **Multilingual Script Routing:** Integrated script tracing via `langdetect` to identify and handle adversarial inputs across English (EN), Urdu (UR), and Korean (KO) character scripts.
* **Localized PII Token Engineering:** Extended the Microsoft Presidio framework by implementing custom `PatternRecognizer` objects to securely track and mask Pakistani National Identity Cards (CNICs) and University Student Registration IDs.
* **Asynchronous Policy Engine:** Centralized scoring weights, mapping incoming queries into strict `ALLOW`, `MASK`, or `BLOCK` execution directives based on a calibrated risk boundary matrix.

---

## 📁 Repository Architecture

The project enforces a strict separation of concerns across highly isolated functional subdirectories:

```text
llm-security-gateway/
├── config/
│   └── gateway_config.yaml     # Centralized threshold and weights parameters
├── data/
│   └── final_eval.csv          # Generated 152-row testing validation dataset
├── app/
│   ├── __init__.py
│   ├── main.py                 # Core FastAPI routing and server assembly
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── rule_detector.py     # Deterministic O(1) signature scanner
│   │   └── semantic_detector.py # Offline TF-IDF + Logistic Regression model
│   ├── pii/
│   │   ├── __init__.py
│   │   └── presidio_custom.py   # Regional Pakistani PII scrubbing engines
│   ├── policy/
│   │   ├── __init__.py
│   │   └── policy_engine.py     # Asymmetric risk consolidation layer
│   └── utils/
│       ├── __init__.py
│       ├── language.py          # Script detection and validation routing
│       └── logging.py           # JSON audit log output stream
├── results/
│   ├── evaluation_results_calibrated.csv # Row-by-row testing execution trace
│   └── metrics_summary.json              # Consolidated evaluation output block
├── .gitignore                  # Isolated local environment exclusions
└── run_evaluation.py           # Automated evaluation harness
⚙️ Core Pipeline MethodologyWhen an untrusted payload hits the /analyze endpoint, it undergoes standard sequential processing blocks:Script Validation: The system runs a script check to capture and handle supported language branches (EN, UR, KO), failing fast on unsupported scripts.Signature Scan: Fast, deterministic regex checks screen the input text for explicit, high-frequency override commands.Semantic Inference: Inputs pass through a locally regularized machine learning classifier. The system extracts n-gram boundaries and computes a probabilistic threat rating:$$P(y = 1 \mid \vec{x}) = \frac{1}{1 + e^{-(\beta_0 + \sum \beta_i x_i)}}$$PII Anonymization: Text ranges matching custom local context strings (CNIC/Student ID) are dynamically scrubbed and masked.Policy Consolidation: Combined category risk outputs are evaluated against calibrated decision boundaries (block_threshold: 0.58) to issue the final proxy directive.📊 Empirical Evaluation SummaryThe performance of the security gateway was programmatically validated across a comprehensive testing grid comprising 152 distinct validation scenarios.System Performance ProfilePerformance DimensionScoreAcademic SignificanceGlobal Classification Accuracy99.34%System correctness across all combined scenarios.System Precision0.9863Percentage of actual attacks out of all flagged blocks.Recall (Sensitivity)1.0000Flawless Catch Rate. Zero attacks bypassed the gateway.F1-Score Metric0.9931Harmonic balance between model precision and recall.Confusion Matrix SummaryTrue Positives (TP): 72 (Adversarial vectors correctly neutralized)False Positives (FP): 1 (Benign request safely blocked due to conservative settings)False Negatives (FN): 0 (Zero malicious prompts leaked to the downstream LLM)True Negatives (TN): 79 (Safe requests properly permitted or masked)Script Performance & Operational Latency BoundariesLanguage [EN]: 100.00% Recall (56/56)Language [UR]: 100.00% Recall (15/15)Language [KO]: 100.00% Recall (1/1)Mean Gateway Processing Latency: 20.54 ms (Fully optimized for live streaming applications)95th Percentile Bound (p95): 25.22 ms🛠️ Setup & Local Execution1. Environment PreparationEnsure you are operating in your project root terminal, initialize your virtual isolation environment, and update your local dependencies:Bash# Initialize and activate environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install required third-party libraries
.\venv\Scripts\pip install fastapi uvicorn langdetect scikit-learn pyyaml presidio-analyzer
2. Launch the Gateway ServerKickstart the local server using the direct execution route:Bash.\venv\Scripts\uvicorn app.main:app --reload
The endpoint will be available locally at http://127.0.0.1:8000.3. Run the Automated Verification SuiteOpen a separate terminal instance and execute the evaluation harness to compile your metrics logs live:Bash.\venv\Scripts\python run_evaluation.py
🎓 Academic AttributionsCourse: Artificial Intelligence (Computer Science Department)Submitted To: Lecturer Tooba TehreemDeveloped By: Talha (4th Semester)