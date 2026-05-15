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