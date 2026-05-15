import json
import yaml
from pathlib import Path
from datetime import datetime, timezone

class AuditLogger:
    def __init__(self):
        config_path = Path(__file__).resolve().parents[2] / "config" / "gateway_config.yaml"
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            
        self.log_file = Path(__file__).resolve().parents[2] / config["logging"]["audit_log_path"]
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_transaction(self, log_payload: dict):
        """
        Appends a flat transaction summary into the local JSON audit file.
        """
        log_payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_payload, ensure_ascii=False) + "\n")