import json
from pathlib import Path

def load_wazuh_logs(filepath: str) -> list[dict]:
    alerts = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                pass  # pomijamy linie które nie są JSON
    return alerts