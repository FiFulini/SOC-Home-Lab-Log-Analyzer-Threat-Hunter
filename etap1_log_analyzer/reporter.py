import csv
from datetime import datetime

def save_to_csv(alerts: list[dict], output_path: str):
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "level", "rule_id", "description", "agent"])
        writer.writeheader()
        for a in alerts:
            writer.writerow({
                "timestamp": a.get("timestamp", ""),
                "level":     a.get("rule", {}).get("level", ""),
                "rule_id":   a.get("rule", {}).get("id", ""),
                "description": a.get("rule", {}).get("description", ""),
                "agent":     a.get("agent", {}).get("name", ""),
            })
    print(f"Zapisano {len(alerts)} alertów do {output_path}")