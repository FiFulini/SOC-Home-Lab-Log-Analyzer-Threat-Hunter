# etap1_log_analyzer/generate_sample_logs.py
import json
import random
from datetime import datetime, timedelta

RULES = [
    {"id": "5710", "level": 10, "description": "Attempt to login using a non-existent user",  "groups": ["authentication_failed"]},
    {"id": "5760", "level": 12, "description": "Multiple authentication failures",              "groups": ["authentication_failed", "brute_force"]},
    {"id": "5503", "level": 7,  "description": "User missed the password more than one time",  "groups": ["authentication_failed"]},
    {"id": "1002", "level": 5,  "description": "Unknown problem somewhere in the system",      "groups": ["syslog"]},
    {"id": "31101","level": 6,  "description": "Web server 400 error code",                    "groups": ["web", "accesslog"]},
    {"id": "31151","level": 9,  "description": "Web server 401 Unauthorized",                  "groups": ["web", "accesslog"]},
    {"id": "5301", "level": 3,  "description": "Login session opened",                         "groups": ["authentication_success"]},
]

AGENTS   = ["linux-server-01", "web-server-02", "db-server-03", "workstation-01"]
BAD_IPS  = ["192.168.1.105", "10.0.0.44", "203.0.113.77", "198.51.100.22"]
GOOD_IPS = ["192.168.1.10",  "192.168.1.20", "10.0.0.1"]

def generate_alert(timestamp):
    rule   = random.choice(RULES)
    is_bad = rule["level"] >= 7
    return {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "id":          rule["id"],
            "level":       rule["level"],
            "description": rule["description"],
            "groups":      rule["groups"],
        },
        "agent": {"id": f"00{random.randint(1,4)}", "name": random.choice(AGENTS)},
        "data":  {"srcip": random.choice(BAD_IPS if is_bad else GOOD_IPS)},
    }

def generate_logs(count=1000, output_file="sample_logs/wazuh_alerts.json"):
    start = datetime.now() - timedelta(hours=168)
    with open(output_file, "w") as f:
        for i in range(count):
            ts    = start + timedelta(seconds=i * 86)
            alert = generate_alert(ts)
            f.write(json.dumps(alert) + "\n")
    print(f"Wygenerowano {count} alertów -> {output_file}")

if __name__ == "__main__":
    generate_logs()