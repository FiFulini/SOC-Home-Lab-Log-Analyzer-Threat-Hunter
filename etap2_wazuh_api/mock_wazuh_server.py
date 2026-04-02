"""
Mock Wazuh API Server — symuluje REST API prawdziwego Wazuh Managera
Endpoints zgodne z Wazuh API v4.x

Uruchom: python mock_wazuh_server.py
Domyślnie nasłuchuje na: http://localhost:55000
"""

import json
import random
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


# ──────────────────────────────────────────────
# Dane symulowanego środowiska
# ──────────────────────────────────────────────

AGENTS = [
    {"id": "001", "name": "linux-server-01",   "ip": "192.168.1.10",  "status": "active"},
    {"id": "002", "name": "web-server-02",      "ip": "192.168.1.20",  "status": "active"},
    {"id": "003", "name": "db-server-03",       "ip": "192.168.1.30",  "status": "active"},
    {"id": "004", "name": "workstation-alice",  "ip": "192.168.1.101", "status": "active"},
    {"id": "005", "name": "workstation-bob",    "ip": "192.168.1.102", "status": "disconnected"},
]

RULES = [
    {"id": "5710", "level": 5,  "description": "sshd: Attempt to login using a non-existent user",   "groups": ["syslog","sshd","authentication_failed"]},
    {"id": "5760", "level": 10, "description": "sshd: Multiple authentication failures",              "groups": ["syslog","sshd","brute_force"]},
    {"id": "5715", "level": 3,  "description": "sshd: Authentication success",                        "groups": ["syslog","sshd","authentication_success"]},
    {"id": "5503", "level": 7,  "description": "sudo: User missed the password more than one time",   "groups": ["syslog","sudo","authentication_failed"]},
    {"id": "31101","level": 5,  "description": "Web server 400 error code",                           "groups": ["web","accesslog"]},
    {"id": "31151","level": 9,  "description": "Web server directory traversal attempt",              "groups": ["web","accesslog","attack"]},
    {"id": "31106","level": 12, "description": "SQL injection attempt",                               "groups": ["web","accesslog","attack","sql_injection"]},
    {"id": "550",  "level": 7,  "description": "Integrity checksum changed",                          "groups": ["ossec","syscheck","integrity_check_failed"]},
    {"id": "554",  "level": 13, "description": "File added to the system",                            "groups": ["ossec","syscheck","integrity_check_failed"]},
    {"id": "5404", "level": 14, "description": "Privilege escalation via sudo",                       "groups": ["syslog","sudo","attack","privilege_escalation"]},
]

ATTACKER_IPS = ["203.0.113.77", "198.51.100.22", "185.220.101.45", "91.108.4.200"]
LEGIT_IPS    = ["192.168.1.5", "192.168.1.6", "10.0.0.1"]

# Globalny licznik alertów (rośnie między zapytaniami — symuluje nowe zdarzenia)
_alert_counter = {"value": 1000}
_alert_lock    = threading.Lock()


# ──────────────────────────────────────────────
# Generator pojedynczego alertu
# ──────────────────────────────────────────────

def make_alert(offset_seconds: int = 0) -> dict:
    rule   = random.choice(RULES)
    agent  = random.choice(AGENTS)
    is_bad = rule["level"] >= 7
    ts     = datetime.utcnow() - timedelta(seconds=offset_seconds)

    with _alert_lock:
        _alert_counter["value"] += 1
        alert_id = str(_alert_counter["value"])

    return {
        "id":        alert_id,
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "id":          rule["id"],
            "level":       rule["level"],
            "description": rule["description"],
            "groups":      rule["groups"],
        },
        "agent": {"id": agent["id"], "name": agent["name"]},
        "manager": {"name": "wazuh-manager"},
        "data": {
            "srcip":   random.choice(ATTACKER_IPS if is_bad else LEGIT_IPS),
            "dstuser": random.choice(["root","admin","alice","bob","deploy","unknown"]),
        },
    }


# ──────────────────────────────────────────────
# HTTP Handler
# ──────────────────────────────────────────────

VALID_TOKEN = "mock-jwt-token-etap2"

class WazuhMockHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Krótszy log w terminalu
        print(f"  [mock] {self.command} {self.path} → {args[1]}")

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def require_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_json({"error": {"code": 401, "message": "Unauthorized"}}, 401)
            return False
        token = auth.split(" ", 1)[1]
        if token != VALID_TOKEN:
            self.send_json({"error": {"code": 401, "message": "Invalid token"}}, 401)
            return False
        return True

    def do_POST(self):
        parsed = urlparse(self.path)

        # POST /security/user/authenticate — zwraca token JWT
        if parsed.path == "/security/user/authenticate":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length) or b"{}")
            user   = body.get("user", "")
            pwd    = body.get("password", "")

            if user == "wazuh" and pwd == "wazuh":
                self.send_json({
                    "data": {"token": VALID_TOKEN},
                    "error": 0,
                })
            else:
                self.send_json({"error": {"code": 401, "message": "Wrong credentials"}}, 401)
            return

        self.send_json({"error": {"code": 404, "message": "Not found"}}, 404)

    def do_GET(self):
        if not self.require_auth():
            return

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path   = parsed.path

        # GET /agents — lista agentów
        if path == "/agents":
            status_filter = params.get("status", [None])[0]
            agents = AGENTS if not status_filter else [
                a for a in AGENTS if a["status"] == status_filter
            ]
            self.send_json({
                "data": {
                    "affected_items":        agents,
                    "total_affected_items":  len(agents),
                    "total_failed_items":    0,
                },
                "error": 0,
            })
            return

        # GET /alerts — lista alertów
        if path == "/alerts":
            limit      = int(params.get("limit",  [20])[0])
            offset     = int(params.get("offset", [0])[0])
            min_level  = int(params.get("level",  [0])[0])

            # Generuj świeże alerty symulując "nowe zdarzenia od ostatniego zapytania"
            count  = min(limit, random.randint(5, 25))
            alerts = []
            for i in range(count):
                a = make_alert(offset_seconds=random.randint(0, 300))
                if a["rule"]["level"] >= min_level:
                    alerts.append(a)

            self.send_json({
                "data": {
                    "affected_items":       alerts,
                    "total_affected_items": len(alerts),
                    "total_failed_items":   0,
                },
                "error": 0,
            })
            return

        # GET /manager/info — informacje o managerze
        if path == "/manager/info":
            self.send_json({
                "data": {
                    "version":    "v4.7.0",
                    "hostname":   "wazuh-manager",
                    "type":       "server",
                    "status":     "running",
                },
                "error": 0,
            })
            return

        # GET /manager/status — status usług
        if path == "/manager/status":
            self.send_json({
                "data": {
                    "wazuh-analysisd": "running",
                    "wazuh-remoted":   "running",
                    "wazuh-db":        "running",
                    "wazuh-monitord":  "running",
                },
                "error": 0,
            })
            return

        self.send_json({"error": {"code": 404, "message": f"Unknown endpoint: {path}"}}, 404)


# ──────────────────────────────────────────────
# Uruchomienie serwera
# ──────────────────────────────────────────────

def run(host: str = "127.0.0.1", port: int = 55000):
    server = HTTPServer((host, port), WazuhMockHandler)
    print(f"Mock Wazuh API nasłuchuje na http://{host}:{port}")
    print(f"  Token:     {VALID_TOKEN}")
    print(f"  Login:     user=wazuh  password=wazuh")
    print(f"  Endpoints: /security/user/authenticate")
    print(f"             /agents")
    print(f"             /alerts?limit=20&level=7")
    print(f"             /manager/info")
    print(f"             /manager/status")
    print(f"\n  Ctrl+C aby zatrzymać\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSerwer zatrzymany.")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Mock Wazuh API Server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=55000)
    args = p.parse_args()
    run(args.host, args.port)
