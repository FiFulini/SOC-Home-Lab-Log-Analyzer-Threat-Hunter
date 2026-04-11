"""
Wazuh Log Generator — realistyczne scenariusze ataków dla home lab SOC
Generuje: brute-force, port scan, web attacks, privilege escalation,
          file integrity (FIM) z pełnymi polami syscheck
"""

import json
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path

AGENTS = [
    {"id": "001", "name": "linux-server-01",   "ip": "192.168.1.10"},
    {"id": "002", "name": "web-server-02",      "ip": "192.168.1.20"},
    {"id": "003", "name": "db-server-03",       "ip": "192.168.1.30"},
    {"id": "004", "name": "workstation-alice",  "ip": "192.168.1.101"},
    {"id": "005", "name": "workstation-bob",    "ip": "192.168.1.102"},
]

ATTACKER_IPS = ["203.0.113.77", "198.51.100.22", "185.220.101.45", "91.108.4.200"]
LEGIT_IPS    = ["192.168.1.5", "192.168.1.6", "10.0.0.1"]
USERNAMES_REAL  = ["alice", "bob", "admin", "root", "deploy"]
USERNAMES_FAKE  = ["administrator", "test", "guest", "oracle", "postgres",
                   "ubuntu", "pi", "ftpuser", "mysql", "apache"]
WEB_PATHS_NORMAL = ["/", "/index.html", "/about", "/api/status", "/favicon.ico"]
WEB_PATHS_ATTACK = [
    "/admin", "/wp-login.php", "/.env", "/etc/passwd",
    "/../../../etc/shadow", "/shell.php", "/phpmyadmin",
    "/?id=1' OR '1'='1",
]

RULE_SSH_FAIL    = {"id": "5710", "level": 5,  "description": "sshd: Attempt to login using a non-existent user",       "groups": ["syslog","sshd","authentication_failed"]}
RULE_SSH_BRUTE   = {"id": "5760", "level": 10, "description": "sshd: Multiple authentication failures",                  "groups": ["syslog","sshd","authentication_failed","brute_force"]}
RULE_SSH_SUCCESS = {"id": "5715", "level": 3,  "description": "sshd: Authentication success",                            "groups": ["syslog","sshd","authentication_success"]}
RULE_SSH_ROOTOK  = {"id": "5718", "level": 8,  "description": "sshd: Root login allowed",                                "groups": ["syslog","sshd","authentication_success"]}
RULE_WEB_400     = {"id": "31101","level": 5,  "description": "Web server 400 error code",                               "groups": ["web","accesslog","invalid_access"]}
RULE_WEB_401     = {"id": "31151","level": 6,  "description": "Web server 401 Unauthorized",                             "groups": ["web","accesslog","authentication_failed"]}
RULE_WEB_404     = {"id": "31102","level": 3,  "description": "Web server 404 error code",                               "groups": ["web","accesslog"]}
RULE_WEB_SCAN    = {"id": "31151","level": 10, "description": "Web server directory traversal attempt",                  "groups": ["web","accesslog","attack","web_attack"]}
RULE_WEB_SQLI    = {"id": "31106","level": 12, "description": "SQL injection attempt",                                   "groups": ["web","accesslog","attack","sql_injection"]}
RULE_SUDO_FAIL   = {"id": "5503", "level": 7,  "description": "sudo: User missed the password more than one time",       "groups": ["syslog","sudo","authentication_failed"]}
RULE_SUDO_OK     = {"id": "5402", "level": 3,  "description": "sudo: Successful sudo to root",                           "groups": ["syslog","sudo","authentication_success"]}
RULE_PRIVESC     = {"id": "5404", "level": 14, "description": "Privilege escalation via sudo — unusual command",         "groups": ["syslog","sudo","attack","privilege_escalation"]}
RULE_FILE_CHANGE = {"id": "550",  "level": 7,  "description": "Integrity checksum changed",                              "groups": ["ossec","syscheck","integrity_check_failed"]}
RULE_FILE_ADDED  = {"id": "554",  "level": 13, "description": "File added to the system",                                "groups": ["ossec","syscheck","integrity_check_failed"]}
RULE_NORMAL_SYS  = {"id": "1002", "level": 2,  "description": "Unknown problem somewhere in the system",                 "groups": ["syslog"]}
RULE_CRON        = {"id": "2502", "level": 3,  "description": "Cron daemon started",                                     "groups": ["syslog","cron"]}


def rand_md5():
    return "%032x" % random.randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

def rand_sha1():
    return "%040x" % random.randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

def rand_sha256():
    return "%064x" % random.randint(0, (1 << 256) - 1)


def make_alert(rule: dict, agent: dict, timestamp: datetime,
               srcip: str = None, user: str = None,
               extra_data: dict = None,
               syscheck: dict = None) -> dict:
    alert = {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "rule": {
            "id":          rule["id"],
            "level":       rule["level"],
            "description": rule["description"],
            "groups":      rule["groups"],
        },
        "agent":   {"id": agent["id"], "name": agent["name"]},
        "manager": {"name": "wazuh-manager"},
        "id":      str(random.randint(1000000000, 9999999999)),
        "data":    {},
    }
    if srcip:
        alert["data"]["srcip"] = srcip
    if user:
        alert["data"]["dstuser"] = user
    if extra_data:
        alert["data"].update(extra_data)

    # Pole syscheck — szczegóły FIM (File Integrity Monitoring)
    if syscheck:
        alert["syscheck"] = syscheck

    return alert


# ──────────────────────────────────────────────
# Generatory pola syscheck
# ──────────────────────────────────────────────

def make_syscheck_added(filepath: str, uid: str = "0", uname: str = "root",
                         perm: str = "rwxr-xr-x", size: int = None) -> dict:
    """Syscheck dla nowo dodanego pliku — pole 'syscheck' w alercie Wazuh."""
    size = size or random.randint(512, 65536)
    return {
        "path":        filepath,
        "mode":        "realtime",
        "event":       "added",
        "size_after":  str(size),
        "uid_after":   uid,
        "gid_after":   uid,
        "uname_after": uname,
        "gname_after": uname,
        "md5_after":   rand_md5(),
        "sha1_after":  rand_sha1(),
        "sha256_after": rand_sha256(),
        "perm_after":  perm,
        "inode_after": random.randint(100000, 999999),
    }


def make_syscheck_modified(filepath: str, uid: str = "0", uname: str = "root") -> dict:
    """Syscheck dla zmodyfikowanego pliku — zawiera MD5 przed i po zmianie."""
    size_before = random.randint(512, 65536)
    size_after  = size_before + random.randint(-200, 500)
    return {
        "path":         filepath,
        "mode":         "realtime",
        "event":        "modified",
        "size_before":  str(size_before),
        "size_after":   str(max(1, size_after)),
        "uid_before":   uid,
        "uid_after":    uid,
        "gid_before":   uid,
        "gid_after":    uid,
        "uname_before": uname,
        "uname_after":  uname,
        "gname_before": uname,
        "gname_after":  uname,
        "md5_before":   rand_md5(),
        "md5_after":    rand_md5(),
        "sha1_before":  rand_sha1(),
        "sha1_after":   rand_sha1(),
        "sha256_before": rand_sha256(),
        "sha256_after":  rand_sha256(),
        "perm_before":  "rw-r--r--",
        "perm_after":   "rw-r--r--",
        "inode_before": random.randint(100000, 999999),
        "inode_after":  random.randint(100000, 999999),
        "mtime_before": (datetime.now() - timedelta(days=random.randint(1,30))).strftime("%Y-%m-%d %H:%M:%S"),
        "mtime_after":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ──────────────────────────────────────────────
# Scenariusze ataków
# ──────────────────────────────────────────────

def scenario_brute_force(start, agent, attacker_ip):
    alerts = []
    ts = start
    attempts = random.randint(20, 40)
    for i in range(attempts):
        user = random.choice(USERNAMES_FAKE + USERNAMES_REAL)
        rule = RULE_SSH_FAIL if i < attempts - 3 else RULE_SSH_BRUTE
        alerts.append(make_alert(rule, agent, ts, srcip=attacker_ip, user=user))
        ts += timedelta(seconds=random.uniform(1, 8))
    if random.random() < 0.30:
        ts += timedelta(seconds=random.uniform(5, 20))
        user = random.choice(USERNAMES_REAL)
        alerts.append(make_alert(
            RULE_SSH_ROOTOK if user == "root" else RULE_SSH_SUCCESS,
            agent, ts, srcip=attacker_ip, user=user
        ))
    return alerts


def scenario_web_scan(start, agent, attacker_ip):
    alerts = []
    ts = start
    paths = WEB_PATHS_ATTACK * 3 + WEB_PATHS_NORMAL
    for path in random.sample(paths, min(len(paths), 25)):
        if "passwd" in path or "shadow" in path or "etc" in path:
            rule = RULE_WEB_SCAN
        elif "'" in path or "OR" in path:
            rule = RULE_WEB_SQLI
        elif path in WEB_PATHS_NORMAL:
            rule = random.choice([RULE_WEB_400, RULE_WEB_404])
        else:
            rule = RULE_WEB_401
        alerts.append(make_alert(rule, agent, ts, srcip=attacker_ip,
                                 extra_data={"url": path, "method": "GET"}))
        ts += timedelta(seconds=random.uniform(0.2, 2))
    return alerts


def scenario_privilege_escalation(start, agent):
    alerts = []
    ts = start
    user = random.choice(["bob", "alice", "deploy"])
    for _ in range(random.randint(2, 4)):
        alerts.append(make_alert(RULE_SUDO_FAIL, agent, ts, user=user))
        ts += timedelta(seconds=random.uniform(10, 30))
    alerts.append(make_alert(RULE_SUDO_OK, agent, ts, user=user,
                             extra_data={"command": "/bin/bash"}))
    ts += timedelta(seconds=random.uniform(5, 15))
    alerts.append(make_alert(RULE_PRIVESC, agent, ts, user=user,
                             extra_data={"command": "chmod 4777 /bin/python3",
                                         "pwd": "/tmp"}))
    return alerts


def scenario_file_integrity(start, agent):
    """
    Scenariusz FIM — mix zmodyfikowanych plików systemowych i nowych plików.
    Każdy alert zawiera pełne pole 'syscheck' z hashami, uprawnieniami i rozmiarem.
    """
    alerts = []
    ts = start

    # Zmodyfikowane pliki krytyczne (reguła 550)
    critical_modified = [
        ("/etc/passwd",                  "0", "root", "rw-r--r--"),
        ("/etc/shadow",                  "0", "root", "rw-------"),
        ("/etc/sudoers",                 "0", "root", "r--r-----"),
        ("/etc/crontab",                 "0", "root", "rw-r--r--"),
        ("/root/.ssh/authorized_keys",   "0", "root", "rw-------"),
        ("/usr/bin/sudo",                "0", "root", "rwsr-xr-x"),
        ("/etc/ssh/sshd_config",         "0", "root", "rw-r--r--"),
    ]

    # Nowe podejrzane pliki (reguła 554)
    suspicious_added = [
        ("/tmp/backdoor.sh",             "0", "root", "rwxrwxrwx", 2048),
        ("/tmp/.hidden_shell",           "0", "root", "rwxr-xr-x", 8192),
        ("/var/www/html/shell.php",      "33", "www-data", "rw-r--r--", 1024),
        ("/root/.bash_history_backup",   "0", "root", "rw-------", 512),
        ("/usr/local/bin/netcat_helper", "0", "root", "rwxr-xr-x", 32768),
    ]

    for filepath, uid, uname, perm in random.sample(critical_modified,
                                                      random.randint(2, 4)):
        sc = make_syscheck_modified(filepath, uid, uname)
        alerts.append(make_alert(RULE_FILE_CHANGE, agent, ts, syscheck=sc,
                                 extra_data={"file": filepath}))
        ts += timedelta(seconds=random.uniform(1, 10))

    for filepath, uid, uname, perm, size in random.sample(suspicious_added,
                                                           random.randint(1, 3)):
        sc = make_syscheck_added(filepath, uid, uname, perm, size)
        alerts.append(make_alert(RULE_FILE_ADDED, agent, ts, syscheck=sc,
                                 extra_data={"file": filepath}))
        ts += timedelta(seconds=random.uniform(1, 5))

    return alerts


def scenario_normal_activity(start, count=30):
    alerts = []
    ts = start
    normal_rules = [RULE_SSH_SUCCESS, RULE_NORMAL_SYS, RULE_CRON,
                    RULE_WEB_404, RULE_SUDO_OK, RULE_WEB_400]
    for _ in range(count):
        agent = random.choice(AGENTS)
        rule  = random.choice(normal_rules)
        ip    = random.choice(LEGIT_IPS)
        user  = random.choice(USERNAMES_REAL)
        alerts.append(make_alert(rule, agent, ts, srcip=ip, user=user))
        ts += timedelta(seconds=random.uniform(30, 180))
    return alerts


# ──────────────────────────────────────────────
# Generator główny
# ──────────────────────────────────────────────

def generate_logs(count=1000, output_file="sample_logs/wazuh_alerts.json",
                  date_from=None, date_to=None, seed=42):
    random.seed(seed)
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    if date_to is None:
        date_to = datetime.now()
    if date_from is None:
        date_from = date_to - timedelta(hours=168)

    total_seconds = (date_to - date_from).total_seconds()
    all_alerts = []

    print(f"Generowanie logów: {date_from.strftime('%Y-%m-%d %H:%M')} → "
          f"{date_to.strftime('%Y-%m-%d %H:%M')}")

    all_alerts += scenario_normal_activity(date_from, count=80)

    attack_slots = sorted(random.sample(range(1, int(total_seconds // 60)), 12))
    attack_scenarios = [
        ("Brute-force SSH",          lambda t, a: scenario_brute_force(t, a, random.choice(ATTACKER_IPS))),
        ("Web scan / SQLi",          lambda t, a: scenario_web_scan(t, a, random.choice(ATTACKER_IPS))),
        ("Privilege escalation",     lambda t, a: scenario_privilege_escalation(t, a)),
        ("File integrity violation", lambda t, a: scenario_file_integrity(t, a)),
    ]

    used = []
    for i, slot_min in enumerate(attack_slots):
        ts    = date_from + timedelta(minutes=slot_min)
        agent = random.choice(AGENTS)
        name, fn = attack_scenarios[i % len(attack_scenarios)]
        new_alerts = fn(ts, agent)
        all_alerts += new_alerts
        used.append((name, agent["name"], ts.strftime("%H:%M"), len(new_alerts)))

    all_alerts.sort(key=lambda a: a["timestamp"])

    with open(output_file, "w") as f:
        for alert in all_alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    print(f"\nZapisano {len(all_alerts)} alertów → {output_file}")
    print(f"\n{'Scenariusz':<30} {'Agent':<22} {'Godz.':<8} Alerty")
    print(f"{'─'*30} {'─'*22} {'─'*8} {'─'*6}")
    for name, agent, hour, cnt in used:
        print(f"  {name:<28} {agent:<22} {hour:<8} {cnt}")

    from collections import Counter
    levels = Counter(a["rule"]["level"] for a in all_alerts)
    print(f"\nRozkład poziomów ryzyka:")
    for lvl in sorted(levels):
        bar   = "█" * (levels[lvl] // 2)
        label = "KRYTYCZNY" if lvl >= 13 else "WYSOKI" if lvl >= 10 else "ŚREDNI" if lvl >= 7 else "NISKI"
        print(f"  Lvl {lvl:>2} [{label:<9}] {bar} ({levels[lvl]})")

    # Pokaż przykład alertu FIM żeby użytkownik widział strukturę
    fim_alerts = [a for a in all_alerts if "syscheck" in a]
    if fim_alerts:
        print(f"\nPrzykład alertu FIM (syscheck) — {len(fim_alerts)} takich alertów:")
        print(json.dumps(fim_alerts[0], indent=2, ensure_ascii=False)[:800] + "\n  ...")


def parse_date(value):
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"Zła data: '{value}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generator logów Wazuh dla home lab SOC")
    parser.add_argument("--count",  type=int, default=1000)
    parser.add_argument("--output", default="sample_logs/wazuh_alerts.json")
    parser.add_argument("--hours",  type=int, default=None)
    parser.add_argument("--seed",   type=int, default=42)
    g = parser.add_argument_group("zakres dat")
    g.add_argument("--from", dest="date_from", type=parse_date, default=None, metavar="YYYY-MM-DD")
    g.add_argument("--to",   dest="date_to",   type=parse_date, default=None, metavar="YYYY-MM-DD")
    args = parser.parse_args()

    date_to = args.date_to or datetime.now()
    if args.date_from:
        date_from = args.date_from
    elif args.hours:
        date_from = date_to - timedelta(hours=args.hours)
    else:
        date_from = date_to - timedelta(hours=168)

    generate_logs(count=args.count, output_file=args.output,
                  date_from=date_from, date_to=date_to, seed=args.seed)
