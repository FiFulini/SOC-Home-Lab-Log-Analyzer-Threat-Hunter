"""
Wazuh Log Generator — realistyczne scenariusze ataków dla home lab SOC
"""

import json
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path

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


def generate_alert(timestamp: datetime) -> dict:
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


def parse_date(value: str) -> datetime:
    """Parsuje datę w formacie YYYY-MM-DD lub YYYY-MM-DD HH:MM."""
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(
        f"Zła data: '{value}'. Użyj formatu YYYY-MM-DD lub 'YYYY-MM-DD HH:MM'"
    )


def generate_logs(
    count:       int      = 1000,
    output_file: str      = "sample_logs/wazuh_alerts.json",
    date_from:   datetime = None,
    date_to:     datetime = None,
) -> None:
    # Domyślny zakres: ostatnie 168h (tydzień)
    if date_to is None:
        date_to = datetime.now()
    if date_from is None:
        date_from = date_to - timedelta(hours=168)

    if date_from >= date_to:
        raise ValueError("--from musi być wcześniej niż --to")

    total_seconds = (date_to - date_from).total_seconds()
    step_seconds  = total_seconds / count

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        for i in range(count):
            ts    = date_from + timedelta(seconds=i * step_seconds)
            alert = generate_alert(ts)
            f.write(json.dumps(alert) + "\n")

    print(f"Wygenerowano {count} alertów")
    print(f"  Zakres: {date_from.strftime('%Y-%m-%d %H:%M')} → {date_to.strftime('%Y-%m-%d %H:%M')}")
    print(f"  Plik:   {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generator logów Wazuh",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  python generate_sample_logs.py
  python generate_sample_logs.py --hours 48
  python generate_sample_logs.py --from 2024-01-10 --to 2024-01-17
  python generate_sample_logs.py --from "2024-01-10 08:00" --to "2024-01-10 20:00"
  python generate_sample_logs.py --count 5000 --output sample_logs/duzy.json
        """
    )
    parser.add_argument("--count",  type=int, default=1000,
                        help="Liczba alertów do wygenerowania (domyślnie: 1000)")
    parser.add_argument("--output", default="sample_logs/wazuh_alerts.json",
                        help="Plik wyjściowy")
    parser.add_argument("--hours",  type=int, default=None,
                        help="Okno czasowe wstecz od teraz w godzinach (domyślnie: 168)")

    # Zakres dat — alternatywa dla --hours
    date_group = parser.add_argument_group("zakres dat (alternatywa dla --hours)")
    date_group.add_argument("--from", dest="date_from", type=parse_date, default=None,
                            metavar="YYYY-MM-DD",
                            help="Początek zakresu, np. 2024-01-10 lub '2024-01-10 08:00'")
    date_group.add_argument("--to",   dest="date_to",   type=parse_date, default=None,
                            metavar="YYYY-MM-DD",
                            help="Koniec zakresu (domyślnie: teraz)")

    args = parser.parse_args()

    # Rozstrzygnięcie priorytetów: --from/--to > --hours > domyślne 168h
    date_to   = args.date_to or datetime.now()
    if args.date_from:
        date_from = args.date_from
    elif args.hours:
        date_from = date_to - timedelta(hours=args.hours)
    else:
        date_from = date_to - timedelta(hours=168)

    generate_logs(
        count=args.count,
        output_file=args.output,
        date_from=date_from,
        date_to=date_to,
    )