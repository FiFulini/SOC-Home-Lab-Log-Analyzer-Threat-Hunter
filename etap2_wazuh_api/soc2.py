"""
soc2.py — CLI Etapu 2
Podkomendy: poll, status, query, agents
"""

import argparse
import json
import logging
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)


def parse_date(value):
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"Zła data: '{value}'")


# ── poll ──────────────────────────────────────

def cmd_poll(args):
    from wazuh_client import WazuhClient, WazuhConfig
    from alert_store  import AlertStore
    from poller       import Poller

    config = WazuhConfig(host=args.host, port=args.port,
                         user=args.user, password=args.password)
    poller = Poller(
        client=WazuhClient(config),
        store=AlertStore(db_path=args.db),
        interval=args.interval,
        min_level=args.level,
        batch_size=args.batch,
    )
    poller.run()


# ── status ────────────────────────────────────

def cmd_status(args):
    from wazuh_client import WazuhClient, WazuhConfig
    from alert_store  import AlertStore

    # Status bazy lokalnej
    store = AlertStore(db_path=args.db)
    stats = store.get_stats()
    SEP   = "─" * 56

    print(f"\n{SEP}")
    print(f" STATUS ETAPU 2")
    print(SEP)
    print(f"  Baza:          {args.db}")
    print(f"  Alertów:       {stats.get('total', 0)}")
    if stats.get("ts_min"):
        print(f"  Zakres:        {stats['ts_min'][:19]} → {stats['ts_max'][:19]}")
    if stats.get("by_level"):
        print(f"\n  Rozkład poziomów:")
        for lvl, cnt in sorted(stats["by_level"].items(), key=lambda x: int(x[0])):
            label = "KRYT" if int(lvl) >= 13 else "WYS" if int(lvl) >= 10 else "ŚR" if int(lvl) >= 7 else "NIS"
            bar   = "█" * min(cnt // 2, 25)
            print(f"    Lvl {lvl:>2} [{label:4}] {bar} ({cnt})")

    if stats.get("top_ips"):
        print(f"\n  Top atakujące IP:")
        for ip, cnt in stats["top_ips"].items():
            print(f"    {ip:<20} {cnt}x")

    # Status API (opcjonalnie)
    if not args.no_api:
        print(f"\n  Wazuh API ({args.host}:{args.port}):")
        try:
            config = WazuhConfig(host=args.host, port=args.port,
                                 user=args.user, password=args.password)
            client = WazuhClient(config)
            info   = client.get_manager_info()
            svc    = client.get_manager_status()
            print(f"    Wersja:  {info['version']}")
            print(f"    Host:    {info['hostname']}")
            for name, state in svc.items():
                icon = "✓" if state == "running" else "✗"
                print(f"    {icon} {name}: {state}")
        except Exception as e:
            print(f"    Niedostępne: {e}")

    print(f"{SEP}\n")


# ── query ─────────────────────────────────────

def cmd_query(args):
    from alert_store import AlertStore
    from collections import Counter

    store  = AlertStore(db_path=args.db)
    alerts = store.get_alerts(
        min_level=args.level,
        date_from=args.date_from,
        date_to=args.date_to,
        agent_name=args.agent,
        srcip=args.ip,
        limit=args.limit,
    )

    if not alerts:
        print("Brak alertów dla podanych filtrów.")
        return

    SEP = "─" * 80
    print(f"\n{SEP}")
    print(f" WYNIKI ZAPYTANIA  |  znaleziono: {len(alerts)}")
    print(SEP)

    if args.format == "table":
        print(f"\n  {'Czas':<20} {'Lvl':>4}  {'Reguła':<8} {'Agent':<22} {'IP źródłowe':<18} Opis")
        print(f"  {'─'*20} {'─'*4}  {'─'*8} {'─'*22} {'─'*18} {'─'*30}")
        for a in alerts:
            ts    = a["timestamp"][:19].replace("T", " ")
            lvl   = a["rule"]["level"]
            rid   = a["rule"]["id"]
            agent = a["agent"]["name"][:22]
            ip    = a.get("data", {}).get("srcip", "")[:18]
            desc  = a["rule"]["description"][:35]
            icon  = "!!!" if lvl >= 13 else "!! " if lvl >= 10 else " ! " if lvl >= 7 else "   "
            print(f"  [{icon}] {ts}  {lvl:>3}  {rid:<8} {agent:<22} {ip:<18} {desc}")

    elif args.format == "json":
        print(json.dumps(alerts, indent=2, ensure_ascii=False))

    elif args.format == "summary":
        top_rules = Counter(
            f"[{a['rule']['id']}] {a['rule']['description'][:50]}" for a in alerts
        )
        print(f"\n  Top reguły:\n")
        for rule, cnt in top_rules.most_common(10):
            bar = "█" * min(cnt, 35)
            print(f"  {bar} {cnt:>3}x  {rule}")

    print(f"\n{SEP}\n")


# ── agents ────────────────────────────────────

def cmd_agents(args):
    from wazuh_client import WazuhClient, WazuhConfig

    config = WazuhConfig(host=args.host, port=args.port,
                         user=args.user, password=args.password)
    try:
        agents = WazuhClient(config).get_agents()
    except Exception as e:
        print(f"Błąd: {e}")
        return

    SEP = "─" * 56
    print(f"\n{SEP}")
    print(f" AGENCI WAZUH  |  łącznie: {len(agents)}")
    print(SEP)
    print(f"  {'ID':<5} {'Nazwa':<25} {'IP':<16} Status")
    print(f"  {'─'*5} {'─'*25} {'─'*16} {'─'*12}")
    for a in agents:
        icon = "●" if a["status"] == "active" else "○"
        print(f"  {a['id']:<5} {a['name']:<25} {a['ip']:<16} {icon} {a['status']}")
    print(f"{SEP}\n")


# ──────────────────────────────────────────────
# Budowanie CLI
# ──────────────────────────────────────────────

def add_connection_args(p):
    g = p.add_argument_group("połączenie z Wazuh API")
    g.add_argument("--host",     default="127.0.0.1",
                   help="Host Wazuh API (domyślnie: 127.0.0.1 = mock)")
    g.add_argument("--port",     type=int, default=55000)
    g.add_argument("--user",     default="wazuh")
    g.add_argument("--password", default="wazuh")


def build_parser():
    root = argparse.ArgumentParser(
        prog="soc2",
        description="SOC Home Lab — Etap 2: Wazuh API + SQLite",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  # Uruchom mock serwer w osobnym terminalu:
  python mock_wazuh_server.py

  # Zbieraj alerty co 5 sekund:
  python soc2.py poll

  # Zbieraj tylko alerty ≥7, co 10 sekund:
  python soc2.py poll --level 7 --interval 10

  # Status bazy i API:
  python soc2.py status

  # Zapytaj bazę — tabela alertów:
  python soc2.py query --level 7

  # Zapytaj bazę — konkretny zakres dat:
  python soc2.py query --from 2024-06-01 --to 2024-06-03 --level 5

  # Zapytaj bazę — konkretny agent lub IP:
  python soc2.py query --agent linux-server-01
  python soc2.py query --ip 91.108.4.200 --format summary

  # Lista agentów:
  python soc2.py agents

  # Na prawdziwym Wazuhu (RPi):
  python soc2.py poll --host 192.168.1.50 --password TWOJE_HASLO
        """
    )

    sub = root.add_subparsers(dest="cmd", metavar="KOMENDA")
    sub.required = True

    # poll
    p_poll = sub.add_parser("poll", help="Zbieraj alerty z API co X sekund")
    add_connection_args(p_poll)
    p_poll.add_argument("--interval", type=int, default=5)
    p_poll.add_argument("--level",    type=int, default=0)
    p_poll.add_argument("--db",       default="alerts.db")
    p_poll.add_argument("--batch",    type=int, default=100)
    p_poll.set_defaults(func=cmd_poll)

    # status
    p_stat = sub.add_parser("status", help="Status bazy lokalnej i Wazuh API")
    add_connection_args(p_stat)
    p_stat.add_argument("--db",       default="alerts.db")
    p_stat.add_argument("--no-api",   action="store_true",
                        help="Pokaż tylko status bazy, bez sprawdzania API")
    p_stat.set_defaults(func=cmd_status)

    # query
    p_q = sub.add_parser("query", help="Przeszukaj lokalną bazę alertów")
    p_q.add_argument("--db",     default="alerts.db")
    p_q.add_argument("--level",  type=int, default=0)
    p_q.add_argument("--from",   dest="date_from", type=parse_date, default=None)
    p_q.add_argument("--to",     dest="date_to",   type=parse_date, default=None)
    p_q.add_argument("--agent",  default=None, help="Filtruj po nazwie agenta")
    p_q.add_argument("--ip",     default=None, help="Filtruj po IP atakującego")
    p_q.add_argument("--limit",  type=int, default=50)
    p_q.add_argument("--format", choices=["table","summary","json"], default="table")
    p_q.set_defaults(func=cmd_query)

    # agents
    p_ag = sub.add_parser("agents", help="Lista agentów Wazuh")
    add_connection_args(p_ag)
    p_ag.set_defaults(func=cmd_agents)

    return root


if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()
    args.func(args)
