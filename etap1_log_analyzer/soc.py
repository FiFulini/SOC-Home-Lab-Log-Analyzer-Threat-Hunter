"""
soc.py — główny punkt wejścia projektu SOC Home Lab
Spina parser, detektor brute-force i visualizer w jedno narzędzie CLI
"""

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path


# ──────────────────────────────────────────────
# Parser dat (wspólny dla wszystkich podkomend)
# ──────────────────────────────────────────────

def parse_date(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(
        f"Zła data: '{value}'. Użyj YYYY-MM-DD lub 'YYYY-MM-DD HH:MM'"
    )


# ──────────────────────────────────────────────
# Podkomenda: generate
# ──────────────────────────────────────────────

def cmd_generate(args):
    from generate_sample_logs import generate_logs

    date_to = args.date_to or datetime.now()
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


# ──────────────────────────────────────────────
# Podkomenda: analyze
# ──────────────────────────────────────────────

def cmd_analyze(args):
    import json
    from collections import Counter
    from datetime import datetime

    def load(path, date_from=None, date_to=None):
        alerts = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a  = json.loads(line)
                    ts = datetime.strptime(a["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")
                    if date_from and ts < date_from:
                        continue
                    if date_to and ts > date_to:
                        continue
                    alerts.append(a)
                except Exception:
                    pass
        return alerts

    date_to = args.date_to or datetime.now()
    if args.date_from:
        date_from = args.date_from
    elif args.hours:
        date_from = date_to - timedelta(hours=args.hours)
    else:
        date_from = None

    alerts = load(args.input, date_from, date_to)

    if not alerts:
        print("Brak alertów w podanym zakresie.")
        return

    high = [a for a in alerts if a["rule"]["level"] >= args.level]
    SEP  = "─" * 72

    print(f"\n{SEP}")
    print(f" ANALIZA LOGÓW  |  plik: {args.input}")
    if date_from:
        print(f" Zakres: {date_from.strftime('%Y-%m-%d %H:%M')} → "
              f"{date_to.strftime('%Y-%m-%d %H:%M')}")
    print(f" Wczytano: {len(alerts)} alertów  |  "
          f"poziom ≥{args.level}: {len(high)}")
    print(SEP)

    # Top reguły
    rule_counts = Counter(
        f"[{a['rule']['id']}] {a['rule']['description'][:50]}" for a in high
    )
    print(f"\n Top reguły (poziom ≥{args.level}):\n")
    for rule, count in rule_counts.most_common(args.top):
        bar = "█" * min(count, 40)
        print(f"  {bar} {count:>4}x  {rule}")

    # Top IP
    ip_counts = Counter(
        a.get("data", {}).get("srcip", "")
        for a in high
        if a.get("data", {}).get("srcip")
    )
    if ip_counts:
        print(f"\n Top atakujące IP:\n")
        for ip, count in ip_counts.most_common(5):
            bar = "█" * min(count // 2, 40)
            print(f"  {bar} {count:>4}x  {ip}")

    # Top agenci
    agent_counts = Counter(a["agent"]["name"] for a in high)
    print(f"\n Najczęściej atakowane hosty:\n")
    for agent, count in agent_counts.most_common(5):
        print(f"  {count:>4}x  {agent}")

    print(f"\n{SEP}\n")

    # Zapis CSV
    if args.csv:
        import csv
        out = args.csv_output or f"analiza_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "timestamp", "level", "rule_id", "description", "agent", "srcip"
            ])
            w.writeheader()
            for a in high:
                w.writerow({
                    "timestamp":   a["timestamp"][:19],
                    "level":       a["rule"]["level"],
                    "rule_id":     a["rule"]["id"],
                    "description": a["rule"]["description"],
                    "agent":       a["agent"]["name"],
                    "srcip":       a.get("data", {}).get("srcip", ""),
                })
        print(f" Raport CSV: {out}")


# ──────────────────────────────────────────────
# Podkomenda: brute-force
# ──────────────────────────────────────────────

def cmd_brute(args):
    from brute_force_detector import BruteForceDetector, print_report, save_report_csv, CONFIG

    CONFIG["brute_force"]["window_seconds"] = args.window
    CONFIG["brute_force"]["min_failures"]   = args.min_fail
    CONFIG["spraying"]["min_users"]         = args.min_users

    detector = BruteForceDetector()
    alerts   = detector.analyze(args.input)
    print_report(alerts)

    if args.csv:
        out = args.csv_output or f"brute_force_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        save_report_csv(alerts, out)


# ──────────────────────────────────────────────
# Podkomenda: chart
# ──────────────────────────────────────────────

def cmd_chart(args):
    from visualizer import generate_dashboard

    date_to = args.date_to or None
    if args.date_from:
        date_from = args.date_from
    elif args.hours:
        date_to   = datetime.now()
        date_from = date_to - timedelta(hours=args.hours)
    else:
        date_from = None

    generate_dashboard(
        input_file=args.input,
        output_file=args.output,
        date_from=date_from,
        date_to=date_to,
    )


# ──────────────────────────────────────────────
# Podkomenda: full (wszystko naraz)
# ──────────────────────────────────────────────

def cmd_full(args):
    """Uruchamia analizę + brute-force + wykres w jednym przebiegu."""

    date_to = args.date_to or datetime.now()
    if args.date_from:
        date_from = args.date_from
    elif args.hours:
        date_from = date_to - timedelta(hours=args.hours)
    else:
        date_from = None

    print("=" * 60)
    print(" PEŁNA ANALIZA SOC")
    print("=" * 60)

    # 1. Analiza ogólna
    print("\n[1/3] Analiza ogólna...")
    analyze_ns = argparse.Namespace(
        input=args.input, level=7, top=10,
        date_from=date_from, date_to=date_to,
        hours=None, csv=args.csv,
        csv_output=f"analiza_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
    )
    cmd_analyze(analyze_ns)

    # 2. Detekcja brute-force
    print("\n[2/3] Detekcja brute-force...")
    brute_ns = argparse.Namespace(
        input=args.input, window=60, min_fail=5, min_users=3,
        csv=args.csv,
        csv_output=f"brute_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
    )
    cmd_brute(brute_ns)

    # 3. Wykres
    print("\n[3/3] Generowanie dashboardu...")
    chart_ns = argparse.Namespace(
        input=args.input,
        output=args.chart_output,
        date_from=date_from, date_to=date_to,
        hours=None,
    )
    cmd_chart(chart_ns)

    print("\n Gotowe!")
    print(f"  Dashboard: {args.chart_output}")
    if args.csv:
        print("  Raporty CSV: analiza_*.csv, brute_*.csv")


# ──────────────────────────────────────────────
# Budowanie CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="soc",
        description="SOC Home Lab — analizator logów Wazuh",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  python soc.py generate
  python soc.py generate --from 2024-06-01 --to 2024-06-07
  python soc.py analyze
  python soc.py analyze --level 10 --hours 24 --csv
  python soc.py brute
  python soc.py brute --window 30 --min-fail 3 --csv
  python soc.py chart
  python soc.py chart --from 2024-06-01 --to 2024-06-03 --output tydzien.png
  python soc.py full
  python soc.py full --hours 48 --csv
        """
    )

    # Wspólne argumenty dat (reużywane w podkomendach)
    def add_date_args(p):
        g = p.add_argument_group("zakres dat")
        g.add_argument("--from",   dest="date_from", type=parse_date, default=None,
                       metavar="YYYY-MM-DD", help="Początek zakresu")
        g.add_argument("--to",     dest="date_to",   type=parse_date, default=None,
                       metavar="YYYY-MM-DD", help="Koniec zakresu (domyślnie: teraz)")
        g.add_argument("--hours",  type=int, default=None,
                       help="Ostatnie N godzin (alternatywa dla --from/--to)")

    sub = root.add_subparsers(dest="cmd", metavar="KOMENDA")
    sub.required = True

    # ── generate ──────────────────────────────
    p_gen = sub.add_parser("generate", help="Generuj przykładowe logi Wazuh")
    p_gen.add_argument("--count",  type=int, default=1000)
    p_gen.add_argument("--output", default="sample_logs/wazuh_alerts.json")
    add_date_args(p_gen)
    p_gen.set_defaults(func=cmd_generate)

    # ── analyze ───────────────────────────────
    p_an = sub.add_parser("analyze", help="Analizuj logi — statystyki i top reguły")
    p_an.add_argument("--input",      default="sample_logs/wazuh_alerts.json")
    p_an.add_argument("--level",      type=int, default=7,
                      help="Minimalny poziom ryzyka (domyślnie: 7)")
    p_an.add_argument("--top",        type=int, default=10,
                      help="Ile top reguł pokazać (domyślnie: 10)")
    p_an.add_argument("--csv",        action="store_true")
    p_an.add_argument("--csv-output", dest="csv_output", default=None)
    add_date_args(p_an)
    p_an.set_defaults(func=cmd_analyze)

    # ── brute ─────────────────────────────────
    p_br = sub.add_parser("brute", help="Wykryj ataki brute-force i password spraying")
    p_br.add_argument("--input",      default="sample_logs/wazuh_alerts.json")
    p_br.add_argument("--window",     type=int, default=60,
                      help="Okno czasowe w sekundach (domyślnie: 60)")
    p_br.add_argument("--min-fail",   dest="min_fail", type=int, default=5,
                      help="Min. nieudanych prób (domyślnie: 5)")
    p_br.add_argument("--min-users",  dest="min_users", type=int, default=3,
                      help="Min. użytkowników dla spraying (domyślnie: 3)")
    p_br.add_argument("--csv",        action="store_true")
    p_br.add_argument("--csv-output", dest="csv_output", default=None)
    p_br.set_defaults(func=cmd_brute)

    # ── chart ─────────────────────────────────
    p_ch = sub.add_parser("chart", help="Generuj dashboard PNG z wykresami")
    p_ch.add_argument("--input",  default="sample_logs/wazuh_alerts.json")
    p_ch.add_argument("--output", default="soc_dashboard.png")
    add_date_args(p_ch)
    p_ch.set_defaults(func=cmd_chart)

    # ── full ──────────────────────────────────
    p_fu = sub.add_parser("full", help="Uruchom pełną analizę (analyze + brute + chart)")
    p_fu.add_argument("--input",        default="sample_logs/wazuh_alerts.json")
    p_fu.add_argument("--chart-output", dest="chart_output", default="soc_dashboard.png")
    p_fu.add_argument("--csv",          action="store_true")
    add_date_args(p_fu)
    p_fu.set_defaults(func=cmd_full)

    return root


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()
    args.func(args)
