"""
SOC Visualizer — wykresy z logów Wazuh z filtrowaniem po zakresie dat
"""

import json
import argparse
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches


SEVERITY_COLORS = {
    "critical": "#e63946",
    "high":     "#f4a261",
    "medium":   "#e9c46a",
    "low":      "#90be6d",
}

def level_to_severity(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"

def level_to_color(level: int) -> str:
    return SEVERITY_COLORS[level_to_severity(level)]

plt.rcParams.update({
    "figure.facecolor": "#0d1117",
    "axes.facecolor":   "#161b22",
    "axes.edgecolor":   "#30363d",
    "axes.labelcolor":  "#c9d1d9",
    "axes.grid":        True,
    "grid.color":       "#21262d",
    "grid.linewidth":   0.6,
    "text.color":       "#c9d1d9",
    "xtick.color":      "#8b949e",
    "ytick.color":      "#8b949e",
    "font.family":      "monospace",
    "font.size":        9,
})


# ──────────────────────────────────────────────
# Wczytywanie i filtrowanie
# ──────────────────────────────────────────────

def parse_ts(alert: dict) -> datetime:
    return datetime.strptime(alert["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")

def parse_date(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(
        f"Zła data: '{value}'. Użyj YYYY-MM-DD lub 'YYYY-MM-DD HH:MM'"
    )

def load_and_filter(filepath: str,
                    date_from: datetime = None,
                    date_to:   datetime = None) -> list[dict]:
    alerts = []
    skipped_parse = 0
    skipped_range = 0

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                ts    = parse_ts(alert)
                if date_from and ts < date_from:
                    skipped_range += 1
                    continue
                if date_to and ts > date_to:
                    skipped_range += 1
                    continue
                alerts.append(alert)
            except (json.JSONDecodeError, KeyError, ValueError):
                skipped_parse += 1

    # Informacja o filtrze
    if date_from or date_to:
        range_str = (
            f"{date_from.strftime('%Y-%m-%d %H:%M') if date_from else 'początek'}"
            f" → "
            f"{date_to.strftime('%Y-%m-%d %H:%M') if date_to else 'koniec'}"
        )
        print(f"Filtr dat: {range_str}")
        print(f"  Wczytano: {len(alerts)}  |  Pominięto (poza zakresem): {skipped_range}")
    else:
        print(f"Wczytano wszystkie {len(alerts)} alertów (brak filtru dat)")

    if skipped_parse:
        print(f"  Pominięto uszkodzone linie: {skipped_parse}")

    return alerts


# ──────────────────────────────────────────────
# Wykresy
# ──────────────────────────────────────────────

def plot_timeline(ax, alerts: list[dict]) -> None:
    times  = [parse_ts(a) for a in alerts]
    levels = [a["rule"]["level"] for a in alerts]
    colors = [level_to_color(l) for l in levels]
    sizes  = [max(10, l ** 1.8) for l in levels]

    ax.scatter(times, levels, c=colors, s=sizes, alpha=0.7, linewidths=0)
    ax.set_ylabel("Poziom ryzyka")
    ax.set_title("Alerty na osi czasu", color="#c9d1d9", pad=8)
    ax.set_ylim(0, 16)

    # Dynamiczny format osi X zależny od rozpiętości danych
    if times:
        span = (max(times) - min(times)).total_seconds()
        if span <= 3600 * 6:
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
            ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=30))
        elif span <= 3600 * 48:
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m %H:%M"))
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=4))
        else:
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m"))
            ax.xaxis.set_major_locator(mdates.DayLocator(interval=1))

    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")

    for lvl, label, color in [
        (13, "KRYTYCZNY", "#e63946"),
        (10, "WYSOKI",    "#f4a261"),
        (7,  "ŚREDNI",    "#e9c46a"),
    ]:
        ax.axhline(lvl, color=color, linewidth=0.8, linestyle="--", alpha=0.5)
        if times:
            ax.text(min(times), lvl + 0.3, label, color=color, fontsize=7, alpha=0.8)


def plot_heatmap(ax, alerts: list[dict]) -> None:
    high_risk   = [a for a in alerts if a["rule"]["level"] >= 7]
    hour_counts = Counter(parse_ts(a).hour for a in high_risk)
    hours       = list(range(24))
    counts      = [hour_counts.get(h, 0) for h in hours]
    max_count   = max(counts) if any(counts) else 1

    colors = [plt.cm.YlOrRd(min(c / max_count, 1.0)) for c in counts]
    bars   = ax.bar(hours, counts, color=colors, width=0.85,
                    edgecolor="#21262d", linewidth=0.5)

    ax.set_xlabel("Godzina")
    ax.set_ylabel("Liczba alertów (poziom ≥ 7)")
    ax.set_title("Aktywność ataków wg godziny", color="#c9d1d9", pad=8)
    ax.set_xticks(hours)
    ax.set_xticklabels([f"{h:02d}" for h in hours], fontsize=7)

    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                    str(count), ha="center", va="bottom", fontsize=7, color="#c9d1d9")


def plot_top_rules(ax, alerts: list[dict]) -> None:
    rule_counts = Counter()
    rule_info   = {}
    for a in alerts:
        rid = a["rule"]["id"]
        rule_counts[rid] += 1
        rule_info[rid] = {
            "desc":  a["rule"]["description"][:45],
            "level": a["rule"]["level"],
        }

    top10  = rule_counts.most_common(10)
    ids    = [r[0] for r in reversed(top10)]
    counts = [r[1] for r in reversed(top10)]
    labels = [f'[{ri}] {rule_info[ri]["desc"]}' for ri in ids]
    colors = [level_to_color(rule_info[ri]["level"]) for ri in ids]

    bars = ax.barh(labels, counts, color=colors, edgecolor="#21262d",
                   linewidth=0.5, height=0.7)
    ax.set_xlabel("Liczba wyzwoleń")
    ax.set_title("Top 10 reguł Wazuh", color="#c9d1d9", pad=8)
    ax.tick_params(axis="y", labelsize=7)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=7, color="#c9d1d9")


def plot_top_ips(ax, alerts: list[dict]) -> None:
    high_risk = [a for a in alerts if a["rule"]["level"] >= 7]
    ip_counts = Counter(
        a.get("data", {}).get("srcip", "unknown")
        for a in high_risk
        if a.get("data", {}).get("srcip", "unknown") != "unknown"
    )
    top_ips = ip_counts.most_common(8)
    if not top_ips:
        ax.text(0.5, 0.5, "Brak danych o IP", transform=ax.transAxes,
                ha="center", va="center", color="#8b949e")
        return

    ips    = [ip for ip, _ in reversed(top_ips)]
    counts = [c  for _, c  in reversed(top_ips)]

    KNOWN_BAD = {"203.0.113.77", "198.51.100.22", "185.220.101.45", "91.108.4.200"}
    colors = ["#e63946" if ip in KNOWN_BAD else "#f4a261" for ip in ips]

    bars = ax.barh(ips, counts, color=colors, edgecolor="#21262d",
                   linewidth=0.5, height=0.6)
    ax.set_xlabel("Liczba alertów wysokiego ryzyka")
    ax.set_title("Top atakujące IP", color="#c9d1d9", pad=8)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=8, color="#c9d1d9")

    legend = [
        mpatches.Patch(color="#e63946", label="Znane złe IP"),
        mpatches.Patch(color="#f4a261", label="Nieznane źródło"),
    ]
    ax.legend(handles=legend, loc="lower right", fontsize=7,
              facecolor="#161b22", edgecolor="#30363d")


# ──────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────

def generate_dashboard(
    input_file: str,
    output_file: str,
    date_from:   datetime = None,
    date_to:     datetime = None,
) -> None:

    alerts = load_and_filter(input_file, date_from, date_to)

    if not alerts:
        print("Brak alertów w podanym zakresie dat — sprawdź --from / --to.")
        return

    ts_min = parse_ts(min(alerts, key=parse_ts))
    ts_max = parse_ts(max(alerts, key=parse_ts))

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle(
        f"SOC Dashboard  |  {len(alerts)} alertów  |  "
        f"{ts_min.strftime('%Y-%m-%d %H:%M')} → {ts_max.strftime('%Y-%m-%d %H:%M')}",
        color="#c9d1d9", fontsize=11, y=0.98,
    )
    fig.patch.set_facecolor("#0d1117")
    plt.subplots_adjust(hspace=0.38, wspace=0.32,
                        left=0.12, right=0.97, top=0.93, bottom=0.08)

    plot_timeline(axes[0][0], alerts)
    plot_heatmap(axes[0][1], alerts)
    plot_top_rules(axes[1][0], alerts)
    plot_top_ips(axes[1][1], alerts)

    legend_patches = [
        mpatches.Patch(color=SEVERITY_COLORS["critical"], label="Krytyczny (13-15)"),
        mpatches.Patch(color=SEVERITY_COLORS["high"],     label="Wysoki (10-12)"),
        mpatches.Patch(color=SEVERITY_COLORS["medium"],   label="Średni (7-9)"),
        mpatches.Patch(color=SEVERITY_COLORS["low"],      label="Niski (1-6)"),
    ]
    fig.legend(handles=legend_patches, loc="lower center", ncol=4,
               fontsize=8, facecolor="#161b22", edgecolor="#30363d",
               bbox_to_anchor=(0.5, 0.01))

    fig.savefig(output_file, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    size_kb = Path(output_file).stat().st_size // 1024
    print(f"Dashboard zapisany: {output_file}  ({size_kb} KB)")


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generator wykresów SOC z logów Wazuh",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  python visualizer.py
  python visualizer.py --from 2024-01-10 --to 2024-01-17
  python visualizer.py --from "2024-01-10 08:00" --to "2024-01-10 20:00"
  python visualizer.py --hours 24
  python visualizer.py --input stare_logi.json --from 2024-01-01 --output styczen.png
        """
    )
    parser.add_argument("--input",  default="sample_logs/wazuh_alerts.json",
                        help="Plik z logami Wazuh (JSON, jeden alert na linię)")
    parser.add_argument("--output", default="soc_dashboard.png",
                        help="Plik wyjściowy PNG")
    parser.add_argument("--hours",  type=int, default=None,
                        help="Pokaż ostatnie N godzin (np. --hours 24)")

    date_group = parser.add_argument_group("zakres dat (alternatywa dla --hours)")
    date_group.add_argument("--from", dest="date_from", type=parse_date, default=None,
                            metavar="YYYY-MM-DD",
                            help="Początek, np. 2024-01-10 lub '2024-01-10 08:00'")
    date_group.add_argument("--to",   dest="date_to",   type=parse_date, default=None,
                            metavar="YYYY-MM-DD",
                            help="Koniec (domyślnie: teraz)")

    args = parser.parse_args()

    # Rozstrzygnięcie priorytetów: --from/--to > --hours > brak filtru
    date_to   = args.date_to
    if args.date_from:
        date_from = args.date_from
    elif args.hours:
        date_from = (args.date_to or datetime.now()) - timedelta(hours=args.hours)
        date_to   = args.date_to or datetime.now()
    else:
        date_from = None

    generate_dashboard(
        input_file=args.input,
        output_file=args.output,
        date_from=date_from,
        date_to=date_to,
    )