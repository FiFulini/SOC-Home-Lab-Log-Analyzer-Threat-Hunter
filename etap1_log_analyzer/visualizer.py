"""
SOC Visualizer — wykresy i statystyki dla analizatora logów Wazuh
Generuje 4 wykresy zapisane do pliku PNG (gotowe do README na GitHubie)
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")   # tryb bez GUI — działa wszędzie, też na serwerze
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches


# ──────────────────────────────────────────────
# Kolory i styl
# ──────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#e63946",   # czerwony  — poziom 13-15
    "high":     "#f4a261",   # pomarańcz — poziom 10-12
    "medium":   "#e9c46a",   # żółty     — poziom 7-9
    "low":      "#90be6d",   # zielony   — poziom 1-6
}

def level_to_severity(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"

def level_to_color(level: int) -> str:
    return SEVERITY_COLORS[level_to_severity(level)]

plt.rcParams.update({
    "figure.facecolor":  "#0d1117",   # tło ciemne (GitHub dark theme)
    "axes.facecolor":    "#161b22",
    "axes.edgecolor":    "#30363d",
    "axes.labelcolor":   "#c9d1d9",
    "axes.grid":         True,
    "grid.color":        "#21262d",
    "grid.linewidth":    0.6,
    "text.color":        "#c9d1d9",
    "xtick.color":       "#8b949e",
    "ytick.color":       "#8b949e",
    "font.family":       "monospace",
    "font.size":         9,
})


# ──────────────────────────────────────────────
# Wczytywanie
# ──────────────────────────────────────────────

def load_alerts(filepath: str) -> list[dict]:
    alerts = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return alerts

def parse_ts(alert: dict) -> datetime:
    return datetime.strptime(alert["timestamp"][:23], "%Y-%m-%dT%H:%M:%S.%f")


# ──────────────────────────────────────────────
# Wykres 1: Timeline alertów (oś czasu)
# ──────────────────────────────────────────────

def plot_timeline(ax, alerts: list[dict]) -> None:
    """
    Scatter plot: każdy alert to kropka na osi czasu.
    Kolor = severity, rozmiar = level (większy = poważniejszy).
    Szczyty na wykresie to właśnie ataki brute-force.
    """
    times   = [parse_ts(a) for a in alerts]
    levels  = [a["rule"]["level"] for a in alerts]
    colors  = [level_to_color(l) for l in levels]
    sizes   = [max(10, l ** 1.8) for l in levels]   # kwadratowa skala

    ax.scatter(times, levels, c=colors, s=sizes, alpha=0.7, linewidths=0)
    ax.set_ylabel("Poziom ryzyka (Wazuh)")
    ax.set_title("Alerty na osi czasu", color="#c9d1d9", pad=8)
    ax.set_ylim(0, 16)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")

    # Linie poziomów krytycznych
    for lvl, label, color in [
        (13, "KRYTYCZNY", "#e63946"),
        (10, "WYSOKI",    "#f4a261"),
        (7,  "ŚREDNI",    "#e9c46a"),
    ]:
        ax.axhline(lvl, color=color, linewidth=0.8, linestyle="--", alpha=0.5)
        ax.text(times[0], lvl + 0.3, label, color=color,
                fontsize=7, alpha=0.8)


# ──────────────────────────────────────────────
# Wykres 2: Heatmapa aktywności (godzina x dzień)
# ──────────────────────────────────────────────

def plot_heatmap(ax, alerts: list[dict]) -> None:
    """
    Heatmapa: ile alertów wysokiego ryzyka (≥7) w każdej godzinie.
    Jasne pola = intensywny ruch = podejrzane.
    Natychmiast widać godziny ataków.
    """
    high_risk = [a for a in alerts if a["rule"]["level"] >= 7]
    hour_counts = Counter(parse_ts(a).hour for a in high_risk)

    hours  = list(range(24))
    counts = [hour_counts.get(h, 0) for h in hours]

    colors = [plt.cm.YlOrRd(min(c / max(counts, default=1), 1.0)) for c in counts]
    bars   = ax.bar(hours, counts, color=colors, width=0.85, edgecolor="#21262d", linewidth=0.5)

    ax.set_xlabel("Godzina")
    ax.set_ylabel("Liczba alertów (poziom ≥ 7)")
    ax.set_title("Aktywność ataków wg godziny", color="#c9d1d9", pad=8)
    ax.set_xticks(hours)
    ax.set_xticklabels([f"{h:02d}" for h in hours], fontsize=7)

    # Etykiety wartości nad słupkami
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                    str(count), ha="center", va="bottom", fontsize=7, color="#c9d1d9")


# ──────────────────────────────────────────────
# Wykres 3: Top 10 reguł (poziome słupki)
# ──────────────────────────────────────────────

def plot_top_rules(ax, alerts: list[dict]) -> None:
    """
    Top 10 reguł według liczby wyzwoleń.
    Kolor = severity reguły. Dobrze widać które reguły "krzyczą" najgłośniej.
    """
    rule_counts = Counter()
    rule_info   = {}
    for a in alerts:
        rid  = a["rule"]["id"]
        rule_counts[rid] += 1
        rule_info[rid] = {
            "desc":  a["rule"]["description"][:45],
            "level": a["rule"]["level"],
        }

    top10   = rule_counts.most_common(10)
    ids     = [r[0] for r in reversed(top10)]
    counts  = [r[1] for r in reversed(top10)]
    labels  = [f'[{ri}] {rule_info[ri]["desc"]}' for ri in ids]
    colors  = [level_to_color(rule_info[ri]["level"]) for ri in ids]

    bars = ax.barh(labels, counts, color=colors, edgecolor="#21262d",
                   linewidth=0.5, height=0.7)
    ax.set_xlabel("Liczba wyzwoleń")
    ax.set_title("Top 10 reguł Wazuh", color="#c9d1d9", pad=8)
    ax.tick_params(axis="y", labelsize=7)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=7, color="#c9d1d9")


# ──────────────────────────────────────────────
# Wykres 4: Top atakujące IP
# ──────────────────────────────────────────────

def plot_top_ips(ax, alerts: list[dict]) -> None:
    """
    Ranking IP po liczbie alertów wysokiego ryzyka.
    Pozwala szybko znaleźć głównych "sprawców" — kandydatów do blokady.
    """
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

    # Kolor: znane złe IP → czerwony, reszta → pomarańcz
    KNOWN_BAD = {"203.0.113.77", "198.51.100.22", "185.220.101.45", "91.108.4.200"}
    colors = ["#e63946" if ip in KNOWN_BAD else "#f4a261" for ip in ips]

    bars = ax.barh(ips, counts, color=colors, edgecolor="#21262d",
                   linewidth=0.5, height=0.6)
    ax.set_xlabel("Liczba alertów wysokiego ryzyka")
    ax.set_title("Top atakujące IP", color="#c9d1d9", pad=8)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=8, color="#c9d1d9")

    # Legenda
    legend = [
        mpatches.Patch(color="#e63946", label="Znane złe IP"),
        mpatches.Patch(color="#f4a261", label="Nieznane źródło"),
    ]
    ax.legend(handles=legend, loc="lower right", fontsize=7,
              facecolor="#161b22", edgecolor="#30363d")


# ──────────────────────────────────────────────
# Złożenie dashboardu
# ──────────────────────────────────────────────

def generate_dashboard(input_file: str = "sample_logs/wazuh_alerts.json",
                        output_file: str = "soc_dashboard.png") -> None:

    alerts = load_alerts(input_file)
    if not alerts:
        print("Brak alertów do wizualizacji.")
        return

    print(f"Wczytano {len(alerts)} alertów z {input_file}")

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle(
        f"SOC Dashboard  |  {len(alerts)} alertów  |  "
        f"okno: {parse_ts(alerts[0]).strftime('%Y-%m-%d %H:%M')} → "
        f"{parse_ts(alerts[-1]).strftime('%Y-%m-%d %H:%M')}",
        color="#c9d1d9", fontsize=11, y=0.98,
    )
    fig.patch.set_facecolor("#0d1117")
    plt.subplots_adjust(hspace=0.38, wspace=0.32,
                        left=0.12, right=0.97, top=0.93, bottom=0.08)

    plot_timeline(axes[0][0], alerts)
    plot_heatmap(axes[0][1], alerts)
    plot_top_rules(axes[1][0], alerts)
    plot_top_ips(axes[1][1], alerts)

    # Legenda severity (wspólna dla całego dashboardu)
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
    print(f"Dashboard zapisany: {output_file}  ({Path(output_file).stat().st_size // 1024} KB)")
    print("\nGotowe! :")
    print("  ![SOC Dashboard](soc_dashboard.png)")


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Generator wykresów SOC z logów Wazuh")
    p.add_argument("--input",  default="sample_logs/wazuh_alerts.json")
    p.add_argument("--output", default="soc_dashboard.png")
    args = p.parse_args()
    generate_dashboard(args.input, args.output)
