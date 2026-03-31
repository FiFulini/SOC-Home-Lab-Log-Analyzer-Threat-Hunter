"""
Brute-Force Detector — korelacja zdarzeń SSH w czasie
Wykrywa: klasyczny brute-force, password spraying, distributed attack
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


# ──────────────────────────────────────────────
# Konfiguracja progów detekcji
# ──────────────────────────────────────────────

CONFIG = {
    # Klasyczny brute-force: jeden IP atakuje jeden cel
    "brute_force": {
        "window_seconds": 60,   # okno czasowe analizy
        "min_failures":   5,    # ile nieudanych prób = alarm
    },
    # Password spraying: jeden IP próbuje wielu userów
    "spraying": {
        "window_seconds": 300,  # szersze okno (wolniejszy atak)
        "min_users":      3,    # ile różnych userów z jednego IP
    },
    # Distributed: wiele IP atakuje tego samego usera
    "distributed": {
        "window_seconds": 300,
        "min_ips":        3,    # ile różnych IP na jednego usera
    },
    # Reguły Wazuh które liczymy jako "nieudane logowanie"
    "failure_rule_ids": {"5710", "5760", "5503", "31151"},
    # Reguły udanego logowania (sukces po failach = przejęcie konta!)
    "success_rule_ids": {"5715", "5718", "5301"},
}


# ──────────────────────────────────────────────
# Struktury danych
# ──────────────────────────────────────────────

class LoginEvent:
    """Pojedyncze zdarzenie logowania z logu Wazuh."""
    def __init__(self, alert: dict):
        self.timestamp = datetime.strptime(
            alert["timestamp"][:23], "%Y-%m-%dT%H:%M:%S.%f"
        )
        self.rule_id   = alert["rule"]["id"]
        self.level     = alert["rule"]["level"]
        self.agent     = alert["agent"]["name"]
        self.srcip     = alert.get("data", {}).get("srcip", "unknown")
        self.user      = alert.get("data", {}).get("dstuser", "unknown")
        self.is_fail   = self.rule_id in CONFIG["failure_rule_ids"]
        self.is_ok     = self.rule_id in CONFIG["success_rule_ids"]


class BruteForceAlert:
    """Wykryty incydent."""
    def __init__(self, kind: str, severity: str, agent: str,
                 srcip: str, user: str, count: int,
                 window_start: datetime, window_end: datetime,
                 success_after: bool = False):
        self.kind          = kind
        self.severity      = severity
        self.agent         = agent
        self.srcip         = srcip
        self.user          = user
        self.count         = count
        self.window_start  = window_start
        self.window_end    = window_end
        self.success_after = success_after

    @property
    def duration_sec(self):
        return int((self.window_end - self.window_start).total_seconds())

    def __str__(self):
        icon = {"KRYTYCZNY": "[!!!]", "WYSOKI": "[!! ]", "SREDNI": "[ ! ]"}[self.severity]
        ts   = self.window_start.strftime("%Y-%m-%d %H:%M:%S")
        base = (f"{icon} {self.severity:<9} | {ts} | {self.kind:<22} | "
                f"agent={self.agent:<22} ip={self.srcip:<18} "
                f"user={self.user:<12} prób={self.count} czas={self.duration_sec}s")
        if self.success_after:
            base += " ← UDANE LOGOWANIE PO ATAKU!"
        return base


# ──────────────────────────────────────────────
# Silnik detekcji
# ──────────────────────────────────────────────

class BruteForceDetector:
    def __init__(self, config: dict = CONFIG):
        self.cfg    = config
        self.alerts = []

    # ── Wczytywanie ──────────────────────────

    def load_events(self, filepath: str) -> list[LoginEvent]:
        events = []
        path   = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Plik nie istnieje: {filepath}")

        with open(filepath) as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    ev    = LoginEvent(alert)
                    if ev.is_fail or ev.is_ok:
                        events.append(ev)
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass  # pomiń uszkodzone linie

        events.sort(key=lambda e: e.timestamp)
        return events

    # ── Algorytm okna czasowego ─────────────

    def _sliding_window(self, events: list, window_sec: int,
                        key_fn) -> dict:
        """
        Grupuje zdarzenia w okna czasowe metodą sliding window.
        key_fn(event) → klucz grupowania (np. (ip, agent) dla brute-force)
        Zwraca: {klucz: [lista_zdarzeń_w_najgęstszym_oknie]}
        """
        by_key = defaultdict(list)
        for ev in events:
            by_key[key_fn(ev)].append(ev)

        result = {}
        window = timedelta(seconds=window_sec)

        for key, evs in by_key.items():
            best_window = []
            for i, ev in enumerate(evs):
                # zbierz wszystkie zdarzenia w oknie [ev.ts, ev.ts + window]
                in_window = [e for e in evs[i:]
                             if e.timestamp - ev.timestamp <= window]
                if len(in_window) > len(best_window):
                    best_window = in_window
            if best_window:
                result[key] = best_window

        return result

    # ── Sprawdzenie: czy po ataku nastąpił sukces ──

    def _success_followed(self, all_events: list[LoginEvent],
                          srcip: str, agent: str,
                          after: datetime, within_sec: int = 120) -> bool:
        cutoff = after + timedelta(seconds=within_sec)
        return any(
            e.is_ok and e.srcip == srcip
            and e.agent == agent
            and after <= e.timestamp <= cutoff
            for e in all_events
        )

    # ── Detekcja 1: klasyczny brute-force ───

    def detect_brute_force(self, events: list[LoginEvent]) -> list[BruteForceAlert]:
        fails  = [e for e in events if e.is_fail]
        cfg    = self.cfg["brute_force"]
        result = []
        seen   = set()

        windows = self._sliding_window(
            fails, cfg["window_seconds"],
            key_fn=lambda e: (e.srcip, e.agent)
        )

        for (ip, agent), evs in windows.items():
            if len(evs) < cfg["min_failures"]:
                continue
            key = (ip, agent, evs[0].timestamp.replace(second=0, microsecond=0))
            if key in seen:
                continue
            seen.add(key)

            rate     = len(evs) / max((evs[-1].timestamp - evs[0].timestamp).total_seconds(), 1)
            severity = "KRYTYCZNY" if (len(evs) >= 20 or rate > 2) else "WYSOKI"
            success  = self._success_followed(events, ip, agent, evs[-1].timestamp)

            result.append(BruteForceAlert(
                kind="Brute-force SSH",
                severity="KRYTYCZNY" if success else severity,
                agent=agent, srcip=ip,
                user=evs[-1].user,
                count=len(evs),
                window_start=evs[0].timestamp,
                window_end=evs[-1].timestamp,
                success_after=success,
            ))

        return result

    # ── Detekcja 2: password spraying ───────

    def detect_spraying(self, events: list[LoginEvent]) -> list[BruteForceAlert]:
        fails  = [e for e in events if e.is_fail]
        cfg    = self.cfg["spraying"]
        result = []
        seen   = set()

        windows = self._sliding_window(
            fails, cfg["window_seconds"],
            key_fn=lambda e: (e.srcip, e.agent)
        )

        for (ip, agent), evs in windows.items():
            unique_users = {e.user for e in evs}
            if len(unique_users) < cfg["min_users"]:
                continue
            key = (ip, agent, evs[0].timestamp.replace(minute=0, second=0, microsecond=0))
            if key in seen:
                continue
            seen.add(key)

            result.append(BruteForceAlert(
                kind="Password spraying",
                severity="WYSOKI",
                agent=agent, srcip=ip,
                user=f"{len(unique_users)} userów",
                count=len(evs),
                window_start=evs[0].timestamp,
                window_end=evs[-1].timestamp,
            ))

        return result

    # ── Detekcja 3: distributed attack ──────

    def detect_distributed(self, events: list[LoginEvent]) -> list[BruteForceAlert]:
        fails  = [e for e in events if e.is_fail]
        cfg    = self.cfg["distributed"]
        result = []
        seen   = set()

        windows = self._sliding_window(
            fails, cfg["window_seconds"],
            key_fn=lambda e: (e.user, e.agent)
        )

        for (user, agent), evs in windows.items():
            if user == "unknown":
                continue
            unique_ips = {e.srcip for e in evs}
            if len(unique_ips) < cfg["min_ips"]:
                continue
            key = (user, agent, evs[0].timestamp.replace(minute=0, second=0, microsecond=0))
            if key in seen:
                continue
            seen.add(key)

            result.append(BruteForceAlert(
                kind="Distributed attack",
                severity="KRYTYCZNY",
                agent=agent, srcip=f"{len(unique_ips)} IP",
                user=user,
                count=len(evs),
                window_start=evs[0].timestamp,
                window_end=evs[-1].timestamp,
            ))

        return result

    # ── Uruchom wszystkie detektory ──────────

    def analyze(self, filepath: str) -> list[BruteForceAlert]:
        print(f"Ładowanie zdarzeń z: {filepath}")
        events = self.load_events(filepath)
        fails  = [e for e in events if e.is_fail]
        print(f"Wczytano {len(events)} zdarzeń logowania "
              f"({len(fails)} nieudanych, {len(events)-len(fails)} udanych)\n")

        all_alerts = []
        all_alerts += self.detect_brute_force(events)
        all_alerts += self.detect_spraying(events)
        all_alerts += self.detect_distributed(events)

        all_alerts.sort(key=lambda a: a.window_start)
        self.alerts = all_alerts
        return all_alerts


# ──────────────────────────────────────────────
# Raport
# ──────────────────────────────────────────────

def print_report(alerts: list[BruteForceAlert]) -> None:
    SEP = "─" * 110

    print(SEP)
    print(f" RAPORT DETEKCJI BRUTE-FORCE  |  wykrytych incydentów: {len(alerts)}")
    print(SEP)

    if not alerts:
        print(" Brak wykrytych incydentów.")
        return

    # Pogrupuj wg severity
    for sev in ["KRYTYCZNY", "WYSOKI", "SREDNI"]:
        group = [a for a in alerts if a.severity == sev]
        if not group:
            continue
        print(f"\n{'[!!!]' if sev=='KRYTYCZNY' else '[!! ]'} {sev} ({len(group)} incydentów)\n")
        for a in group:
            print(f"  {a}")

    # Statystyki
    print(f"\n{SEP}")
    print(" STATYSTYKI\n")

    top_ips = defaultdict(int)
    for a in alerts:
        if "IP" not in a.srcip:
            top_ips[a.srcip] += a.count
    if top_ips:
        print(f"  Top atakujące IP:")
        for ip, cnt in sorted(top_ips.items(), key=lambda x: -x[1])[:5]:
            bar = "█" * min(cnt // 3, 30)
            print(f"    {ip:<20} {bar} ({cnt} prób)")

    top_agents = defaultdict(int)
    for a in alerts:
        top_agents[a.agent] += a.count
    if top_agents:
        print(f"\n  Najczęściej atakowane hosty:")
        for agent, cnt in sorted(top_agents.items(), key=lambda x: -x[1])[:5]:
            print(f"    {agent:<25} {cnt} prób")

    compromised = [a for a in alerts if a.success_after]
    if compromised:
        print(f"\n  UWAGA — potencjalnie przejęte konta ({len(compromised)}):")
        for a in compromised:
            print(f"    host={a.agent}  ip={a.srcip}  user={a.user}  "
                  f"o {a.window_end.strftime('%H:%M:%S')}")

    print(f"\n{SEP}")


def save_report_csv(alerts: list[BruteForceAlert], output: str = "raport_brute_force.csv") -> None:
    import csv
    fields = ["timestamp", "kind", "severity", "agent",
              "srcip", "user", "attempts", "duration_sec", "compromised"]
    with open(output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in alerts:
            w.writerow({
                "timestamp":    a.window_start.strftime("%Y-%m-%d %H:%M:%S"),
                "kind":         a.kind,
                "severity":     a.severity,
                "agent":        a.agent,
                "srcip":        a.srcip,
                "user":         a.user,
                "attempts":     a.count,
                "duration_sec": a.duration_sec,
                "compromised":  "TAK" if a.success_after else "NIE",
            })
    print(f"\nRaport CSV zapisany: {output}")


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Detektor brute-force w logach Wazuh")
    parser.add_argument("--input",    default="sample_logs/wazuh_alerts.json")
    parser.add_argument("--csv",      action="store_true", help="Zapisz raport CSV")
    parser.add_argument("--window",   type=int, default=60,  help="Okno czasowe w sekundach")
    parser.add_argument("--min-fail", type=int, default=5,   help="Min. nieudanych prób")
    args = parser.parse_args()

    CONFIG["brute_force"]["window_seconds"] = args.window
    CONFIG["brute_force"]["min_failures"]   = args.min_fail

    detector = BruteForceDetector()
    alerts   = detector.analyze(args.input)
    print_report(alerts)

    if args.csv:
        save_report_csv(alerts)
