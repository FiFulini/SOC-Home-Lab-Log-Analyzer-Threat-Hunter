"""
Poller — odpytuje Wazuh API co X minut i zapisuje nowe alerty do SQLite
To jest serce Etapu 2: automatyczny kolektor działający w tle

Uruchom: python poller.py
         python poller.py --interval 2 --level 5
"""

import logging
import signal
import sys
import time
import argparse
from datetime import datetime

from wazuh_client import WazuhClient, WazuhConfig
from alert_store  import AlertStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("poller")


# ──────────────────────────────────────────────
# Poller
# ──────────────────────────────────────────────

class Poller:
    def __init__(
        self,
        client:   WazuhClient,
        store:    AlertStore,
        interval: int = 5,        # sekundy między odpytaniami
        min_level: int = 0,       # pobieraj alerty od tego poziomu
        batch_size: int = 100,    # ile alertów na jedno zapytanie
    ):
        self.client     = client
        self.store      = store
        self.interval   = interval
        self.min_level  = min_level
        self.batch_size = batch_size
        self._running   = False
        self._cycle     = 0

        # Statystyki sesji
        self._session_new = 0
        self._session_dup = 0
        self._session_err = 0

    def _poll_once(self) -> tuple[int, int]:
        """Jeden cykl odpytywania. Zwraca (nowe, zduplikowane)."""
        alerts          = self.client.get_alerts(
            limit=self.batch_size,
            min_level=self.min_level,
        )
        new_count, dup = self.store.save_alerts(alerts)
        return new_count, dup

    def _print_status(self, new: int, dup: int):
        total = self.store.count()
        ts    = datetime.now().strftime("%H:%M:%S")
        bar   = "█" * min(new, 30)
        print(
            f"  [{ts}] cykl={self._cycle:>4}  "
            f"nowe={new:>3}  {bar:30s}  "
            f"dup={dup:>3}  baza={total:>6}  "
            f"błędy_sesji={self._session_err}"
        )

    def _print_summary(self):
        stats = self.store.get_stats()
        SEP   = "─" * 60
        print(f"\n{SEP}")
        print(f" PODSUMOWANIE SESJI")
        print(f"{SEP}")
        print(f"  Cykli:         {self._cycle}")
        print(f"  Nowych alertów: {self._session_new}")
        print(f"  Duplikatów:    {self._session_dup}")
        print(f"  Błędów:        {self._session_err}")
        print(f"  Razem w bazie: {stats.get('total', 0)}")

        if stats.get("top_ips"):
            print(f"\n  Top IP (poziom ≥7):")
            for ip, cnt in stats["top_ips"].items():
                print(f"    {ip:<20} {cnt}x")
        print(f"{SEP}\n")

    def run(self):
        """Pętla główna — odpytuje API co self.interval sekund."""
        self._running = True

        # Podłącz i sprawdź połączenie
        logger.info("Łączenie z Wazuh API...")
        try:
            info = self.client.get_manager_info()
            logger.info("Połączono z Wazuh %s (%s)", info["version"], info["hostname"])
        except Exception as e:
            logger.error("Nie można połączyć: %s", e)
            logger.error("Upewnij się że mock serwer działa: python mock_wazuh_server.py")
            return

        status = self.client.get_manager_status()
        for svc, state in status.items():
            icon = "✓" if state == "running" else "✗"
            logger.info("  %s %s: %s", icon, svc, state)

        agents = self.client.get_agents(status="active")
        logger.info("Aktywnych agentów: %d", len(agents))
        for a in agents:
            logger.info("  [%s] %s (%s)", a["id"], a["name"], a["ip"])

        print(f"\n  Odpytuję co {self.interval}s | min_level={self.min_level} | Ctrl+C aby zatrzymać\n")
        print(f"  {'Czas':^10}  {'Cykl':^6}  {'Nowe':^5}  {'Pasek aktywności':^30}  {'Dup':^4}  {'Baza':^7}")
        print(f"  {'─'*10}  {'─'*6}  {'─'*5}  {'─'*30}  {'─'*4}  {'─'*7}")

        while self._running:
            self._cycle += 1
            try:
                new, dup             = self._poll_once()
                self._session_new   += new
                self._session_dup   += dup
                self._print_status(new, dup)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self._session_err += 1
                logger.warning("Błąd cyklu %d: %s", self._cycle, e)

            # Czekaj interval sekund (z możliwością przerwania)
            try:
                time.sleep(self.interval)
            except KeyboardInterrupt:
                break

        self._print_summary()

    def stop(self):
        self._running = False


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Poller — automatyczne pobieranie alertów z Wazuh API",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  python poller.py                          # domyślne ustawienia
  python poller.py --interval 2            # odpytuj co 2 sekundy
  python poller.py --level 7 --interval 10 # tylko alerty ≥7, co 10s
  python poller.py --host 192.168.1.50     # prawdziwy Wazuh na RPi
        """
    )
    parser.add_argument("--host",     default="127.0.0.1",
                        help="Host Wazuh API (domyślnie: 127.0.0.1)")
    parser.add_argument("--port",     type=int, default=55000)
    parser.add_argument("--user",     default="wazuh")
    parser.add_argument("--password", default="wazuh")
    parser.add_argument("--interval", type=int, default=5,
                        help="Sekundy między odpytaniami (domyślnie: 5)")
    parser.add_argument("--level",    type=int, default=0,
                        help="Minimalny poziom alertu (domyślnie: 0 = wszystkie)")
    parser.add_argument("--db",       default="alerts.db",
                        help="Plik bazy SQLite (domyślnie: alerts.db)")
    parser.add_argument("--batch",    type=int, default=100,
                        help="Ile alertów pobierać na raz (domyślnie: 100)")
    args = parser.parse_args()

    config = WazuhConfig(
        host=args.host, port=args.port,
        user=args.user, password=args.password,
    )
    client = WazuhClient(config)
    store  = AlertStore(db_path=args.db)
    poller = Poller(
        client=client, store=store,
        interval=args.interval,
        min_level=args.level,
        batch_size=args.batch,
    )

    # Graceful shutdown na Ctrl+C
    def handle_signal(sig, frame):
        print("\nZatrzymuję...")
        poller.stop()

    signal.signal(signal.SIGINT, handle_signal)
    poller.run()


if __name__ == "__main__":
    main()
