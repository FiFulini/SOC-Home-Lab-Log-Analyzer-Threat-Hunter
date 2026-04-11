"""
Wazuh API Client — klient REST API dla Wazuh Manager v4.x
Działa identycznie z mock serwerem i prawdziwym Wazuhem na RPi.
Żeby przejść na prawdziwe środowisko zmień tylko HOST, USER i PASSWORD.
"""

import json
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger("wazuh_client")


# ──────────────────────────────────────────────
# Konfiguracja połączenia
# ──────────────────────────────────────────────

@dataclass
class WazuhConfig:
    host:     str   = "127.0.0.1"   # ← zmień na IP RPi gdy będziesz gotowy
    port:     int   = 55000
    user:     str   = "wazuh"
    password: str   = "wazuh"
    verify_ssl: bool = False         # True na produkcji z certyfikatem
    timeout:  int   = 10            # sekundy

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
        # Na prawdziwym Wazuhu z SSL: f"https://{self.host}:{self.port}"


# ──────────────────────────────────────────────
# Klient
# ──────────────────────────────────────────────

class WazuhClient:
    def __init__(self, config: WazuhConfig):
        self.cfg   = config
        self._token: Optional[str] = None
        self._token_ts: float      = 0
        self._token_ttl: int       = 900   # token ważny 15 minut

    # ── Autentykacja ─────────────────────────

    def _is_token_valid(self) -> bool:
        return (
            self._token is not None and
            time.time() - self._token_ts < self._token_ttl
        )

    def authenticate(self) -> str:
        """Pobiera token JWT. Automatycznie odświeża gdy wygaśnie."""
        if self._is_token_valid():
            return self._token

        url  = f"{self.cfg.base_url}/security/user/authenticate"
        body = json.dumps({"user": self.cfg.user, "password": self.cfg.password}).encode()
        req  = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                data = json.loads(resp.read())
            self._token    = data["data"]["token"]
            self._token_ts = time.time()
            logger.info("Autentykacja OK — token ważny %ds", self._token_ttl)
            return self._token
        except urllib.error.HTTPError as e:
            raise ConnectionError(f"Błąd autentykacji HTTP {e.code}: {e.read().decode()}") from e
        except Exception as e:
            raise ConnectionError(f"Nie można połączyć z {self.cfg.base_url}: {e}") from e

    # ── Bazowe zapytanie GET ──────────────────

    def _get(self, endpoint: str, params: dict = None) -> dict:
        token = self.authenticate()
        url   = f"{self.cfg.base_url}{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})

        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            # Token mógł wygasnąć — wymuś re-autentykację
            if e.code == 401:
                self._token = None
                raise ConnectionError("Token wygasł — spróbuj ponownie") from e
            raise ConnectionError(f"HTTP {e.code}: {body}") from e

    # ── Publiczne metody API ──────────────────

    def get_manager_info(self) -> dict:
        """Wersja i status Wazuh Managera."""
        return self._get("/manager/info")["data"]

    def get_manager_status(self) -> dict:
        """Status poszczególnych usług Wazuha."""
        return self._get("/manager/status")["data"]

    def get_agents(self, status: str = None) -> list[dict]:
        """
        Lista agentów.
        status: 'active' | 'disconnected' | 'pending' | None (wszyscy)
        """
        data = self._get("/agents", {"status": status})
        return data["data"]["affected_items"]

    def get_alerts(
        self,
        limit:     int = 100,
        offset:    int = 0,
        min_level: int = 0,
    ) -> list[dict]:
        """
        Pobiera alerty z Wazuh API.
        limit:     ile alertów na raz (max 500 w prawdziwym Wazuhu)
        offset:    paginacja
        min_level: filtruj alerty poniżej tego poziomu
        """
        data = self._get("/alerts", {
            "limit":  limit,
            "offset": offset,
            "level":  min_level if min_level > 0 else None,
        })
        return data["data"]["affected_items"]

    def get_all_alerts(self, min_level: int = 0, page_size: int = 100) -> list[dict]:
        """
        Pobiera wszystkie alerty stronicując automatycznie.
        Na prawdziwym Wazuhu z dużą liczbą alertów używaj min_level
        żeby nie pobierać tysięcy rekordów naraz.
        """
        all_alerts = []
        offset     = 0
        while True:
            page = self.get_alerts(limit=page_size, offset=offset, min_level=min_level)
            if not page:
                break
            all_alerts += page
            offset     += len(page)
            if len(page) < page_size:
                break
        return all_alerts

    def ping(self) -> bool:
        """Sprawdza czy API jest dostępne."""
        try:
            self.get_manager_info()
            return True
        except Exception:
            return False
