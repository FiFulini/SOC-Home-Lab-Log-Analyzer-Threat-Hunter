# SOC Home Lab — Log Analyzer & Threat Hunter

Projekt edukacyjny do nauki cyberbezpieczeństwa, zbudowany na bazie Wazuh SIEM.

## Stack technologiczny

- **SIEM**: Wazuh v
- **Język**: Python 3.10+
- **Analiza**: pandas, scikit-learn, matplotlib
- **Dashboard**: Streamlit (Etap 4)
- **Sprzęt**: Raspberry Pi 4/5 8GB RAM (do zakupienia do Etap 2)

---

## Struktura projektu

```
soc-home-lab/
├── README.md
├── requirements.txt
│
├── etap1_log_analyzer/        ← jesteś tutaj
│   ├── parser.py              # wczytuje i parsuje logi Wazuh JSON
│   ├── rules.py               # reguły filtrowania alertów
│   ├── reporter.py            # generuje raport CSV
│   ├── main.py                # punkt wejścia
│   └── sample_logs/
│       └── wazuh_alerts.json  # przykładowe logi do testów
│
├── etap2_wazuh_api/           ← wkrótce
├── etap3_threat_intel/        ← wkrótce
├── etap4_dashboard/           ← wkrótce
├── etap5_soar_lite/           ← wkrótce
└── etap6_ml_anomaly/          ← wkrótce
```

---

## Etap 1 — Analizator logów

### Co robi

Skrypt wczytuje logi Wazuh w formacie JSON (jeden alert na linię),
filtruje według poziomu ryzyka i generuje raport CSV.

### Jak uruchomić

```bash
# Sklonuj repozytorium
git clone https://github.com/FiFulini/SOC-Home-Lab-Log-Analyzer-Threat-Hunter.git
cd SOC-Home-Lab-Log-Analyzer-Threat-Hunter

# Zainstaluj zależności
pip install -r requirements.txt

# Uruchom analizator
cd etap1_log_analyzer
python main.py
```

### Format logów Wazuh (JSON)

Każda linia pliku to jeden alert w formacie:

```json
{
  "timestamp": "2024-01-15T10:23:45.123+0000",
  "rule": {
    "level": 10,
    "id": "5710",
    "description": "Attempt to login using a non-existent user",
    "groups": ["authentication_failed", "syslog"]
  },
  "agent": {
    "id": "001",
    "name": "linux-server-01"
  },
  "data": {
    "srcip": "192.168.1.105"
  }
}
```

# Przykładowy wykres SOC Dashboard (Streamlit)

![SOC Dashboard](etap1_log_analyzer/soc_dashboard.png)

### Opis wykresu

**Lewy górny — timeline alertów.** Każda kropka to jeden alert, kolor i rozmiar to severity. Szczyty skupień na osi czasu to właśnie Twoje zaszyfrowane ataki brute-force — widać je gołym okiem bez czytania logów. Tak właśnie pracuje analityk SOC pierwszej linii: patrzy na timeline i szuka anomalii wizualnie.

**Prawy górny — heatmapa godzinowa.** Pokazuje o której godzinie jest najwięcej alertów wysokiego ryzyka. W prawdziwym środowisku produkcyjnym nocne szczyty (np. 2:00-4:00) są klasycznym sygnałem ataku — bo atakujący zakłada że wtedy nikt nie patrzy. Twój generator zaszywa ataki losowo, więc zobaczysz rozkład przez całą dobę.

**Lewy dolny — top 10 reguł.** Pokazuje które reguły Wazuha wyzwalają się najczęściej. Reguła `5710` (nieistniejący użytkownik SSH) dominuje bo generator produkuje dużo prób z fałszywymi loginami. W praktyce jeśli jakaś reguła jest na szczycie przez tygodnie — albo masz realny problem, albo reguła wymaga tuningu (zbyt czuła).

**Prawy dolny — top IP.** Kandydaci do zablokowania przez `iptables`. Czerwone to IP z listy znanych złych aktorów którą zakodowałem w generatorze (`91.108.4.200` to rzeczywiście znany węzeł Tor/botnet używany w przykładach edukacyjnych). To połączenie z Etapem 5 — tam zamiast tylko wyświetlać IP, skrypt będzie je automatycznie blokował.


### Rozszerzenia do samodzielnego zrobienia

- [ ] Dodaj filtrowanie po zakresie dat (`--from`, `--to`)
- [ ] Dodaj filtrowanie po nazwie agenta (`--agent`)
- [ ] Wykryj brute-force: >5 nieudanych logowań z jednego IP w 60 sekund
- [ ] Wygeneruj wykres słupkowy (matplotlib) z top 10 reguł
- [ ] Dodaj argumenty CLI z biblioteką `argparse`

---

## Wymagania sprzętowe (home lab)

### Opcja A — Raspberry Pi 4/5 (rekomendowane)

```
[Twój PC]                    [Raspberry Pi 4/5 8GB]
Wazuh Agent          →       Wazuh Manager
Python / VS Code             Elasticsearch + Kibana
                             │
                             └── [Dysk USB SSD 500GB]
                                 /mnt/wazuh-logs
```

**Zalety**: cichy, tani w eksploatacji, działa 24/7, nie obciąża PC.

### Opcja B — Maszyna wirtualna (na start / bez kosztu)

```
[Twój PC]
├── Host OS (Windows/Linux)
│   └── Python, VS Code, Wazuh Agent
└── VM (VirtualBox / VMware)
    └── Ubuntu 22.04 + Wazuh Manager + Elasticsearch
```

**Zalety**: zero kosztu, snapshoty, łatwy reset.
**Wady**: obciąża główny PC, logi giną przy usunięciu VM.

### Minimalne wymagania dla Wazuh Manager

| Komponent | Minimum | Rekomendowane |
|-----------|---------|---------------|
| RAM | 4 GB | 8 GB |
| CPU | 2 rdzenie | 4 rdzenie |
| Dysk | 50 GB | 250 GB SSD |
| System | Ubuntu 20.04+ | Ubuntu 22.04 LTS |

---

## Przydatne linki

- [Dokumentacja Wazuh](https://documentation.wazuh.com)
- [Wazuh ruleset — lista reguł](https://github.com/wazuh/wazuh-ruleset)
- [AbuseIPDB API](https://www.abuseipdb.com/api) — darmowy do 1000 req/dzień
- [AlienVault OTX](https://otx.alienvault.com) — darmowe threat feeds

---

## Postęp

- [x] Etap 1 — Analizator logów Python
- [ ] Etap 2 — Integracja Wazuh API
- [ ] Etap 3 — Threat Intelligence Feed
- [ ] Etap 4 — Dashboard Streamlit
- [ ] Etap 5 — Automatyczna odpowiedź (SOAR-lite)
- [ ] Etap 6 — ML Anomaly Detection

---

*Projekt edukacyjny — cybersecurity home lab*
