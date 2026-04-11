# SOC Home Lab — Log Analyzer & Threat Hunter

Projekt edukacyjny do nauki cyberbezpieczeństwa zbudowany na bazie Wazuh SIEM.
Każdy etap to niezależny moduł — razem tworzą mini-platformę SOC-analityczną.

Projekt powstał jako ćwiczenie praktyczne po pracy inżynierskiej z optymalizacji
SIEM (Wazuh). Celem jest przełożenie umiejętności z analizy danych
na realne narzędzia bezpieczeństwa.

---

## Postęp

- [x] **Etap 1** — Analizator logów (parser, brute-force detector, dashboard PNG, CLI)
- [x] **Etap 2** — Integracja z Wazuh API (mock serwer, klient REST, SQLite, poller)
- [ ] **Etap 3** — Threat Intelligence (AbuseIPDB, AlienVault OTX)
- [ ] **Etap 4** — Dashboard webowy (Streamlit)
- [ ] **Etap 5** — Automatyczna odpowiedź na incydenty (SOAR-lite)
- [ ] **Etap 6** — ML Anomaly Detection (Isolation Forest)

---

## Struktura projektu

```
soc-home-lab/
├── README.md
├── requirements.txt
├── TODO.md                        ← sprzęt, zakupy, konfiguracja RPi
├── KOMENDY.txt                    ← wszystkie komendy Etapu 1
├── KOMENDY_ETAP2.txt              ← wszystkie komendy Etapu 2
├── OPIS_PLIKOW.md                 ← szczegółowy opis każdego pliku Etapu 1
├── soc_dashboard.png              ← screenshot dashboardu
├── soc_viewer.html                ← wygenerowany panel filtrów (przykład)
│
├── etap1_log_analyzer/
│   ├── soc.py                     ← główny CLI: generate / analyze / brute / chart / full
│   ├── generate_sample_logs.py    ← generator logów z realistycznymi scenariuszami ataków
│   ├── brute_force_detector.py    ← detekcja brute-force, password spraying, distributed
│   ├── visualizer.py              ← dashboard PNG (4 wykresy matplotlib)
│   ├── viewer_html.py             ← interaktywny panel filtrów w przeglądarce
│   ├── viewer.py                  ← panel filtrów w Streamlit (zalążek Etapu 4)
│   ├── parser.py                  ← wczytywanie i parsowanie logów JSON
│   ├── rules.py                   ← filtrowanie alertów po poziomie i grupie
│   ├── reporter.py                ← eksport wyników do CSV
│   ├── main.py                    ← standalone analiza bez CLI
│   └── sample_logs/               ← dane testowe (nie w git)
│
└── etap2_wazuh_api/
    ├── soc2.py                    ← CLI: poll / status / query / agents
    ├── mock_wazuh_server.py       ← symuluje Wazuh REST API v4.x (testy lokalne)
    ├── wazuh_client.py            ← klient HTTP z auto-refresh tokenu JWT
    ├── alert_store.py             ← lokalna baza SQLite z deduplikacją po ID
    └── poller.py                  ← pętla zbierająca alerty co X sekund
```

---

## Etap 1 — Analizator logów ✓

Parser i analizator logów Wazuh w Pythonie. Wykrywa ataki brute-force trzema
algorytmami korelacji zdarzeń, generuje dashboard wizualny i interaktywny
panel filtrów w przeglądarce. Działa w całości lokalnie — nie potrzeba serwera.

![SOC Dashboard](etap1_log_analyzer/soc_dashboard.png)

### Wymagania

```bash
pip install -r requirements.txt   # pandas, matplotlib, python-dateutil
```

Python 3.10+. Brak niestandardowych zależności — działa na każdym PC, VM i RPi.

### Szybki start

```bash
cd etap1_log_analyzer

# 1. Wygeneruj testowe logi (1000 alertów, ostatnie 7 dni)
python soc.py generate

# 2. Analiza ogólna — statystyki, top reguły, top IP
python soc.py analyze

# 3. Wykryj ataki brute-force, password spraying i distributed attacks
python soc.py brute

# 4. Wygeneruj dashboard PNG (4 wykresy)
python soc.py chart

# 5. Wszystko naraz z eksportem CSV
python soc.py full --csv
```

Pełna lista komend: [KOMENDY.txt](etap1_log_analyzer/KOMENDY.txt)
Opis każdego pliku: [OPIS_PLIKOW.md](etap1_log_analyzer/OPIS_PLIKOW.md)

### Filtry dat

Wszystkie komendy obsługują filtry czasowe:

```bash
python soc.py analyze --hours 24
python soc.py analyze --from 2024-06-01 --to 2024-06-07
python soc.py generate --from "2024-06-01 08:00" --to "2024-06-01 20:00"
```

### Przykładowy wynik `soc.py analyze`

```
────────────────────────────────────────────────────────────────────────
 ANALIZA LOGÓW  |  plik: sample_logs/wazuh_alerts.json
 Wczytano: 1000 alertów  |  poziom ≥7: 214
────────────────────────────────────────────────────────────────────────

 Top reguły (poziom ≥7):

  ███████████████   87x  [5710] sshd: Attempt to login non-existent user
  ██████████   53x  [5760] sshd: Multiple authentication failures
  ████████    42x  [31151] Web server directory traversal attempt

 Top atakujące IP:

  ██████████████   116x  91.108.4.200

[!!!] KRYTYCZNY | 2024-06-03 02:14 | Brute-force SSH
      agent=linux-server-01  ip=91.108.4.200  prób=34  ← UDANE LOGOWANIE!
```

### Algorytmy detekcji

Trzy algorytmy oparte na sliding window — tym samym mechanizmie który stosuje
Splunk, Elastic SIEM i reguły Sigma:

- **Brute-force** — okno 60s, ≥5 nieudanych prób z jednego IP na jeden host.
  Automatycznie wykrywa udane logowanie po ataku i eskaluje severity do KRYTYCZNY.
- **Password spraying** — okno 300s, jeden IP próbuje ≥3 różnych użytkowników.
  Wykrywa powolne ataki omijające blokady kont których klasyczny licznik nie złapie.
- **Distributed attack** — okno 300s, ≥3 różne IP atakują tego samego użytkownika.
  Wykrywa skoordynowane ataki botnetowe gdzie każde IP wygląda niewinnie z osobna.

### Generator logów z FIM (syscheck)

Generator produkuje cztery realistyczne scenariusze ataków, w tym alerty
File Integrity Monitor z pełnym polem `syscheck`:

```json
{
  "syscheck": {
    "path": "/tmp/backdoor.sh",
    "event": "added",
    "size_after": "2048",
    "perm_after": "rwxrwxrwx",
    "uname_after": "root",
    "md5_after": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1_after": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256_after": "e3b0c44298fc1c149afbf4c8996fb924..."
  }
}
```

Dla zmodyfikowanych plików generator dołącza diff (MD5/SHA1/SHA256 przed i po,
rozmiar przed i po, uprawnienia przed i po, timestamp modyfikacji).
Identyczna struktura jak prawdziwy Wazuh FIM — kod działa bez zmian po
podłączeniu RPi.

### Powiązania MITRE ATT&CK

| Scenariusz | Technika |
|---|---|
| Brute-force SSH | T1110.001 — Password Guessing |
| Password spraying | T1110.003 — Password Spraying |
| Web scan / SQLi | T1595 — Active Scanning |
| Privilege escalation sudo | T1548.003 — Sudo Caching |
| File integrity violation | T1565 — Data Manipulation |

### Dashboard

Cztery wykresy w jednym pliku PNG:

| Wykres | Co pokazuje |
|---|---|
| Timeline alertów | Każdy alert jako kropka na osi czasu — skupienia = ataki |
| Heatmapa godzinowa | O której godzinie jest szczyt ataków |
| Top 10 reguł | Które reguły Wazuha wyzwalają się najczęściej |
| Top atakujące IP | Kandydaci do blokady przez iptables |

---

## Viewer — interaktywny panel filtrów

Dwa sposoby przeglądania dużych zbiorów alertów w przeglądarce.
Oba obsługują Etap 1 (pliki JSON) i Etap 2 (baza SQLite).

### `viewer_html.py` — zero zależności (zalecane)

Generuje jeden plik `.html` który otwierasz w przeglądarce. Filtrowanie
i paginacja działają w JavaScript — nie potrzeba serwera, działa offline.

```bash
# Z pliku JSON (Etap 1)
python viewer_html.py --input sample_logs/wazuh_alerts.json --open

# Z bazy SQLite (Etap 2)
python viewer_html.py --db etap2_wazuh_api/alerts.db --open

# Zapisz raport HTML do przekazania dalej
python viewer_html.py --db alerts.db --output raport_tygodniowy.html
```

Funkcje panelu:

| Funkcja | Opis |
|---|---|
| Suwak poziomu (1–15) | Filtruj po severity Wazuha |
| Zakres dat | Od / Do z date pickerem |
| IP atakującego | Multiselect — Ctrl żeby zaznaczyć wiele |
| Agent / host | Multiselect po nazwie hosta |
| ID reguły | Multiselect po numerze reguły Wazuha |
| Szukaj w opisie | Filtr tekstowy (brute, injection, sudo, /tmp...) |
| Tylko FIM | Checkbox — tylko alerty z polem syscheck |
| Paginacja | 20 / 50 / 100 / 500 alertów na stronę |
| Sortowanie | Kliknij nagłówek kolumny — ↕ zmienia kierunek |
| Panel szczegółów | Kliknij wiersz → pełne dane alertu z boku ekranu |
| Eksport CSV | Pobiera tylko przefiltrowane wiersze |

**Panel szczegółów alertu** — kliknięcie w dowolny wiersz wysuwa panel
z prawej strony z pełnymi informacjami. Dla alertów FIM pokazuje:

- dla `event: modified` — diff pliku (rozmiar przed/po, MD5 przed/po,
  uprawnienia przed/po, właściciel przed/po, timestamp modyfikacji)
- dla `event: added` — rozmiar, uprawnienia, właściciel, checksums (MD5,
  SHA1, SHA256), numer inode
- dla wszystkich alertów — surowy JSON na dole panelu

### `viewer.py` — Streamlit (zalążek Etapu 4)

Wersja z auto-odświeżaniem co 15 sekund — przydatna gdy poller zbiera
alerty na żywo.

```bash
pip install streamlit pandas
streamlit run viewer.py
# → otwiera http://localhost:8501 automatycznie
```

Dodatkowe funkcje: zakładka Statystyki z interaktywnymi wykresami
(top reguły, top IP, rozkład poziomów, top agenci), zakładka Timeline
z liczbą alertów per godzina i aktywność wg godziny doby.

---

## Etap 2 — Wazuh API + SQLite ✓

Klient REST API dla Wazuh Managera z lokalną bazą SQLite i automatycznym
pollerem. Testowany w całości lokalnie — mock serwer symuluje pełne API
Wazuha v4.x bez fizycznego serwera.

### Szybki start (dwa terminale)

**Terminal 1 — mock serwer:**

```bash
cd etap2_wazuh_api
python mock_wazuh_server.py
```

**Terminal 2 — zbieranie i analiza:**

```bash
# Zbieraj alerty co 5 sekund
python soc2.py poll

# Tylko alerty wysokiego ryzyka, co 10 sekund
python soc2.py poll --level 7 --interval 10

# Status bazy i API
python soc2.py status

# Przeszukaj zebrane dane
python soc2.py query --level 10
python soc2.py query --ip 91.108.4.200 --format summary
python soc2.py query --agent linux-server-01

# Lista agentów
python soc2.py agents
```

Pełna lista komend: [KOMENDY_ETAP2.txt](etap2_wazuh_api/KOMENDY_ETAP2.txt)

### Połączenie Etapu 1 i 2

Dane zebrane przez poller można analizować narzędziami z Etapu 1:

```bash
python soc2.py query --level 0 --format json --limit 9999 > zebrane.json
cd ../etap1_log_analyzer
python soc.py analyze --input ../etap2_wazuh_api/zebrane.json
python soc.py brute   --input ../etap2_wazuh_api/zebrane.json
python soc.py chart   --input ../etap2_wazuh_api/zebrane.json
```

### Przejście na prawdziwy Wazuh

Gdy masz serwer z Wazuhem — jedna zmiana w komendzie:

```bash
# Mock (testowanie lokalne)
python soc2.py poll --host 127.0.0.1

# Prawdziwy Wazuh Manager (RPi lub VM)
python soc2.py poll --host 192.168.1.50 --password TWOJE_HASLO
python soc2.py agents --host 192.168.1.50
python soc2.py status --host 192.168.1.50
```

Cały kod — klient, baza, poller, CLI — zostaje bez zmian.

### Architektura

```
[Mock serwer / RPi z Wazuhem]
        │  REST API (JWT)
        ▼
  wazuh_client.py     ← autentykacja, GET /alerts, GET /agents
        │
        ▼
  alert_store.py      ← SQLite, INSERT OR IGNORE (deduplikacja po ID)
        │
        ▼
  soc2.py query       ← filtrowanie po dacie, IP, agencie, poziomie
        │
        ▼
  soc.py / viewer     ← analiza i wizualizacja z Etapu 1
```

---

## Wymagania

```
pandas>=2.0.0
matplotlib>=3.8.0
python-dateutil>=2.8.2
requests>=2.31.0        # przygotowane pod Etap 3

# Etap 2 nie wymaga dodatkowych bibliotek
# (używa tylko stdlib: urllib, sqlite3, json, http.server)
```

```bash
pip install -r requirements.txt
```

---

## Stack technologiczny

| Warstwa | Technologia |
|---|---|
| SIEM | Wazuh v4.x |
| Język | Python 3.10+ |
| Analiza | pandas, matplotlib |
| Baza danych | SQLite (wbudowana w Python) |
| Detekcja | sliding window (własna implementacja) |
| API client | urllib (stdlib, bez dodatkowych zależności) |
| Viewer | HTML + JavaScript / Streamlit |
| Sprzęt (Etap 2+) | Raspberry Pi 5 8GB + Ubuntu 22.04 |

---

## Przydatne linki

- [Dokumentacja Wazuh](https://documentation.wazuh.com)
- [Wazuh ruleset — lista reguł](https://github.com/wazuh/wazuh-ruleset)
- [MITRE ATT&CK](https://attack.mitre.org)
- [AbuseIPDB API](https://www.abuseipdb.com/api) — darmowy do 1000 req/dzień
- [AlienVault OTX](https://otx.alienvault.com) — darmowe threat feeds

---

*Projekt edukacyjny — cybersecurity home lab*
