# TODO — SOC Home Lab

Lista rzeczy do zrobienia, zakupu i skonfigurowania.
Rzeczy czysto projektowe (kod, dokumentacja) trafiają do Issues na GitHubie —
tu są tylko sprawy sprzętowe, konfiguracyjne i zakupowe.

---

## Sprzęt do kupienia

### Raspberry Pi 5 — zestaw docelowy

| Co | Model | Gdzie | Cena (IV 2026) |
|---|---|---|---|
| RPi 5 8GB | Raspberry Pi 5 8GB SC1112 | Botland / Morele | ~547 zł |
| Obudowa z NVMe | Argon NEO 5 M.2 NVMe PCIe | Botland / Allegro | ~161 zł |
| Zasilacz | oficjalny RPi 27W USB-C 5V/5A | Allegro / msalamon | ~55 zł |
| microSD (system) | SanDisk High Endurance 64GB V30 | x-kom / Allegro | ~66 zł |
| Dysk USB (logi) | Samsung T7 500GB USB 3.2 | Ceneo | ~339 zł |
| **Razem** | | | **~1168 zł** |

> Obudowę Argon NEO 5 M.2 wybrano nad Argon ONE V3 dlatego że ma slot NVMe
> w cenie ~161 zł. ONE V3 bez NVMe kosztuje podobnie, ale żeby dodać NVMe
> trzeba dokupić płytkę rozszerzeń za ~87 zł — łącznie ~242 zł za mniej funkcji.

### W przyszłości (opcjonalnie)

- [ ] Dysk M.2 NVMe (zastąpi Samsung T7 na USB) — ~200–400 zł za 500GB
  - Format M-Key do 2280 (obsługiwany przez Argon NEO 5)
  - Przykład: WD Black SN770 500GB lub Samsung 980
- [ ] Drugi agent — stary laptop lub VM jako dodatkowy monitorowany host

---

## Konfiguracja po zakupie RPi

### Krok 1 — system operacyjny

- [ ] Nagrać Ubuntu 22.04 LTS na microSD przez Raspberry Pi Imager
- [ ] Pierwsze uruchomienie — SSH, aktualizacja systemu
- [ ] Zmienić domyślne hasło

```bash
sudo apt update && sudo apt upgrade -y
```

### Krok 2 — dysk USB na logi

- [ ] Podłączyć Samsung T7 przez USB 3.0
- [ ] Sformatować i zamontować

```bash
sudo mkfs.ext4 /dev/sdb1
sudo mkdir -p /mnt/wazuh-logs
sudo mount /dev/sdb1 /mnt/wazuh-logs
echo '/dev/sdb1 /mnt/wazuh-logs ext4 defaults 0 2' | sudo tee -a /etc/fstab
```

### Krok 3 — Wazuh Manager

- [ ] Zainstalować Wazuh Manager v4.x

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

- [ ] Przekierować logi Wazuh na dysk USB

```bash
sudo systemctl stop wazuh-manager
sudo mv /var/ossec/logs /mnt/wazuh-logs/ossec-logs
sudo ln -s /mnt/wazuh-logs/ossec-logs /var/ossec/logs
sudo systemctl start wazuh-manager
```

- [ ] Zmienić domyślne hasło Wazuh API (domyślne: wazuh/wazuh)
- [ ] Zanotować IP RPi (`hostname -I`)

### Krok 4 — Wazuh Agent na głównym PC

- [ ] Zainstalować agenta na swoim komputerze

```bash
# Ubuntu/Debian:
curl -sO https://packages.wazuh.com/4.7/wazuh-agent.deb
sudo WAZUH_MANAGER='192.168.1.50' dpkg -i wazuh-agent.deb
sudo systemctl enable --now wazuh-agent

# Windows — pobrać instalator ze strony wazuh.com
```

- [ ] Sprawdzić że agent widoczny w `python soc2.py agents --host 192.168.1.50`

### Krok 5 — test połączenia

- [ ] Podmienić adres w pollerze i sprawdzić live feed

```bash
python soc2.py poll --host 192.168.1.50 --level 3 --interval 30
python soc2.py status --host 192.168.1.50
```

---

## Kod — rzeczy do zrobienia

### Etap 2 — pozostałe

- [ ] Dodać obsługę SSL/TLS (`verify_ssl=True`) dla połączenia z prawdziwym Wazuhem
- [ ] Przetestować autentykację ze zmienionym hasłem
- [ ] Sprawdzić paginację przy dużej liczbie alertów (>500)

### Etap 3 — następny (nie potrzeba RPi!)

- [ ] Zarejestrować się na AbuseIPDB (darmowe, 1000 req/dzień)
  → https://www.abuseipdb.com/register
- [ ] Zarejestrować się na AlienVault OTX (darmowe)
  → https://otx.alienvault.com
- [ ] Napisać `threat_intel.py` — odpytuje IP z bazy SQLite o reputację
- [ ] Dodać kolumnę `threat_score` do tabeli `alerts` w SQLite
- [ ] Zaktualizować `soc2.py query` o filtr `--threat-score`

### Etap 4

- [ ] `pip install streamlit` i zacząć od prostego dashboardu
- [ ] Wykres timeline z bazy SQLite w czasie rzeczywistym

---

## Dokumentacja

- [ ] Wrzucić screenshot dashboardu z prawdziwymi alertami (po podłączeniu RPi)
- [ ] Zaktualizować README — sekcja "Przejście na prawdziwy Wazuh" z prawdziwym IP
- [ ] Napisać OPIS_PLIKOW.md dla Etapu 2 (tak jak zrobione dla Etapu 1)

---

## Git

- [ ] Dodać `*.db` i `alerts.db` do `.gitignore` (bazy danych nie commitujemy)
- [ ] Dodać `sample_logs/` do `.gitignore` (dane testowe nie należą do repo)
- [ ] Sprawdzić że `requirements.txt` jest aktualny po każdym nowym `pip install`

```bash
# Szablon .gitignore dla tego projektu:
echo "*.db\nsample_logs/\n*.csv\n__pycache__/\nvenv/\n*.pyc" > .gitignore
```

