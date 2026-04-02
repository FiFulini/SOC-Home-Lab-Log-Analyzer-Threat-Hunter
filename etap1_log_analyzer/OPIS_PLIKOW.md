# Opis plików — Etap 1

Dokument wyjaśnia co robi każdy plik w projekcie, jakie decyzje projektowe zostały podjęte i dlaczego kod wygląda tak a nie inaczej.

---

## `soc.py` — główny punkt wejścia

Spina wszystkie moduły w jedno narzędzie CLI z podkomendami (`generate`, `analyze`, `brute`, `chart`, `full`). Napisany z `argparse` — standardową biblioteką Pythona do budowania CLI.

**Dlaczego podkomendy zamiast flag?** Bo każda operacja ma inne argumenty. `analyze --level` nie ma sensu dla `chart`, a `brute --min-fail` nie ma sensu dla `generate`. Podkomendy wymuszają porządek i robią `--help` czytelnym.

**Wzorzec `args.func(args)`** — każda podkomenda rejestruje swoją funkcję przez `set_defaults(func=cmd_xyz)`. Dzięki temu główna pętla nie musi wiedzieć co która podkomenda robi — po prostu wywołuje `args.func(args)`. To klasyczny wzorzec Command Pattern.

**`cmd_full`** uruchamia analizę + brute-force + wykres w jednym przebiegu — przydatne do automatyzacji (np. cron co godzinę na RPi).

---

## `generate_sample_logs.py` — generator logów testowych

Generuje realistyczne logi Wazuh w formacie JSON bez potrzeby posiadania prawdziwego środowiska. Każda linia pliku wyjściowego to jeden alert — dokładnie tak jak Wazuh zapisuje logi na dysk.

**Cztery scenariusze ataków** odpowiadają realnym wzorcom z raportów bezpieczeństwa:

- `scenario_brute_force` — 20–40 szybkich prób SSH z jednego IP, losowo kończących się sukcesem (30% szans). Mapuje na MITRE T1110.001.
- `scenario_web_scan` — skanowanie katalogów (`/.env`, `/wp-login.php`) i próby SQL injection. Mapuje na MITRE T1595 i T1190.
- `scenario_privilege_escalation` — kilka błędnych `sudo`, potem udane `sudo bash` z podejrzaną komendą (`chmod 4777`). Mapuje na MITRE T1548.003.
- `scenario_file_integrity` — zmiana MD5 na plikach `/etc/passwd`, `/etc/shadow`, `/root/.ssh/authorized_keys`. Mapuje na MITRE T1565.

**`--seed`** sprawia że wyniki są powtarzalne — przydatne do testów jednostkowych i debugowania. Ten sam seed zawsze daje te same logi.

**`make_alert()`** to jedyna funkcja budująca słownik alertu — dzięki temu format JSON jest spójny w całym generatorze. Jeśli zmieniasz strukturę alertu, zmieniasz jedno miejsce.

---

## `brute_force_detector.py` — detektor ataków

Implementuje trzy algorytmy detekcji brute-force. Każdy wykrywa inny wzorzec ataku.

### Klasa `LoginEvent`

Opakowuje surowy słownik alertu w obiekt z gotowymi polami. Zamiast pisać wszędzie `alert["rule"]["id"]` piszesz `event.rule_id`. Dwie flagi `is_fail` i `is_ok` ustawiają się w konstruktorze raz — nie powtarzasz logiki filtrowania w każdej funkcji.

### `_sliding_window()` — serce detektora

Algorytm który będziesz spotykał wszędzie w security (Splunk, Elastic SIEM, reguły Sigma). Dla każdego zdarzenia zbiera wszystkie inne zdarzenia z tego samego klucza które nastąpiły w ciągu `window_sec` sekund po nim. Zachowuje okno z największą liczbą zdarzeń — to właśnie wykrywa "szczyt aktywności".

```
Zdarzenia:  A  B  C        D  E  F  G
Czas:       0  5  8       45 47 49 55
Okno 60s:   └──────────────┘  <- dla A: A,B,C,D,E,F (6 zdarzeń)
                    └──────────────┘  <- dla C: C,D,E,F,G (5 zdarzeń)
```

`key_fn` to funkcja która mówi "co grupujemy razem" — dla brute-force to `(ip, agent)`, dla spraying to też `(ip, agent)` ale liczymy unikalne username'y, dla distributed to `(user, agent)`.

### `_success_followed()` — korelacja zdarzeń

Najważniejsza funkcja w całym pliku. Sprawdza czy w ciągu 120 sekund po ostatniej próbie ataku nastąpiło udane logowanie z tego samego IP. Jeśli tak — atak się powiódł i mamy potencjalnie przejęte konto. To jest właśnie **korelacja zdarzeń** — fundament pracy analityka SOC. Nie wystarczy wykryć atak, trzeba odpowiedzieć na pytanie "czy się udał?".

### Trzy detektory

**`detect_brute_force`** — klasyczny: jeden IP, jeden host, dużo prób w krótkim czasie.

**`detect_spraying`** — odwrócony: jeden IP próbuje wielu różnych użytkowników. Atakujący celowo spowalnia i zmienia loginy żeby uniknąć blokady konta. Klasyczny licznik prób tego nie wykryje — sliding window tak.

**`detect_distributed`** — botnet: wiele IP atakuje jednego usera. Każde pojedyncze IP wysyła tylko 2-3 próby i wygląda jak normalna literówka w haśle. Razem — skoordynowany atak.

### Klasa `BruteForceAlert`

Przechowuje gotowy wynik detekcji. Property `duration_sec` oblicza się automatycznie z timestamps — nie musisz tego liczyć ręcznie w każdym miejscu.

---

## `visualizer.py` — dashboard PNG

Generuje cztery wykresy w jednym pliku PNG. Używa `matplotlib` w trybie `Agg` (bez GUI) — dzięki temu działa też na serwerze bez monitora (RPi, VM).

**Ciemne tło (#0d1117)** to kolor tła GitHuba w dark mode — dashboard w README wygląda natywnie.

### Wykres 1 — timeline alertów (scatter plot)

Każdy alert to kropka na osi czasu (X) i poziomie ryzyka (Y). Kolor i rozmiar zakodowują severity — im poważniejszy alert, tym większa i cieplejsza kropka. Skupienia kropek w czasie to właśnie ataki. Analityk SOC widzi anomalie wzrokowo bez czytania logów.

**Dynamiczny format osi X** — zakres poniżej 6 godzin pokazuje minuty (`14:30`), do 48 godzin pokazuje datę i godzinę (`01.06 14:00`), powyżej pokazuje tylko daty (`01.06`). Skala dostosowuje się do rozpiętości danych.

### Wykres 2 — heatmapa godzinowa

Zlicza alerty wysokiego ryzyka (poziom ≥7) per godzina. Jasny kolor = intensywny ruch. W prawdziwym środowisku produkcyjnym nocne szczyty (2:00–4:00) to klasyczny sygnał ataku — atakujący zakłada że wtedy nikt nie patrzy.

**`plt.cm.YlOrRd`** — żółto-pomarańczowo-czerwona colormap, intuicyjnie kojarzy się z zagrożeniem.

### Wykres 3 — top 10 reguł (poziome słupki)

Pokazuje które reguły Wazuha wyzwalają się najczęściej. Jeśli jedna reguła dominuje przez tygodnie — albo masz realny problem, albo reguła jest zbyt czuła i wymaga tuningu progu. To dokładnie ta sama analiza którą robiłeś przy optymalizacji SIEMa na inżynierce.

### Wykres 4 — top atakujące IP

Kandydaci do blokady przez `iptables`. Czerwone IP to adresy z zakodowanej listy znanych złych aktorów (węzły Tor, znane botnety z dokumentacji edukacyjnej). W Etapie 5 (SOAR) skrypt będzie je automatycznie blokował.

---

## `parser.py` — wczytywanie logów

Czyta plik JSON linia po linii (`for line in f`) zamiast wczytywać całość do pamięci. Przy pliku z milionem alertów to ma znaczenie — nie ładujesz gigabajta do RAM naraz.

`try/except json.JSONDecodeError` pomija uszkodzone lub puste linie bez przerywania pracy. W prawdziwych logach zdarzają się urwane linie przy restarcie SIEM-a.

---

## `rules.py` — filtrowanie alertów

Dwie czyste funkcje bez efektów ubocznych:

- `filter_by_level(alerts, min_level)` — zwraca alerty o poziomie ≥ min_level
- `filter_by_group(alerts, group)` — zwraca alerty z daną grupą Wazuha (np. `"brute_force"`, `"web"`)

Każda przyjmuje listę i zwraca listę — można łączyć łańcuchowo:

```python
alerts = filter_by_level(all_alerts, min_level=7)
alerts = filter_by_group(alerts, group="authentication_failed")
```

---

## `reporter.py` — eksport CSV

Zapisuje wybrane pola alertu do pliku CSV gotowego do otwarcia w Excelu lub pandas. `csv.DictWriter` z listą `fieldnames` gwarantuje że kolumny są zawsze w tej samej kolejności niezależnie od kolejności kluczy w słowniku alertu.

---

## `main.py` — standalone analiza

Łączy parser + rules + reporter w jeden prosty skrypt. Istnieje obok `soc.py` jako uproszczona wersja bez CLI — przydatna do szybkich testów i jako punkt wejścia dla początkujących którzy jeszcze nie znają podkomend.

---

## `sample_logs/wazuh_alerts.json`

Plik generowany przez `generate_sample_logs.py`. Każda linia to jeden alert JSON — format identyczny z prawdziwym Wazuhem. Gdy przejdziesz na RPi z prawdziwym SIEM-em, podmienisz ten plik na live feed z API i cały pozostały kod zadziała bez zmian.

**Plik nie jest commitowany do gita** (`.gitignore`) bo jest duży i można go zawsze wygenerować od nowa. Commitowanie danych binarnych/dużych plików to częsty błąd w projektach.

---

## Format alertu Wazuh (JSON)

Każda linia pliku logów ma tę strukturę:

```json
{
  "timestamp": "2024-06-03T02:14:55.000+0000",
  "rule": {
    "id": "5760",
    "level": 12,
    "description": "sshd: Multiple authentication failures",
    "groups": ["syslog", "sshd", "authentication_failed", "brute_force"]
  },
  "agent": {
    "id": "001",
    "name": "linux-server-01"
  },
  "manager": {
    "name": "wazuh-manager"
  },
  "data": {
    "srcip": "91.108.4.200",
    "dstuser": "root"
  }
}
```

Pola które używamy w kodzie:

| Pole | Użycie |
|---|---|
| `timestamp` | oś czasu wykresów, filtrowanie dat, sliding window |
| `rule.id` | identyfikacja typu zdarzenia, filtrowanie success/fail |
| `rule.level` | severity, filtrowanie alertów wysokiego ryzyka |
| `rule.groups` | klasyfikacja zdarzeń (brute_force, web, syscheck) |
| `agent.name` | który host jest atakowany |
| `data.srcip` | który IP atakuje — kandydat do blokady |
| `data.dstuser` | który użytkownik jest celem |

