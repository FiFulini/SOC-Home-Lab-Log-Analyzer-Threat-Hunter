"""
SOC Log Viewer (HTML) — działa BEZ żadnych zależności poza stdlib Pythona
Generuje plik HTML z pełną tabelą, filtrami JavaScript i eksportem CSV

Uruchomienie:
    python viewer_html.py                                    # z domyślnego pliku JSON
    python viewer_html.py --input sample_logs/alerts.json
    python viewer_html.py --db alerts.db                    # z SQLite (Etap 2)
    python viewer_html.py --input alerts.json --open        # otwórz w przeglądarce od razu
    python viewer_html.py --db alerts.db --open
"""

import argparse
import json
import sqlite3
import webbrowser
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
# Ładowanie danych
# ──────────────────────────────────────────────

def load_json(filepath: str) -> list[dict]:
    rows = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                rows.append({
                    "timestamp":   a.get("timestamp", "")[:19].replace("T", " "),
                    "level":       a["rule"]["level"],
                    "rule_id":     a["rule"]["id"],
                    "description": a["rule"]["description"],
                    "groups":      ", ".join(a["rule"].get("groups", [])),
                    "agent":       a["agent"]["name"],
                    "srcip":       a.get("data", {}).get("srcip", ""),
                    "dstuser":     a.get("data", {}).get("dstuser", ""),
                })
            except Exception:
                pass
    return rows


def load_sqlite(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT timestamp, level, rule_id, description,
                  groups, agent_name as agent, srcip, dstuser
           FROM alerts ORDER BY timestamp DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def severity(level: int) -> tuple[str, str]:
    if level >= 13: return "KRYTYCZNY", "#e63946"
    if level >= 10: return "WYSOKI",    "#f4a261"
    if level >= 7:  return "ŚREDNI",    "#e9c46a"
    return "NISKI", "#90be6d"


# ──────────────────────────────────────────────
# Generator HTML
# ──────────────────────────────────────────────

def generate_html(alerts: list[dict], source: str) -> str:

    # Zbierz unikalne wartości do dropdownów
    all_ips     = sorted({a["srcip"]   for a in alerts if a["srcip"]})
    all_agents  = sorted({a["agent"]   for a in alerts if a["agent"]})
    all_rules   = sorted({a["rule_id"] for a in alerts if a["rule_id"]})

    # Serializuj dane do JS
    alerts_js = json.dumps(alerts, ensure_ascii=False)

    ip_options     = "".join(f'<option value="{v}">{v}</option>' for v in all_ips)
    agent_options  = "".join(f'<option value="{v}">{v}</option>' for v in all_agents)
    rule_options   = "".join(f'<option value="{v}">{v}</option>' for v in all_rules)

    ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>SOC Log Viewer</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', monospace, sans-serif; background: #0d1117; color: #c9d1d9; font-size: 13px; }}
  header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 14px 24px; display: flex; align-items: center; gap: 16px; }}
  header h1 {{ font-size: 18px; font-weight: 500; color: #f0f6fc; }}
  header span {{ color: #8b949e; font-size: 12px; }}
  .layout {{ display: flex; height: calc(100vh - 53px); }}
  .sidebar {{ width: 280px; min-width: 280px; background: #161b22; border-right: 1px solid #30363d; padding: 16px; overflow-y: auto; }}
  .sidebar h2 {{ font-size: 13px; font-weight: 500; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 12px; }}
  .filter-group {{ margin-bottom: 16px; }}
  label {{ display: block; font-size: 11px; color: #8b949e; margin-bottom: 4px; }}
  input, select {{ width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; padding: 6px 8px; font-size: 12px; }}
  input:focus, select:focus {{ outline: none; border-color: #388bfd; }}
  select[multiple] {{ height: 90px; }}
  .range-row {{ display: flex; gap: 8px; align-items: center; }}
  .range-row input {{ width: 56px; text-align: center; }}
  .range-row span {{ color: #8b949e; }}
  .btn {{ width: 100%; padding: 7px; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; margin-top: 6px; }}
  .btn-clear  {{ background: #21262d; color: #c9d1d9; }}
  .btn-export {{ background: #238636; color: #fff; }}
  .btn:hover {{ opacity: .85; }}
  .main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}
  .stats-bar {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 20px; display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }}
  .stat {{ display: flex; flex-direction: column; align-items: center; }}
  .stat .num {{ font-size: 20px; font-weight: 500; color: #f0f6fc; }}
  .stat .lbl {{ font-size: 10px; color: #8b949e; }}
  .stat.crit .num {{ color: #e63946; }}
  .stat.high .num {{ color: #f4a261; }}
  .stat.med  .num {{ color: #e9c46a; }}
  .stat.low  .num {{ color: #90be6d; }}
  .search-bar {{ padding: 10px 20px; background: #0d1117; border-bottom: 1px solid #21262d; }}
  .search-bar input {{ max-width: 400px; }}
  .table-wrap {{ flex: 1; overflow: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{ background: #161b22; color: #8b949e; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; padding: 8px 12px; text-align: left; position: sticky; top: 0; border-bottom: 1px solid #30363d; cursor: pointer; white-space: nowrap; user-select: none; }}
  thead th:hover {{ color: #c9d1d9; }}
  tbody tr {{ border-bottom: 1px solid #21262d; }}
  tbody tr:hover {{ background: #161b22; }}
  td {{ padding: 7px 12px; vertical-align: middle; }}
  .badge {{ display: inline-block; padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 500; }}
  .ts {{ color: #8b949e; font-size: 11px; white-space: nowrap; }}
  .lvl {{ font-weight: 500; text-align: center; }}
  .desc {{ max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #c9d1d9; }}
  .ip {{ font-family: monospace; color: #79c0ff; font-size: 11px; }}
  .agent {{ color: #7ee787; font-size: 11px; }}
  .empty {{ text-align: center; padding: 60px; color: #8b949e; }}
  .footer {{ padding: 6px 20px; background: #161b22; border-top: 1px solid #30363d; font-size: 11px; color: #8b949e; display: flex; justify-content: space-between; }}
</style>
</head>
<body>

<header>
  <h1>🛡 SOC Log Viewer</h1>
  <span>źródło: {source} &nbsp;·&nbsp; wygenerowano: {ts_now}</span>
</header>

<div class="layout">

  <!-- Sidebar filtrów -->
  <aside class="sidebar">
    <h2>Filtry</h2>

    <div class="filter-group">
      <label>Poziom ryzyka (1–15)</label>
      <div class="range-row">
        <input type="number" id="lvl-min" value="1" min="1" max="15" oninput="applyFilters()">
        <span>—</span>
        <input type="number" id="lvl-max" value="15" min="1" max="15" oninput="applyFilters()">
      </div>
    </div>

    <div class="filter-group">
      <label>Od daty</label>
      <input type="date" id="date-from" oninput="applyFilters()">
    </div>

    <div class="filter-group">
      <label>Do daty</label>
      <input type="date" id="date-to" oninput="applyFilters()">
    </div>

    <div class="filter-group">
      <label>IP atakującego (Ctrl = wiele)</label>
      <select id="sel-ip" multiple oninput="applyFilters()">
        {ip_options}
      </select>
    </div>

    <div class="filter-group">
      <label>Agent / host (Ctrl = wiele)</label>
      <select id="sel-agent" multiple oninput="applyFilters()">
        {agent_options}
      </select>
    </div>

    <div class="filter-group">
      <label>ID reguły Wazuh (Ctrl = wiele)</label>
      <select id="sel-rule" multiple oninput="applyFilters()">
        {rule_options}
      </select>
    </div>

    <button class="btn btn-clear" onclick="clearFilters()">Wyczyść filtry</button>
    <button class="btn btn-export" onclick="exportCSV()">Pobierz CSV</button>
  </aside>

  <div class="main">

    <!-- Pasek metryk -->
    <div class="stats-bar">
      <div class="stat"><span class="num" id="cnt-all">0</span><span class="lbl">Wszystkich</span></div>
      <div class="stat crit"><span class="num" id="cnt-crit">0</span><span class="lbl">Krytycznych</span></div>
      <div class="stat high"><span class="num" id="cnt-high">0</span><span class="lbl">Wysokich</span></div>
      <div class="stat med" ><span class="num" id="cnt-med">0</span><span class="lbl">Średnich</span></div>
      <div class="stat low" ><span class="num" id="cnt-low">0</span><span class="lbl">Niskich</span></div>
    </div>

    <!-- Pasek wyszukiwania -->
    <div class="search-bar">
      <input type="text" id="search-desc" placeholder="Szukaj w opisie alertu... (np. brute, injection, sudo)" oninput="applyFilters()">
    </div>

    <!-- Tabela -->
    <div class="table-wrap">
      <table id="alert-table">
        <thead>
          <tr>
            <th onclick="sortTable('timestamp')">Czas ↕</th>
            <th onclick="sortTable('level')">Lvl ↕</th>
            <th>Severity</th>
            <th onclick="sortTable('rule_id')">Reguła ↕</th>
            <th>Opis</th>
            <th onclick="sortTable('agent')">Agent ↕</th>
            <th onclick="sortTable('srcip')">IP źródłowe ↕</th>
            <th>User</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
      <div class="empty" id="empty-msg" style="display:none">Brak alertów spełniających kryteria filtrów.</div>
    </div>

    <div class="footer">
      <span id="footer-info">Ładowanie...</span>
      <span>SOC Home Lab — Etap 1 &amp; 2</span>
    </div>

  </div>
</div>

<script>
const ALERTS = {alerts_js};

const SEV = (l) => l >= 13 ? ['KRYTYCZNY','#e63946'] : l >= 10 ? ['WYSOKI','#f4a261'] : l >= 7 ? ['ŚREDNI','#e9c46a'] : ['NISKI','#90be6d'];

let filtered = [...ALERTS];
let sortKey  = 'timestamp';
let sortDir  = -1;

function getSelected(id) {{
  return [...document.getElementById(id).selectedOptions].map(o => o.value);
}}

function applyFilters() {{
  const lvlMin   = +document.getElementById('lvl-min').value  || 1;
  const lvlMax   = +document.getElementById('lvl-max').value  || 15;
  const dateFrom = document.getElementById('date-from').value;
  const dateTo   = document.getElementById('date-to').value;
  const ips      = getSelected('sel-ip');
  const agents   = getSelected('sel-agent');
  const rules    = getSelected('sel-rule');
  const search   = document.getElementById('search-desc').value.toLowerCase();

  filtered = ALERTS.filter(a => {{
    if (a.level < lvlMin || a.level > lvlMax) return false;
    if (dateFrom && a.timestamp.slice(0,10) < dateFrom) return false;
    if (dateTo   && a.timestamp.slice(0,10) > dateTo)   return false;
    if (ips.length    && !ips.includes(a.srcip))    return false;
    if (agents.length && !agents.includes(a.agent)) return false;
    if (rules.length  && !rules.includes(a.rule_id)) return false;
    if (search && !a.description.toLowerCase().includes(search)) return false;
    return true;
  }});

  sortAndRender();
}}

function sortTable(key) {{
  if (sortKey === key) sortDir *= -1;
  else {{ sortKey = key; sortDir = -1; }}
  sortAndRender();
}}

function sortAndRender() {{
  const sorted = [...filtered].sort((a, b) => {{
    const av = a[sortKey] ?? '', bv = b[sortKey] ?? '';
    if (typeof av === 'number') return (av - bv) * sortDir;
    return av.localeCompare(bv) * sortDir;
  }});
  render(sorted);
}}

function render(data) {{
  const tbody = document.getElementById('tbody');
  const empty = document.getElementById('empty-msg');

  if (!data.length) {{
    tbody.innerHTML = '';
    empty.style.display = 'block';
  }} else {{
    empty.style.display = 'none';
    tbody.innerHTML = data.map(a => {{
      const [sev, col] = SEV(a.level);
      return `<tr>
        <td class="ts">${{a.timestamp}}</td>
        <td class="lvl" style="color:${{col}}">${{a.level}}</td>
        <td><span class="badge" style="background:${{col}}22;color:${{col}}">${{sev}}</span></td>
        <td style="font-family:monospace;color:#8b949e">${{a.rule_id}}</td>
        <td class="desc" title="${{a.description}}">${{a.description}}</td>
        <td class="agent">${{a.agent}}</td>
        <td class="ip">${{a.srcip || '—'}}</td>
        <td style="color:#8b949e">${{a.dstuser || '—'}}</td>
      </tr>`;
    }}).join('');
  }}

  document.getElementById('cnt-all').textContent  = data.length.toLocaleString();
  document.getElementById('cnt-crit').textContent = data.filter(a => a.level >= 13).length;
  document.getElementById('cnt-high').textContent = data.filter(a => a.level >= 10 && a.level < 13).length;
  document.getElementById('cnt-med').textContent  = data.filter(a => a.level >= 7  && a.level < 10).length;
  document.getElementById('cnt-low').textContent  = data.filter(a => a.level < 7).length;
  document.getElementById('footer-info').textContent =
    `${{data.length.toLocaleString()}} z ${{ALERTS.length.toLocaleString()}} alertów`;
}}

function clearFilters() {{
  document.getElementById('lvl-min').value  = 1;
  document.getElementById('lvl-max').value  = 15;
  document.getElementById('date-from').value = '';
  document.getElementById('date-to').value   = '';
  document.getElementById('search-desc').value = '';
  ['sel-ip','sel-agent','sel-rule'].forEach(id => {{
    [...document.getElementById(id).options].forEach(o => o.selected = false);
  }});
  applyFilters();
}}

function exportCSV() {{
  const header = ['timestamp','level','severity','rule_id','description','agent','srcip','dstuser'];
  const rows   = filtered.map(a => {{
    const [sev] = SEV(a.level);
    return [a.timestamp, a.level, sev, a.rule_id,
            '"' + a.description.replace(/"/g,'""') + '"',
            a.agent, a.srcip, a.dstuser].join(',');
  }});
  const csv  = [header.join(','), ...rows].join('\\n');
  const blob = new Blob([csv], {{type:'text/csv'}});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = 'alerty_' + new Date().toISOString().slice(0,16).replace(':','-') + '.csv';
  a.click();
  URL.revokeObjectURL(url);
}}

// Inicjalizacja
applyFilters();
</script>
</body>
</html>"""


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC Log Viewer — generuje HTML z filtrowalnymi alertami",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  python viewer_html.py                                         # domyślny plik JSON
  python viewer_html.py --input etap1_log_analyzer/sample_logs/wazuh_alerts.json
  python viewer_html.py --db etap2_wazuh_api/alerts.db 
  python viewer_html.py --input alerts.json --output raport.html --open
  python viewer_html.py --db etap2_wazuh_api/alerts.db --open
        """
    )
    parser.add_argument("--input",  default="etap1_log_analyzer/sample_logs/wazuh_alerts.json",
                        help="Plik JSON z alertami (Etap 1)")
    parser.add_argument("--db",     default=None,
                        help="Baza SQLite (Etap 2) — nadpisuje --input")
    parser.add_argument("--output", default="soc_viewer.html",
                        help="Plik wyjściowy HTML (domyślnie: soc_viewer.html)")
    parser.add_argument("--open",   action="store_true",
                        help="Otwórz w przeglądarce po wygenerowaniu")
    args = parser.parse_args()

    if args.db:
        print(f"Ładowanie z SQLite: {args.db}")
        alerts = load_sqlite(args.db)
        source = args.db
    else:
        print(f"Ładowanie z JSON: {args.input}")
        alerts = load_json(args.input)
        source = args.input

    if not alerts:
        print("Brak alertów — sprawdź ścieżkę do pliku.")
        return

    print(f"Wczytano {len(alerts):,} alertów")
    html = generate_html(alerts, source)

    output = Path(args.output)
    output.write_text(html, encoding="utf-8")
    size_kb = output.stat().st_size // 1024
    print(f"Zapisano: {output} ({size_kb} KB)")

    if args.open:
        webbrowser.open(output.resolve().as_uri())
        print("Otwarto w przeglądarce")
    else:
        print(f"Otwórz ręcznie: {output.resolve()}")


if __name__ == "__main__":
    main()
