"""
SOC Log Viewer (HTML) — działa BEZ żadnych zależności poza stdlib Pythona
Generuje plik HTML z filtrowalnymi alertami, paginacją i eksportem CSV

Uruchomienie:
    python viewer_html.py
    python viewer_html.py --input sample_logs/alerts.json --open
    python viewer_html.py --db alerts.db --open
    python viewer_html.py --input alerts.json --output raport.html
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


# ──────────────────────────────────────────────
# Generator HTML
# ──────────────────────────────────────────────

def generate_html(alerts: list[dict], source: str) -> str:

    all_ips    = sorted({a["srcip"]   for a in alerts if a["srcip"]})
    all_agents = sorted({a["agent"]   for a in alerts if a["agent"]})
    all_rules  = sorted({a["rule_id"] for a in alerts if a["rule_id"]})

    alerts_js   = json.dumps(alerts, ensure_ascii=False)
    ip_options  = "".join(f'<option value="{v}">{v}</option>' for v in all_ips)
    ag_options  = "".join(f'<option value="{v}">{v}</option>' for v in all_agents)
    ru_options  = "".join(f'<option value="{v}">{v}</option>' for v in all_rules)
    ts_now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total       = len(alerts)

    return f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<title>SOC Log Viewer</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', monospace, sans-serif; background: #0d1117; color: #c9d1d9; font-size: 13px; }}
header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }}
header h1 {{ font-size: 17px; font-weight: 500; color: #f0f6fc; }}
header span {{ color: #8b949e; font-size: 11px; }}
.layout {{ display: flex; height: calc(100vh - 49px); }}

/* Sidebar */
.sidebar {{ width: 272px; min-width: 272px; background: #161b22; border-right: 1px solid #30363d; padding: 14px; overflow-y: auto; }}
.sidebar h2 {{ font-size: 11px; font-weight: 500; color: #8b949e; text-transform: uppercase; letter-spacing: .06em; margin-bottom: 10px; }}
.fg {{ margin-bottom: 13px; }}
label {{ display: block; font-size: 11px; color: #8b949e; margin-bottom: 3px; }}
input[type=text], input[type=date], input[type=number], select {{
  width: 100%; background: #0d1117; border: 1px solid #30363d;
  border-radius: 6px; color: #c9d1d9; padding: 5px 8px; font-size: 12px;
}}
input:focus, select:focus {{ outline: none; border-color: #388bfd; }}
select[multiple] {{ height: 88px; }}
.row2 {{ display: flex; gap: 6px; align-items: center; }}
.row2 input {{ width: 54px; text-align: center; }}
.row2 span {{ color: #8b949e; }}
.btn {{ width: 100%; padding: 6px; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; margin-top: 5px; }}
.btn-clear  {{ background: #21262d; color: #c9d1d9; }}
.btn-export {{ background: #238636; color: #fff; }}
.btn:hover {{ opacity: .85; }}

/* Main */
.main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }}
.stats-bar {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 18px; display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }}
.stat {{ display: flex; flex-direction: column; align-items: center; }}
.stat .num {{ font-size: 19px; font-weight: 500; color: #f0f6fc; }}
.stat .lbl {{ font-size: 10px; color: #8b949e; }}
.stat.crit .num {{ color: #e63946; }}
.stat.high .num {{ color: #f4a261; }}
.stat.med  .num {{ color: #e9c46a; }}
.stat.low  .num {{ color: #90be6d; }}

/* Pasek narzędzi nad tabelą */
.toolbar {{ padding: 8px 18px; background: #0d1117; border-bottom: 1px solid #21262d; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.toolbar input[type=text] {{ flex: 1; min-width: 180px; max-width: 380px; }}
.page-size-label {{ font-size: 11px; color: #8b949e; white-space: nowrap; }}
.page-size-label select {{ width: auto; display: inline; padding: 4px 6px; }}

/* Paginacja */
.pagination {{ display: flex; align-items: center; gap: 6px; margin-left: auto; flex-wrap: wrap; }}
.pagination button {{
  background: #21262d; border: 1px solid #30363d; color: #c9d1d9;
  border-radius: 5px; padding: 3px 9px; cursor: pointer; font-size: 12px;
}}
.pagination button:hover {{ background: #30363d; }}
.pagination button.active {{ background: #388bfd; border-color: #388bfd; color: #fff; }}
.pagination button:disabled {{ opacity: .4; cursor: default; }}
.pagination .page-info {{ font-size: 11px; color: #8b949e; white-space: nowrap; }}

/* Tabela */
.table-wrap {{ flex: 1; overflow: auto; }}
table {{ width: 100%; border-collapse: collapse; }}
thead th {{
  background: #161b22; color: #8b949e; font-weight: 500; font-size: 11px;
  text-transform: uppercase; letter-spacing: .04em; padding: 7px 11px;
  text-align: left; position: sticky; top: 0; border-bottom: 1px solid #30363d;
  cursor: pointer; white-space: nowrap; user-select: none;
}}
thead th:hover {{ color: #c9d1d9; }}
tbody tr {{ border-bottom: 1px solid #21262d; }}
tbody tr:hover {{ background: #161b22; }}
td {{ padding: 6px 11px; vertical-align: middle; }}
.badge {{ display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: 500; }}
.ts    {{ color: #8b949e; font-size: 11px; white-space: nowrap; }}
.lvl   {{ font-weight: 500; text-align: center; }}
.desc  {{ max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.ip    {{ font-family: monospace; color: #79c0ff; font-size: 11px; }}
.agent {{ color: #7ee787; font-size: 11px; }}
.empty {{ text-align: center; padding: 60px; color: #8b949e; }}
.footer {{ padding: 5px 18px; background: #161b22; border-top: 1px solid #30363d; font-size: 11px; color: #8b949e; display: flex; justify-content: space-between; }}
</style>
</head>
<body>

<header>
  <h1>🛡 SOC Log Viewer</h1>
  <span>źródło: {source} &nbsp;·&nbsp; {total:,} alertów łącznie &nbsp;·&nbsp; {ts_now}</span>
</header>

<div class="layout">

  <aside class="sidebar">
    <h2>Filtry</h2>

    <div class="fg">
      <label>Poziom ryzyka (1–15)</label>
      <div class="row2">
        <input type="number" id="lvl-min" value="1"  min="1" max="15" oninput="applyFilters()">
        <span>—</span>
        <input type="number" id="lvl-max" value="15" min="1" max="15" oninput="applyFilters()">
      </div>
    </div>

    <div class="fg">
      <label>Od daty</label>
      <input type="date" id="date-from" oninput="applyFilters()">
    </div>

    <div class="fg">
      <label>Do daty</label>
      <input type="date" id="date-to" oninput="applyFilters()">
    </div>

    <div class="fg">
      <label>IP atakującego <small>(Ctrl = wiele)</small></label>
      <select id="sel-ip" multiple oninput="applyFilters()">
        {ip_options}
      </select>
    </div>

    <div class="fg">
      <label>Agent / host <small>(Ctrl = wiele)</small></label>
      <select id="sel-agent" multiple oninput="applyFilters()">
        {ag_options}
      </select>
    </div>

    <div class="fg">
      <label>ID reguły Wazuh <small>(Ctrl = wiele)</small></label>
      <select id="sel-rule" multiple oninput="applyFilters()">
        {ru_options}
      </select>
    </div>

    <button class="btn btn-clear"  onclick="clearFilters()">Wyczyść filtry</button>
    <button class="btn btn-export" onclick="exportCSV()">Pobierz CSV (przefiltrowane)</button>
  </aside>

  <div class="main">

    <div class="stats-bar">
      <div class="stat">      <span class="num" id="cnt-all">0</span> <span class="lbl">Wyfiltrowanych</span></div>
      <div class="stat crit"> <span class="num" id="cnt-crit">0</span><span class="lbl">Krytycznych ≥13</span></div>
      <div class="stat high"> <span class="num" id="cnt-high">0</span><span class="lbl">Wysokich 10–12</span></div>
      <div class="stat med">  <span class="num" id="cnt-med">0</span> <span class="lbl">Średnich 7–9</span></div>
      <div class="stat low">  <span class="num" id="cnt-low">0</span> <span class="lbl">Niskich 1–6</span></div>
    </div>

    <div class="toolbar">
      <input type="text" id="search-desc" placeholder="Szukaj w opisie alertu... (brute, injection, sudo...)" oninput="applyFilters()">

      <span class="page-size-label">
        Wyświetl
        <select id="page-size" onchange="changePageSize()">
          <option value="20">20</option>
          <option value="50" selected>50</option>
          <option value="100">100</option>
          <option value="500">500</option>
        </select>
        na stronę
      </span>

      <div class="pagination">
        <button id="btn-first" onclick="goPage(0)" title="Pierwsza">«</button>
        <button id="btn-prev"  onclick="goPage(currentPage-1)" title="Poprzednia">‹</button>
        <span class="page-info" id="page-info">—</span>
        <button id="btn-next"  onclick="goPage(currentPage+1)" title="Następna">›</button>
        <button id="btn-last"  onclick="goPage(totalPages-1)" title="Ostatnia">»</button>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th onclick="sortBy('timestamp')">Czas ↕</th>
            <th onclick="sortBy('level')">Lvl ↕</th>
            <th>Severity</th>
            <th onclick="sortBy('rule_id')">Reguła ↕</th>
            <th>Opis</th>
            <th onclick="sortBy('agent')">Agent ↕</th>
            <th onclick="sortBy('srcip')">IP źródłowe ↕</th>
            <th>User</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
      <div class="empty" id="empty-msg" style="display:none">Brak alertów spełniających kryteria.</div>
    </div>

    <div class="footer">
      <span id="footer-info">Ładowanie...</span>
      <span>SOC Home Lab &nbsp;·&nbsp; Etap 1 &amp; 2</span>
    </div>

  </div>
</div>

<script>
const ALL = {alerts_js};

const SEV = l => l >= 13 ? ['KRYTYCZNY','#e63946']
              : l >= 10 ? ['WYSOKI',    '#f4a261']
              : l >= 7  ? ['ŚREDNI',    '#e9c46a']
                        : ['NISKI',     '#90be6d'];

let filtered    = [];
let sortKey     = 'timestamp';
let sortDir     = -1;
let currentPage = 0;
let totalPages  = 1;

function pageSize() {{ return +document.getElementById('page-size').value; }}

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

  filtered = ALL.filter(a => {{
    if (a.level < lvlMin || a.level > lvlMax) return false;
    const d = a.timestamp.slice(0,10);
    if (dateFrom && d < dateFrom) return false;
    if (dateTo   && d > dateTo)   return false;
    if (ips.length    && !ips.includes(a.srcip))     return false;
    if (agents.length && !agents.includes(a.agent))  return false;
    if (rules.length  && !rules.includes(a.rule_id)) return false;
    if (search && !a.description.toLowerCase().includes(search)) return false;
    return true;
  }});

  sortAndRender(true);
}}

function sortBy(key) {{
  if (sortKey === key) sortDir *= -1; else {{ sortKey = key; sortDir = -1; }}
  sortAndRender(false);
}}

function changePageSize() {{ sortAndRender(true); }}
function goPage(p) {{ currentPage = p; renderPage(); }}

function sortAndRender(resetPage) {{
  filtered.sort((a, b) => {{
    const av = a[sortKey] ?? '', bv = b[sortKey] ?? '';
    return (typeof av === 'number' ? av - bv : av.localeCompare(bv)) * sortDir;
  }});

  if (resetPage) currentPage = 0;
  totalPages = Math.max(1, Math.ceil(filtered.length / pageSize()));
  if (currentPage >= totalPages) currentPage = totalPages - 1;

  updateStats();
  renderPage();
}}

function updateStats() {{
  document.getElementById('cnt-all').textContent  = filtered.length.toLocaleString();
  document.getElementById('cnt-crit').textContent = filtered.filter(a => a.level >= 13).length;
  document.getElementById('cnt-high').textContent = filtered.filter(a => a.level >= 10 && a.level < 13).length;
  document.getElementById('cnt-med').textContent  = filtered.filter(a => a.level >= 7  && a.level < 10).length;
  document.getElementById('cnt-low').textContent  = filtered.filter(a => a.level  < 7).length;
}}

function renderPage() {{
  const ps    = pageSize();
  const start = currentPage * ps;
  const page  = filtered.slice(start, start + ps);
  const tbody = document.getElementById('tbody');
  const empty = document.getElementById('empty-msg');

  if (!filtered.length) {{
    tbody.innerHTML = '';
    empty.style.display = 'block';
  }} else {{
    empty.style.display = 'none';
    tbody.innerHTML = page.map(a => {{
      const [sev, col] = SEV(a.level);
      return `<tr>
        <td class="ts">${{a.timestamp}}</td>
        <td class="lvl" style="color:${{col}}">${{a.level}}</td>
        <td><span class="badge" style="background:${{col}}22;color:${{col}}">${{sev}}</span></td>
        <td style="font-family:monospace;color:#8b949e;font-size:11px">${{a.rule_id}}</td>
        <td class="desc" title="${{a.description.replace(/"/g,'&quot;')}}">${{a.description}}</td>
        <td class="agent">${{a.agent}}</td>
        <td class="ip">${{a.srcip || '—'}}</td>
        <td style="color:#8b949e;font-size:11px">${{a.dstuser || '—'}}</td>
      </tr>`;
    }}).join('');
  }}

  const end = Math.min(start + ps, filtered.length);
  document.getElementById('page-info').textContent =
    filtered.length ? `${{start+1}}–${{end}} / ${{filtered.length.toLocaleString()}}` : '0';
  document.getElementById('footer-info').textContent =
    `Strona ${{currentPage+1}} z ${{totalPages}} · ${{filtered.length.toLocaleString()}} z ${{ALL.length.toLocaleString()}} alertów`;

  document.getElementById('btn-first').disabled = currentPage === 0;
  document.getElementById('btn-prev').disabled  = currentPage === 0;
  document.getElementById('btn-next').disabled  = currentPage >= totalPages - 1;
  document.getElementById('btn-last').disabled  = currentPage >= totalPages - 1;
}}

function clearFilters() {{
  document.getElementById('lvl-min').value    = 1;
  document.getElementById('lvl-max').value    = 15;
  document.getElementById('date-from').value  = '';
  document.getElementById('date-to').value    = '';
  document.getElementById('search-desc').value = '';
  ['sel-ip','sel-agent','sel-rule'].forEach(id =>
    [...document.getElementById(id).options].forEach(o => o.selected = false)
  );
  applyFilters();
}}

function exportCSV() {{
  const header = 'timestamp,level,severity,rule_id,description,agent,srcip,dstuser';
  const rows = filtered.map(a => {{
    const [sev] = SEV(a.level);
    return [a.timestamp, a.level, sev, a.rule_id,
            '"' + a.description.replace(/"/g,'""') + '"',
            a.agent, a.srcip, a.dstuser].join(',');
  }});
  const blob = new Blob([[header, ...rows].join('\\n')], {{type:'text/csv'}});
  const url  = URL.createObjectURL(blob);
  const el   = Object.assign(document.createElement('a'), {{
    href: url, download: 'alerty_' + new Date().toISOString().slice(0,16).replace(':','-') + '.csv'
  }});
  el.click();
  URL.revokeObjectURL(url);
}}

applyFilters();
</script>
</body>
</html>"""


# ──────────────────────────────────────────────
# Punkt wejścia
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC Log Viewer — panel filtrów w HTML, zero zależności",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Przykłady:
  python viewer_html.py
  python viewer_html.py --input sample_logs/wazuh_alerts.json --open
  python viewer_html.py --db etap2_wazuh_api/alerts.db --open
  python viewer_html.py --db alerts.db --output raport.html
        """
    )
    parser.add_argument("--input",  default="etap1_log_analyzer/sample_logs/wazuh_alerts.json")
    parser.add_argument("--db",     default=None,   help="Baza SQLite — nadpisuje --input")
    parser.add_argument("--output", default="soc_viewer.html")
    parser.add_argument("--open",   action="store_true", help="Otwórz w przeglądarce po wygenerowaniu")
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
        print("Brak alertów — sprawdź ścieżkę.")
        return

    print(f"Wczytano {len(alerts):,} alertów")
    html = generate_html(alerts, source)

    out = Path(args.output)
    out.write_text(html, encoding="utf-8")
    print(f"Zapisano: {out}  ({out.stat().st_size // 1024} KB)")

    if args.open:
        webbrowser.open(out.resolve().as_uri())
    else:
        print(f"Otwórz: {out.resolve()}")


if __name__ == "__main__":
    main()
