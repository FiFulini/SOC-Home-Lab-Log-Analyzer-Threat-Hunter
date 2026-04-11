"""
SOC Log Viewer (HTML) — panel filtrów, paginacja, szczegóły alertu
Zero zależności poza stdlib Pythona.

Uruchomienie:
    python viewer_html.py --input sample_logs/wazuh_alerts.json --open
    python viewer_html.py --db alerts.db --open
"""

import argparse
import json
import sqlite3
import webbrowser
from datetime import datetime
from pathlib import Path


def load_json(filepath: str) -> list[dict]:
    rows = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def load_sqlite(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT raw FROM alerts ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        try:
            result.append(json.loads(r["raw"]))
        except Exception:
            pass
    return result


def flatten(alert: dict) -> dict:
    """Spłaszcza zagnieżdżony alert do płaskiego słownika dla tabeli."""
    return {
        "timestamp":   alert.get("timestamp", "")[:19].replace("T", " "),
        "level":       alert["rule"]["level"],
        "rule_id":     alert["rule"]["id"],
        "description": alert["rule"]["description"],
        "groups":      ", ".join(alert["rule"].get("groups", [])),
        "agent":       alert["agent"]["name"],
        "srcip":       alert.get("data", {}).get("srcip", ""),
        "dstuser":     alert.get("data", {}).get("dstuser", ""),
        "has_syscheck": "syscheck" in alert,
    }


def generate_html(alerts: list[dict], source: str) -> str:

    flat         = [flatten(a) for a in alerts]
    all_ips      = sorted({r["srcip"]   for r in flat if r["srcip"]})
    all_agents   = sorted({r["agent"]   for r in flat if r["agent"]})
    all_rules    = sorted({r["rule_id"] for r in flat if r["rule_id"]})

    # Pełne alerty (z syscheck) serializowane do JS
    alerts_full_js = json.dumps(alerts, ensure_ascii=False)
    flat_js        = json.dumps(flat,   ensure_ascii=False)

    ip_options = "".join(f'<option value="{v}">{v}</option>' for v in all_ips)
    ag_options = "".join(f'<option value="{v}">{v}</option>' for v in all_agents)
    ru_options = "".join(f'<option value="{v}">{v}</option>' for v in all_rules)
    ts_now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total      = len(alerts)

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

/* Sidebar filtrów */
.sidebar {{ width: 268px; min-width: 268px; background: #161b22; border-right: 1px solid #30363d; padding: 14px; overflow-y: auto; }}
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

/* Środek — tabela */
.main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }}
.stats-bar {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 18px; display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }}
.stat {{ display: flex; flex-direction: column; align-items: center; }}
.stat .num {{ font-size: 19px; font-weight: 500; color: #f0f6fc; }}
.stat .lbl {{ font-size: 10px; color: #8b949e; }}
.stat.crit .num {{ color: #e63946; }}
.stat.high .num {{ color: #f4a261; }}
.stat.med  .num {{ color: #e9c46a; }}
.stat.low  .num {{ color: #90be6d; }}

.toolbar {{ padding: 8px 18px; background: #0d1117; border-bottom: 1px solid #21262d; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.toolbar input[type=text] {{ flex: 1; min-width: 180px; max-width: 360px; }}
.ps-label {{ font-size: 11px; color: #8b949e; white-space: nowrap; }}
.ps-label select {{ width: auto; display: inline; padding: 4px 6px; }}
.pagination {{ display: flex; align-items: center; gap: 5px; margin-left: auto; }}
.pagination button {{
  background: #21262d; border: 1px solid #30363d; color: #c9d1d9;
  border-radius: 5px; padding: 3px 9px; cursor: pointer; font-size: 12px;
}}
.pagination button:hover {{ background: #30363d; }}
.pagination button:disabled {{ opacity: .4; cursor: default; }}
.pagination .pi {{ font-size: 11px; color: #8b949e; white-space: nowrap; padding: 0 4px; }}

.table-wrap {{ flex: 1; overflow: auto; }}
table {{ width: 100%; border-collapse: collapse; }}
thead th {{
  background: #161b22; color: #8b949e; font-weight: 500; font-size: 11px;
  text-transform: uppercase; letter-spacing: .04em; padding: 7px 10px;
  text-align: left; position: sticky; top: 0; border-bottom: 1px solid #30363d;
  cursor: pointer; white-space: nowrap; user-select: none;
}}
thead th:hover {{ color: #c9d1d9; }}
tbody tr {{ border-bottom: 1px solid #21262d; cursor: pointer; }}
tbody tr:hover {{ background: #1c2128; }}
tbody tr.selected {{ background: #1f2d3d !important; border-left: 3px solid #388bfd; }}
td {{ padding: 6px 10px; vertical-align: middle; }}
.badge {{ display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: 500; }}
.fim-badge {{ background: #3d2314; color: #f4a261; font-size: 9px; padding: 1px 5px; border-radius: 8px; margin-left: 4px; }}
.ts    {{ color: #8b949e; font-size: 11px; white-space: nowrap; }}
.lvl   {{ font-weight: 500; text-align: center; }}
.desc  {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.ip    {{ font-family: monospace; color: #79c0ff; font-size: 11px; }}
.ag    {{ color: #7ee787; font-size: 11px; }}
.empty {{ text-align: center; padding: 60px; color: #8b949e; }}
.footer {{ padding: 5px 18px; background: #161b22; border-top: 1px solid #30363d; font-size: 11px; color: #8b949e; display: flex; justify-content: space-between; }}

/* Panel szczegółów — wysuwa się z prawej */
.detail-panel {{
  width: 0; min-width: 0; background: #161b22;
  border-left: 1px solid #30363d;
  overflow: hidden; transition: width .2s ease;
  display: flex; flex-direction: column;
}}
.detail-panel.open {{ width: 420px; min-width: 420px; }}
.dp-header {{
  padding: 12px 16px; border-bottom: 1px solid #30363d;
  display: flex; align-items: center; justify-content: space-between;
}}
.dp-header h3 {{ font-size: 13px; font-weight: 500; color: #f0f6fc; }}
.dp-close {{
  background: none; border: none; color: #8b949e; cursor: pointer;
  font-size: 16px; padding: 0 4px; line-height: 1;
}}
.dp-close:hover {{ color: #c9d1d9; }}
.dp-body {{ flex: 1; overflow-y: auto; padding: 14px 16px; }}
.dp-section {{ margin-bottom: 18px; }}
.dp-section h4 {{
  font-size: 10px; font-weight: 500; color: #8b949e;
  text-transform: uppercase; letter-spacing: .06em;
  margin-bottom: 8px; padding-bottom: 4px;
  border-bottom: 1px solid #21262d;
}}
.dp-row {{ display: flex; gap: 8px; margin-bottom: 6px; align-items: flex-start; }}
.dp-key {{
  font-size: 11px; color: #8b949e; min-width: 110px;
  flex-shrink: 0; padding-top: 1px;
}}
.dp-val {{
  font-size: 12px; color: #c9d1d9; font-family: monospace;
  word-break: break-all; flex: 1;
}}
.dp-val.critical {{ color: #e63946; }}
.dp-val.high     {{ color: #f4a261; }}
.dp-val.medium   {{ color: #e9c46a; }}
.dp-val.low      {{ color: #90be6d; }}
.dp-val.path     {{ color: #79c0ff; }}
.dp-val.hash     {{ font-size: 10px; color: #6e7681; }}
.dp-val.changed  {{ color: #f4a261; }}
.dp-val.added    {{ color: #e63946; }}
.hash-row {{ display: flex; flex-direction: column; gap: 2px; }}
.hash-line {{ font-size: 10px; color: #6e7681; font-family: monospace; word-break: break-all; }}
.hash-line span {{ color: #8b949e; margin-right: 4px; }}
.diff-block {{
  background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
  padding: 8px 10px; margin-top: 4px;
}}
.diff-before {{ color: #e63946; font-size: 11px; font-family: monospace; }}
.diff-after  {{ color: #7ee787; font-size: 11px; font-family: monospace; }}
.groups-list {{ display: flex; flex-wrap: wrap; gap: 4px; }}
.group-tag {{
  background: #21262d; border: 1px solid #30363d; border-radius: 10px;
  padding: 2px 7px; font-size: 10px; color: #8b949e;
}}
.json-block {{
  background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
  padding: 10px; font-size: 10px; font-family: monospace; color: #8b949e;
  overflow-x: auto; white-space: pre; margin-top: 6px; max-height: 300px; overflow-y: auto;
}}
</style>
</head>
<body>

<header>
  <h1>🛡 SOC Log Viewer</h1>
  <span>źródło: {source} · {total:,} alertów · {ts_now}</span>
</header>

<div class="layout">

  <!-- Sidebar filtrów -->
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
      <select id="sel-ip" multiple oninput="applyFilters()">{ip_options}</select>
    </div>
    <div class="fg">
      <label>Agent / host <small>(Ctrl = wiele)</small></label>
      <select id="sel-agent" multiple oninput="applyFilters()">{ag_options}</select>
    </div>
    <div class="fg">
      <label>ID reguły Wazuh <small>(Ctrl = wiele)</small></label>
      <select id="sel-rule" multiple oninput="applyFilters()">{ru_options}</select>
    </div>
    <div class="fg">
      <label><input type="checkbox" id="only-fim" onchange="applyFilters()" style="width:auto;margin-right:5px">Tylko alerty FIM (syscheck)</label>
    </div>
    <button class="btn btn-clear"  onclick="clearFilters()">Wyczyść filtry</button>
    <button class="btn btn-export" onclick="exportCSV()">Pobierz CSV</button>
  </aside>

  <!-- Tabela -->
  <div class="main">
    <div class="stats-bar">
      <div class="stat">      <span class="num" id="cnt-all">0</span> <span class="lbl">Wyfiltrowanych</span></div>
      <div class="stat crit"> <span class="num" id="cnt-crit">0</span><span class="lbl">Krytycznych</span></div>
      <div class="stat high"> <span class="num" id="cnt-high">0</span><span class="lbl">Wysokich</span></div>
      <div class="stat med">  <span class="num" id="cnt-med">0</span> <span class="lbl">Średnich</span></div>
      <div class="stat low">  <span class="num" id="cnt-low">0</span> <span class="lbl">Niskich</span></div>
    </div>
    <div class="toolbar">
      <input type="text" id="search-desc" placeholder="Szukaj w opisie (brute, injection, sudo, /tmp...)..." oninput="applyFilters()">
      <span class="ps-label">Wyświetl
        <select id="page-size" onchange="changePageSize()">
          <option value="20">20</option>
          <option value="50" selected>50</option>
          <option value="100">100</option>
          <option value="500">500</option>
        </select> na stronę
      </span>
      <div class="pagination">
        <button id="btn-first" onclick="goPage(0)">«</button>
        <button id="btn-prev"  onclick="goPage(currentPage-1)">‹</button>
        <span class="pi" id="page-info">—</span>
        <button id="btn-next"  onclick="goPage(currentPage+1)">›</button>
        <button id="btn-last"  onclick="goPage(totalPages-1)">»</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th onclick="sortBy('timestamp')">Czas ↕</th>
          <th onclick="sortBy('level')">Lvl ↕</th>
          <th>Severity</th>
          <th onclick="sortBy('rule_id')">Reguła ↕</th>
          <th>Opis</th>
          <th onclick="sortBy('agent')">Agent ↕</th>
          <th onclick="sortBy('srcip')">IP źródłowe ↕</th>
          <th>User</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
      <div class="empty" id="empty-msg" style="display:none">Brak alertów spełniających kryteria.</div>
    </div>
    <div class="footer">
      <span id="footer-info">Ładowanie...</span>
      <span>Kliknij wiersz → szczegóły alertu &nbsp;·&nbsp; SOC Home Lab</span>
    </div>
  </div>

  <!-- Panel szczegółów -->
  <div class="detail-panel" id="detail-panel">
    <div class="dp-header">
      <h3 id="dp-title">Szczegóły alertu</h3>
      <button class="dp-close" onclick="closeDetail()">✕</button>
    </div>
    <div class="dp-body" id="dp-body"></div>
  </div>

</div>

<script>
const FULL  = {alerts_full_js};
const FLAT  = {flat_js};

const SEV = l => l>=13?['KRYTYCZNY','#e63946','critical']:l>=10?['WYSOKI','#f4a261','high']:l>=7?['ŚREDNI','#e9c46a','medium']:['NISKI','#90be6d','low'];

let filtered=[], filteredFull=[], sortKey='timestamp', sortDir=-1, currentPage=0, totalPages=1, selectedIdx=null;

function pageSize(){{ return +document.getElementById('page-size').value; }}
function getSelected(id){{ return [...document.getElementById(id).selectedOptions].map(o=>o.value); }}

function applyFilters(){{
  const lvlMin   = +document.getElementById('lvl-min').value||1;
  const lvlMax   = +document.getElementById('lvl-max').value||15;
  const dateFrom = document.getElementById('date-from').value;
  const dateTo   = document.getElementById('date-to').value;
  const ips      = getSelected('sel-ip');
  const agents   = getSelected('sel-agent');
  const rules    = getSelected('sel-rule');
  const search   = document.getElementById('search-desc').value.toLowerCase();
  const onlyFim  = document.getElementById('only-fim').checked;

  const idxs = [];
  FLAT.forEach((f,i)=>{{
    if(f.level<lvlMin||f.level>lvlMax) return;
    const d=f.timestamp.slice(0,10);
    if(dateFrom&&d<dateFrom) return;
    if(dateTo&&d>dateTo) return;
    if(ips.length&&!ips.includes(f.srcip)) return;
    if(agents.length&&!agents.includes(f.agent)) return;
    if(rules.length&&!rules.includes(f.rule_id)) return;
    if(search&&!f.description.toLowerCase().includes(search)&&
       !(FULL[i].syscheck?.path||'').toLowerCase().includes(search)) return;
    if(onlyFim&&!f.has_syscheck) return;
    idxs.push(i);
  }});

  filtered     = idxs.map(i=>FLAT[i]);
  filteredFull = idxs.map(i=>FULL[i]);
  sortAndRender(true);
}}

function sortBy(key){{
  if(sortKey===key) sortDir*=-1; else{{sortKey=key;sortDir=-1;}}
  sortAndRender(false);
}}

function changePageSize(){{ sortAndRender(true); }}
function goPage(p){{ currentPage=p; renderPage(); }}

function sortAndRender(reset){{
  const pairs = filtered.map((f,i)=>([f,filteredFull[i],i]));
  pairs.sort((a,b)=>{{
    const av=a[0][sortKey]??'', bv=b[0][sortKey]??'';
    return(typeof av==='number'?av-bv:av.localeCompare(bv))*sortDir;
  }});
  filtered     = pairs.map(p=>p[0]);
  filteredFull = pairs.map(p=>p[1]);
  if(reset) currentPage=0;
  totalPages = Math.max(1,Math.ceil(filtered.length/pageSize()));
  if(currentPage>=totalPages) currentPage=totalPages-1;
  updateStats();
  renderPage();
}}

function updateStats(){{
  document.getElementById('cnt-all').textContent  = filtered.length.toLocaleString();
  document.getElementById('cnt-crit').textContent = filtered.filter(f=>f.level>=13).length;
  document.getElementById('cnt-high').textContent = filtered.filter(f=>f.level>=10&&f.level<13).length;
  document.getElementById('cnt-med').textContent  = filtered.filter(f=>f.level>=7&&f.level<10).length;
  document.getElementById('cnt-low').textContent  = filtered.filter(f=>f.level<7).length;
}}

function renderPage(){{
  const ps=pageSize(), start=currentPage*ps;
  const pageFull = filteredFull.slice(start,start+ps);
  const pageFlat = filtered.slice(start,start+ps);
  const tbody=document.getElementById('tbody');
  const empty=document.getElementById('empty-msg');

  if(!filtered.length){{tbody.innerHTML='';empty.style.display='block';}}
  else{{
    empty.style.display='none';
    const globalOffset=start;
    tbody.innerHTML=pageFlat.map((f,i)=>{{
      const gi=globalOffset+i;
      const [sev,col]=SEV(f.level);
      const fim=f.has_syscheck?'<span class="fim-badge">FIM</span>':'';
      const sel=gi===selectedIdx?' selected':'';
      return `<tr class="${{sel}}" onclick="showDetail(${{gi}})">
        <td class="ts">${{f.timestamp}}</td>
        <td class="lvl" style="color:${{col}}">${{f.level}}</td>
        <td><span class="badge" style="background:${{col}}22;color:${{col}}">${{sev}}</span></td>
        <td style="font-family:monospace;color:#8b949e;font-size:11px">${{f.rule_id}}</td>
        <td class="desc">${{f.description}}${{fim}}</td>
        <td class="ag">${{f.agent}}</td>
        <td class="ip">${{f.srcip||'—'}}</td>
        <td style="color:#8b949e;font-size:11px">${{f.dstuser||'—'}}</td>
      </tr>`;
    }}).join('');
  }}

  const end=Math.min(start+ps,filtered.length);
  document.getElementById('page-info').textContent=filtered.length?`${{start+1}}–${{end}} / ${{filtered.length.toLocaleString()}}`:'0';
  document.getElementById('footer-info').textContent=`Strona ${{currentPage+1}} z ${{totalPages}} · ${{filtered.length.toLocaleString()}} z ${{FULL.length.toLocaleString()}} alertów`;
  document.getElementById('btn-first').disabled=currentPage===0;
  document.getElementById('btn-prev').disabled=currentPage===0;
  document.getElementById('btn-next').disabled=currentPage>=totalPages-1;
  document.getElementById('btn-last').disabled=currentPage>=totalPages-1;
}}

// ── Panel szczegółów ──────────────────────────────────────────────

function showDetail(idx){{
  selectedIdx=idx;
  const a=filteredFull[idx];
  const f=filtered[idx];
  if(!a) return;

  document.querySelectorAll('tbody tr').forEach((tr,i)=>{{
    const ps=pageSize(), start=currentPage*ps;
    tr.classList.toggle('selected', start+i===idx);
  }});

  const [sev,col,cls]=SEV(a.rule.level);
  document.getElementById('dp-title').textContent=`Alert #${{a.id||idx}}`;

  let html='';

  // Sekcja: reguła
  html+=`<div class="dp-section">
    <h4>Reguła Wazuh</h4>
    <div class="dp-row"><span class="dp-key">ID reguły</span><span class="dp-val">${{a.rule.id}}</span></div>
    <div class="dp-row"><span class="dp-key">Poziom</span><span class="dp-val ${{cls}}">${{a.rule.level}} — ${{sev}}</span></div>
    <div class="dp-row"><span class="dp-key">Opis</span><span class="dp-val" style="color:#f0f6fc;font-weight:500">${{a.rule.description}}</span></div>
    <div class="dp-row"><span class="dp-key">Grupy</span>
      <div class="groups-list">${{(a.rule.groups||[]).map(g=>`<span class="group-tag">${{g}}</span>`).join('')}}</div>
    </div>
  </div>`;

  // Sekcja: kontekst
  html+=`<div class="dp-section">
    <h4>Kontekst zdarzenia</h4>
    <div class="dp-row"><span class="dp-key">Czas</span><span class="dp-val">${{a.timestamp.replace('T',' ').slice(0,19)}}</span></div>
    <div class="dp-row"><span class="dp-key">Agent / host</span><span class="dp-val" style="color:#7ee787">${{a.agent.name}} (ID: ${{a.agent.id}})</span></div>
    <div class="dp-row"><span class="dp-key">Manager</span><span class="dp-val">${{a.manager?.name||'—'}}</span></div>`;

  if(a.data?.srcip)  html+=`<div class="dp-row"><span class="dp-key">IP źródłowe</span><span class="dp-val ip">${{a.data.srcip}}</span></div>`;
  if(a.data?.dstuser) html+=`<div class="dp-row"><span class="dp-key">Użytkownik</span><span class="dp-val">${{a.data.dstuser}}</span></div>`;
  if(a.data?.url)    html+=`<div class="dp-row"><span class="dp-key">URL</span><span class="dp-val path">${{a.data.url}}</span></div>`;
  if(a.data?.command) html+=`<div class="dp-row"><span class="dp-key">Komenda</span><span class="dp-val" style="color:#f4a261">${{a.data.command}}</span></div>`;
  html+=`</div>`;

  // Sekcja: syscheck (FIM) — najważniejsza część
  if(a.syscheck){{
    const sc=a.syscheck;
    const evtColor=sc.event==='added'?'#e63946':sc.event==='modified'?'#f4a261':'#90be6d';

    html+=`<div class="dp-section">
      <h4>File Integrity Monitor (syscheck)</h4>
      <div class="dp-row"><span class="dp-key">Plik</span><span class="dp-val path">${{sc.path}}</span></div>
      <div class="dp-row"><span class="dp-key">Zdarzenie</span><span class="dp-val" style="color:${{evtColor}};font-weight:500;text-transform:uppercase">${{sc.event}}</span></div>
      <div class="dp-row"><span class="dp-key">Tryb</span><span class="dp-val">${{sc.mode||'—'}}</span></div>`;

    if(sc.event==='modified'){{
      html+=`<div class="dp-row"><span class="dp-key">Rozmiar</span>
        <div class="diff-block">
          <div class="diff-before">- przed: ${{sc.size_before}} B</div>
          <div class="diff-after">+ po:    ${{sc.size_after}} B</div>
        </div>
      </div>`;

      html+=`<div class="dp-row"><span class="dp-key">Uprawnienia</span>
        <div class="diff-block">
          <div class="diff-before">- przed: ${{sc.perm_before||'—'}}</div>
          <div class="diff-after">+ po:    ${{sc.perm_after||'—'}}</div>
        </div>
      </div>`;

      html+=`<div class="dp-row"><span class="dp-key">Właściciel</span>
        <div class="diff-block">
          <div class="diff-before">- przed: ${{sc.uname_before}}:${{sc.gname_before}} (uid=${{sc.uid_before}})</div>
          <div class="diff-after">+ po:    ${{sc.uname_after}}:${{sc.gname_after}} (uid=${{sc.uid_after}})</div>
        </div>
      </div>`;

      html+=`<div class="dp-row"><span class="dp-key">Checksums (po)</span>
        <div class="hash-row">
          <div class="hash-line"><span>MD5 przed:</span>${{sc.md5_before}}</div>
          <div class="hash-line" style="color:#e63946"><span>MD5 po:   </span>${{sc.md5_after}}</div>
          <div class="hash-line"><span>SHA1 po:  </span>${{sc.sha1_after||'—'}}</div>
          <div class="hash-line"><span>SHA256 po:</span>${{(sc.sha256_after||'—').slice(0,32)}}...</div>
        </div>
      </div>`;

      if(sc.mtime_before){{
        html+=`<div class="dp-row"><span class="dp-key">Modyfikacja</span>
          <div class="diff-block">
            <div class="diff-before">- przed: ${{sc.mtime_before}}</div>
            <div class="diff-after">+ po:    ${{sc.mtime_after||'—'}}</div>
          </div>
        </div>`;
      }}
    }} else if(sc.event==='added'){{
      html+=`<div class="dp-row"><span class="dp-key">Rozmiar</span><span class="dp-val added">${{sc.size_after}} B (NOWY PLIK)</span></div>`;
      html+=`<div class="dp-row"><span class="dp-key">Uprawnienia</span><span class="dp-val ${{sc.perm_after?.includes('x')?'changed':''}}">${{sc.perm_after||'—'}}</span></div>`;
      html+=`<div class="dp-row"><span class="dp-key">Właściciel</span><span class="dp-val">${{sc.uname_after}}:${{sc.gname_after}} (uid=${{sc.uid_after}})</span></div>`;
      html+=`<div class="dp-row"><span class="dp-key">Checksums</span>
        <div class="hash-row">
          <div class="hash-line"><span>MD5:    </span>${{sc.md5_after}}</div>
          <div class="hash-line"><span>SHA1:   </span>${{sc.sha1_after||'—'}}</div>
          <div class="hash-line"><span>SHA256: </span>${{(sc.sha256_after||'—').slice(0,32)}}...</div>
        </div>
      </div>`;
      html+=`<div class="dp-row"><span class="dp-key">Inode</span><span class="dp-val">${{sc.inode_after||'—'}}</span></div>`;
    }}
    html+=`</div>`;
  }}

  // Surowy JSON na dole
  html+=`<div class="dp-section">
    <h4>Surowy JSON alertu</h4>
    <div class="json-block">${{JSON.stringify(a,null,2).replace(/</g,'&lt;').replace(/>/g,'&gt;')}}</div>
  </div>`;

  document.getElementById('dp-body').innerHTML=html;
  document.getElementById('detail-panel').classList.add('open');
}}

function closeDetail(){{
  document.getElementById('detail-panel').classList.remove('open');
  document.querySelectorAll('tbody tr').forEach(tr=>tr.classList.remove('selected'));
  selectedIdx=null;
}}

function clearFilters(){{
  document.getElementById('lvl-min').value=1;
  document.getElementById('lvl-max').value=15;
  document.getElementById('date-from').value='';
  document.getElementById('date-to').value='';
  document.getElementById('search-desc').value='';
  document.getElementById('only-fim').checked=false;
  ['sel-ip','sel-agent','sel-rule'].forEach(id=>
    [...document.getElementById(id).options].forEach(o=>o.selected=false));
  applyFilters();
}}

function exportCSV(){{
  const header='timestamp,level,severity,rule_id,description,agent,srcip,dstuser,syscheck_path,syscheck_event';
  const rows=filtered.map((f,i)=>{{
    const [sev]=SEV(f.level);
    const sc=filteredFull[i].syscheck||{{}};
    return[f.timestamp,f.level,sev,f.rule_id,
      '"'+f.description.replace(/"/g,'""')+'"',
      f.agent,f.srcip,f.dstuser,
      sc.path||'', sc.event||''].join(',');
  }});
  const blob=new Blob([[header,...rows].join('\\n')],{{type:'text/csv'}});
  const url=URL.createObjectURL(blob);
  Object.assign(document.createElement('a'),{{
    href:url, download:'alerty_'+new Date().toISOString().slice(0,16).replace(':','-')+'.csv'
  }}).click();
  URL.revokeObjectURL(url);
}}

applyFilters();
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="SOC Log Viewer — panel filtrów + szczegóły alertu")
    parser.add_argument("--input",  default="etap1_log_analyzer/sample_logs/wazuh_alerts.json")
    parser.add_argument("--db",     default=None)
    parser.add_argument("--output", default="soc_viewer.html")
    parser.add_argument("--open",   action="store_true")
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
        print("Brak alertów.")
        return

    print(f"Wczytano {len(alerts):,} alertów  "
          f"({sum(1 for a in alerts if 'syscheck' in a)} z polem syscheck)")

    html = generate_html(alerts, source)
    out  = Path(args.output)
    out.write_text(html, encoding="utf-8")
    print(f"Zapisano: {out}  ({out.stat().st_size // 1024} KB)")

    if args.open:
        webbrowser.open(out.resolve().as_uri())
    else:
        print(f"Otwórz: {out.resolve()}")


if __name__ == "__main__":
    main()
