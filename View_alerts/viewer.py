"""
SOC Log Viewer — interaktywny panel filtrów w przeglądarce
Obsługuje oba etapy: pliki JSON (Etap 1) i bazę SQLite (Etap 2)

Uruchomienie:
    pip install streamlit pandas
    streamlit run viewer.py

Otwiera się automatycznie na http://localhost:8501
"""

import json
import sqlite3
import glob
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st
import pandas as pd

# ──────────────────────────────────────────────
# Konfiguracja strony
# ──────────────────────────────────────────────

st.set_page_config(
    page_title="SOC Log Viewer",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .metric-card {
        background: #1e2329;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
        text-align: center;
    }
    .critical { border-left: 4px solid #e63946; }
    .high     { border-left: 4px solid #f4a261; }
    .medium   { border-left: 4px solid #e9c46a; }
    .low      { border-left: 4px solid #90be6d; }
    div[data-testid="stDataFrame"] { font-size: 13px; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Ładowanie danych
# ──────────────────────────────────────────────

@st.cache_data(ttl=30)
def load_from_json(filepath: str) -> pd.DataFrame:
    """Wczytuje alerty z pliku JSON (Etap 1)."""
    rows = []
    path = Path(filepath)
    if not path.exists():
        return pd.DataFrame()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                rows.append({
                    "id":          a.get("id", ""),
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
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


@st.cache_data(ttl=15)
def load_from_sqlite(db_path: str) -> pd.DataFrame:
    """Wczytuje alerty z bazy SQLite (Etap 2)."""
    path = Path(db_path)
    if not path.exists():
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query(
            """SELECT id, timestamp, level, rule_id, description,
                      groups, agent_name as agent, srcip, dstuser
               FROM alerts ORDER BY timestamp DESC""",
            conn,
        )
        conn.close()
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df
    except Exception as e:
        st.error(f"Błąd bazy SQLite: {e}")
        return pd.DataFrame()


def severity_label(level: int) -> str:
    if level >= 13: return "KRYTYCZNY"
    if level >= 10: return "WYSOKI"
    if level >= 7:  return "ŚREDNI"
    return "NISKI"

def severity_color(level: int) -> str:
    if level >= 13: return "🔴"
    if level >= 10: return "🟠"
    if level >= 7:  return "🟡"
    return "🟢"


# ──────────────────────────────────────────────
# Sidebar — źródło danych
# ──────────────────────────────────────────────

with st.sidebar:
    st.title("🛡 SOC Log Viewer")
    st.markdown("---")

    source_type = st.radio(
        "Źródło danych",
        ["Plik JSON (Etap 1)", "Baza SQLite (Etap 2)"],
        index=0,
    )

    if source_type == "Plik JSON (Etap 1)":
        # Znajdź dostępne pliki JSON
        json_files = sorted(glob.glob("**/*.json", recursive=True))
        json_files += sorted(glob.glob("*.json"))
        json_files = list(dict.fromkeys(json_files))  # deduplikacja

        if json_files:
            selected_file = st.selectbox("Plik logów", json_files)
        else:
            selected_file = st.text_input(
                "Ścieżka do pliku JSON",
                value="etap1_log_analyzer/sample_logs/wazuh_alerts.json",
            )

        if st.button("Odśwież dane", use_container_width=True):
            st.cache_data.clear()

        df_raw = load_from_json(selected_file)

    else:
        db_files = sorted(glob.glob("**/*.db", recursive=True)) + sorted(glob.glob("*.db"))
        db_files = list(dict.fromkeys(db_files))

        if db_files:
            selected_db = st.selectbox("Baza danych", db_files)
        else:
            selected_db = st.text_input(
                "Ścieżka do bazy SQLite",
                value="etap2_wazuh_api/alerts.db",
            )

        auto_refresh = st.toggle("Auto-odświeżanie (co 15s)", value=False)
        if auto_refresh:
            st.cache_data.clear()

        if st.button("Odśwież teraz", use_container_width=True):
            st.cache_data.clear()

        df_raw = load_from_sqlite(selected_db)

    st.markdown("---")

    # ── Panel filtrów ──────────────────────────

    st.subheader("Filtry")

    if df_raw.empty:
        st.warning("Brak danych. Sprawdź ścieżkę do pliku.")
        st.stop()

    # Poziom ryzyka
    level_range = st.slider(
        "Poziom ryzyka (Wazuh 1–15)",
        min_value=1,
        max_value=15,
        value=(1, 15),
        step=1,
    )

    # Zakres dat
    if not df_raw["timestamp"].isna().all():
        ts_min = df_raw["timestamp"].min().date()
        ts_max = df_raw["timestamp"].max().date()
    else:
        ts_min = ts_max = datetime.today().date()

    date_from = st.date_input("Od daty", value=ts_min, min_value=ts_min, max_value=ts_max)
    date_to   = st.date_input("Do daty", value=ts_max, min_value=ts_min, max_value=ts_max)

    # IP atakującego
    all_ips = sorted(df_raw["srcip"].dropna().unique().tolist())
    all_ips = [ip for ip in all_ips if ip]
    selected_ips = st.multiselect(
        "IP atakującego",
        options=all_ips,
        placeholder="Wszystkie IP...",
    )

    # Agent (host)
    all_agents = sorted(df_raw["agent"].dropna().unique().tolist())
    selected_agents = st.multiselect(
        "Agent (host)",
        options=all_agents,
        placeholder="Wszystkie hosty...",
    )

    # ID reguły
    all_rules = sorted(df_raw["rule_id"].dropna().unique().tolist())
    selected_rules = st.multiselect(
        "ID reguły Wazuh",
        options=all_rules,
        placeholder="Wszystkie reguły...",
    )

    # Szukanie w opisie
    search_text = st.text_input(
        "Szukaj w opisie alertu",
        placeholder="np. brute, injection, sudo...",
    )

    st.markdown("---")
    if st.button("Wyczyść filtry", use_container_width=True):
        st.rerun()


# ──────────────────────────────────────────────
# Filtrowanie
# ──────────────────────────────────────────────

df = df_raw.copy()

# Poziom
df = df[(df["level"] >= level_range[0]) & (df["level"] <= level_range[1])]

# Daty
df = df[
    (df["timestamp"].dt.date >= date_from) &
    (df["timestamp"].dt.date <= date_to)
]

# IP
if selected_ips:
    df = df[df["srcip"].isin(selected_ips)]

# Agenci
if selected_agents:
    df = df[df["agent"].isin(selected_agents)]

# Reguły
if selected_rules:
    df = df[df["rule_id"].isin(selected_rules)]

# Tekst w opisie
if search_text:
    df = df[df["description"].str.contains(search_text, case=False, na=False)]

# Dodaj kolumnę severity
df["severity"] = df["level"].apply(lambda l: f"{severity_color(l)} {severity_label(l)}")


# ──────────────────────────────────────────────
# Nagłówek i metryki
# ──────────────────────────────────────────────

st.title("SOC Log Viewer")

filtered_pct = f"{len(df) / max(len(df_raw), 1) * 100:.0f}%"
st.caption(
    f"Wyświetlono **{len(df):,}** z **{len(df_raw):,}** alertów ({filtered_pct}) "
    f"— źródło: `{selected_file if source_type == 'Plik JSON (Etap 1)' else selected_db}`"
)

# Liczniki severity
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Wszystkich", f"{len(df):,}")
with col2:
    n = len(df[df["level"] >= 13])
    st.metric("🔴 Krytycznych", n, delta=None if n == 0 else f"poziom ≥13")
with col3:
    n = len(df[(df["level"] >= 10) & (df["level"] < 13)])
    st.metric("🟠 Wysokich", n)
with col4:
    n = len(df[(df["level"] >= 7) & (df["level"] < 10)])
    st.metric("🟡 Średnich", n)
with col5:
    n = len(df[df["level"] < 7])
    st.metric("🟢 Niskich", n)

st.markdown("---")


# ──────────────────────────────────────────────
# Główna tabela
# ──────────────────────────────────────────────

tab_table, tab_stats, tab_timeline = st.tabs(["Tabela alertów", "Statystyki", "Timeline"])

with tab_table:
    sort_col = st.selectbox(
        "Sortuj po",
        ["timestamp", "level", "agent", "srcip", "rule_id"],
        index=0,
        horizontal=True,
    ) if not df.empty else "timestamp"

    sort_asc = st.radio("Kierunek", ["Malejąco", "Rosnąco"], horizontal=True) == "Rosnąco"

    if not df.empty:
        df_show = (
            df[["timestamp", "severity", "level", "rule_id",
                "description", "agent", "srcip", "dstuser"]]
            .sort_values(sort_col, ascending=sort_asc)
            .reset_index(drop=True)
        )
        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

        st.dataframe(
            df_show,
            use_container_width=True,
            height=520,
            column_config={
                "timestamp":   st.column_config.TextColumn("Czas", width=160),
                "severity":    st.column_config.TextColumn("Severity", width=130),
                "level":       st.column_config.NumberColumn("Lvl", width=55),
                "rule_id":     st.column_config.TextColumn("Reguła", width=75),
                "description": st.column_config.TextColumn("Opis", width=350),
                "agent":       st.column_config.TextColumn("Agent", width=170),
                "srcip":       st.column_config.TextColumn("IP źródłowe", width=140),
                "dstuser":     st.column_config.TextColumn("User", width=100),
            },
            hide_index=True,
        )

        # Eksport CSV
        csv = df_show.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Pobierz CSV",
            data=csv,
            file_name=f"alerty_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
        )
    else:
        st.info("Brak alertów spełniających kryteria filtrów.")

with tab_stats:
    if df.empty:
        st.info("Brak danych do statystyk.")
    else:
        col_l, col_r = st.columns(2)

        with col_l:
            st.subheader("Top 10 reguł")
            top_rules = (
                df.groupby(["rule_id", "description"])
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
                .head(10)
            )
            top_rules["label"] = top_rules["rule_id"] + " — " + top_rules["description"].str[:40]
            st.bar_chart(top_rules.set_index("label")["count"])

        with col_r:
            st.subheader("Top 10 atakujących IP")
            top_ips = (
                df[df["srcip"].notna() & (df["srcip"] != "")]
                .groupby("srcip")
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
                .head(10)
            )
            st.bar_chart(top_ips.set_index("srcip")["count"])

        col_l2, col_r2 = st.columns(2)

        with col_l2:
            st.subheader("Rozkład poziomów")
            level_dist = (
                df.groupby("level")
                .size()
                .reset_index(name="count")
                .sort_values("level")
            )
            st.bar_chart(level_dist.set_index("level")["count"])

        with col_r2:
            st.subheader("Top 10 agentów")
            top_agents = (
                df.groupby("agent")
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
                .head(10)
            )
            st.bar_chart(top_agents.set_index("agent")["count"])

with tab_timeline:
    if df.empty:
        st.info("Brak danych do wykresu.")
    else:
        st.subheader("Liczba alertów w czasie")

        # Grupuj po godzinie
        df_time = df.copy()
        df_time["hour"] = df_time["timestamp"].dt.floor("h")
        timeline = (
            df_time.groupby("hour")
            .size()
            .reset_index(name="count")
            .sort_values("hour")
        )
        st.line_chart(timeline.set_index("hour")["count"])

        st.subheader("Aktywność wg godziny doby")
        df_time["hour_of_day"] = df_time["timestamp"].dt.hour
        heatmap = (
            df_time[df_time["level"] >= 7]
            .groupby("hour_of_day")
            .size()
            .reset_index(name="count")
        )
        # Uzupełnij brakujące godziny zerami
        all_hours = pd.DataFrame({"hour_of_day": range(24)})
        heatmap = all_hours.merge(heatmap, on="hour_of_day", how="left").fillna(0)
        heatmap["count"] = heatmap["count"].astype(int)
        st.bar_chart(heatmap.set_index("hour_of_day")["count"])
        st.caption("Tylko alerty o poziomie ≥7")
