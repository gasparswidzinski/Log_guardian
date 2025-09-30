
# app.py — Log Guardian Dashboard (Streamlit)
# Run: streamlit run app.py

from __future__ import annotations
import io
import pandas as pd
import streamlit as st
import altair as alt
from datetime import date

st.set_page_config(page_title="Log Guardian • Dashboard", layout="wide")
st.title("Log Guardian • Dashboard")
st.caption("Visualizá y filtrá los hallazgos generados por Log Guardian (findings.csv).")

# Sidebar — data source
st.sidebar.header("Origen de datos")
uploaded = st.sidebar.file_uploader("Subí un findings.csv", type=["csv"])
path = st.sidebar.text_input("Ruta local (opcional)", "./out/findings.csv")

@st.cache_data(show_spinner=False)
def load_csv_from_bytes(b: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(b))

@st.cache_data(show_spinner=False)
def load_csv_from_path(p: str) -> pd.DataFrame:
    return pd.read_csv(p)

df = None
load_error = None
if uploaded is not None:
    try:
        df = load_csv_from_bytes(uploaded.getvalue())
    except Exception as e:
        load_error = f"No pude leer el CSV subido: {e}"
elif path:
    try:
        df = load_csv_from_path(path)
    except Exception as e:
        load_error = f"No pude leer el archivo en '{path}': {e}"

if df is None:
    st.info("Subí un **findings.csv** o indicá la **ruta local** en la barra lateral para comenzar.")
    if load_error:
        st.error(load_error)
    st.stop()

# Validate / normalize
expected_cols = ["timestamp","rule","severity","user","src_ip","host","message"]
missing = [c for c in expected_cols if c not in df.columns]
if missing:
    st.error(f"Faltan columnas en el CSV: {missing}. Columnas esperadas: {expected_cols}")
    st.stop()

df = df.copy()
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=False)
df["date"] = df["timestamp"].dt.date

# Sidebar — filters
st.sidebar.header("Filtros")
min_d = df["date"].min() if not df["date"].isna().all() else date.today()
max_d = df["date"].max() if not df["date"].isna().all() else date.today()
if min_d and max_d:
    start_d, end_d = st.sidebar.date_input("Rango de fechas", value=(min_d, max_d), min_value=min_d, max_value=max_d)
else:
    start_d = end_d = None

rules = ["(todas)"] + sorted([x for x in df["rule"].dropna().unique()])
severities = ["(todas)"] + sorted([x for x in df["severity"].dropna().unique()])
hosts = ["(todos)"] + sorted([x for x in df["host"].dropna().unique()])
users = ["(todos)"] + sorted([x for x in df["user"].dropna().unique()])
ips = ["(todas)"] + sorted([x for x in df["src_ip"].dropna().unique()])

c1, c2 = st.sidebar.columns(2)
rule_sel = c1.selectbox("Regla", rules, index=0)
sev_sel = c2.selectbox("Severidad", severities, index=0)
host_sel = st.sidebar.selectbox("Host", hosts, index=0)
user_sel = st.sidebar.selectbox("Usuario", users, index=0)
ip_sel = st.sidebar.selectbox("IP", ips, index=0)

# Apply filters
q = df.copy()
if start_d and end_d:
    q = q[(q["date"] >= start_d) & (q["date"] <= end_d)]
if rule_sel != "(todas)":
    q = q[q["rule"] == rule_sel]
if sev_sel != "(todas)":
    q = q[q["severity"] == sev_sel]
if host_sel != "(todos)":
    q = q[q["host"] == host_sel]
if user_sel != "(todos)":
    q = q[q["user"] == user_sel]
if ip_sel != "(todas)":
    q = q[q["src_ip"] == ip_sel]

# KPIs
k1, k2, k3, k4 = st.columns(4)
k1.metric("Eventos cargados", len(df))
k2.metric("Hallazgos filtrados", len(q))
k3.metric("Usuarios únicos", int(q["user"].nunique()))
k4.metric("Hosts únicos", int(q["host"].nunique()))

# Charts
if not q["timestamp"].isna().all():
    ts = q.copy()
    ts["hour"] = ts["timestamp"].dt.floor("h")
    ts_count = ts.groupby("hour").size().reset_index(name="count")
    chart_ts = alt.Chart(ts_count).mark_line(point=True).encode(
        x=alt.X("hour:T", title="Hora"),
        y=alt.Y("count:Q", title="Hallazgos"),
        tooltip=["hour:T", "count:Q"],
    ).properties(height=250)
    st.subheader("Serie temporal")
    st.altair_chart(chart_ts, use_container_width=True)

grp = q.groupby(["rule","severity"]).size().reset_index(name="count")
if not grp.empty:
    st.subheader("Distribución por regla/severidad")
    chart_bar = alt.Chart(grp).mark_bar().encode(
        x=alt.X("rule:N", title="Regla"),
        y=alt.Y("count:Q", title="Hallazgos"),
        color="severity:N",
        column=alt.Column("severity:N", header=alt.Header(title="Severidad")),
        tooltip=["rule:N", "severity:N", "count:Q"],
    ).resolve_scale(x="independent").properties(height=250)
    st.altair_chart(chart_bar, use_container_width=True)

# Table + Download
st.subheader("Resultados")
show_cols = ["timestamp","rule","severity","user","src_ip","host","message"]
st.dataframe(q[show_cols].sort_values("timestamp", ascending=False), use_container_width=True)

csv_bytes = q[show_cols].to_csv(index=False).encode("utf-8")
st.download_button("Descargar CSV filtrado", data=csv_bytes, file_name="findings_filtered.csv", mime="text/csv")

st.caption("Tip: Ejecutá el analizador y después levantá este dashboard para una demo rápida.")
