from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from netsleuth.detector import detect_threats, validate_traffic

st.set_page_config(page_title="NetSleuth | Network Security", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
    .block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
    div[data-testid="stMetric"] {background: #101827; border: 1px solid #24334b; padding: 14px; border-radius: 12px;}
    .small-note {color: #94a3b8; font-size: 0.88rem;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ NetSleuth")
st.caption("NETWORK TRAFFIC ANALYSIS · RULE-BASED THREAT TRIAGE")
st.markdown("Review connection records, identify unusual patterns, and export an investigation snapshot.")

with st.sidebar:
    st.header("Analysis settings")
    st.markdown("**Detection thresholds**")
    scan_threshold = st.slider("Unique ports for possible scan", 3, 30, 8)
    burst_threshold = st.slider("Connections per source for burst", 10, 100, 25)
    large_bytes = st.number_input("Large transfer threshold (bytes)", min_value=100_000, max_value=100_000_000, value=5_000_000, step=500_000)
    st.divider()
    uploaded = st.file_uploader("Upload traffic CSV", type=["csv"])
    st.caption("Expected fields are documented in README.md.")

sample_path = Path("data/sample_traffic.csv")
if uploaded is not None:
    try:
        raw = pd.read_csv(uploaded)
        traffic = validate_traffic(raw)
    except Exception as exc:
        st.error(f"Could not read this traffic file: {exc}")
        st.stop()
    source_label = f"Uploaded: {uploaded.name}"
else:
    if not sample_path.exists():
        st.warning("Sample data not found. Run `python generate_sample_data.py` from the project folder.")
        st.stop()
    try:
        traffic = validate_traffic(pd.read_csv(sample_path))
    except Exception as exc:
        st.error(f"Sample data could not be loaded: {exc}")
        st.stop()
    source_label = "Built-in synthetic sample"

alerts = detect_threats(traffic, scan_threshold, burst_threshold, int(large_bytes))
st.markdown(f"<div class='small-note'>Data source: {source_label} · {len(traffic):,} valid records</div>", unsafe_allow_html=True)
st.write("")

high = int((alerts["severity"] == "High").sum()) if not alerts.empty else 0
medium = int((alerts["severity"] == "Medium").sum()) if not alerts.empty else 0
unique_sources = int(traffic["src_ip"].nunique())
blocked = int((traffic["status"] == "blocked").sum())

m1, m2, m3, m4 = st.columns(4)
m1.metric("Traffic records", f"{len(traffic):,}")
m2.metric("High-severity alerts", high)
m3.metric("Medium-severity alerts", medium)
m4.metric("Unique source hosts", unique_sources)

left, right = st.columns([1.35, 1])
with left:
    st.subheader("Traffic over time")
    timeline = traffic.set_index("timestamp").resample("10min").size().rename("Connections").reset_index()
    fig = px.line(timeline, x="timestamp", y="Connections", markers=True, template="plotly_dark")
    fig.update_layout(margin=dict(l=10, r=10, t=15, b=10), xaxis_title="Time (UTC)", yaxis_title="Connections")
    st.plotly_chart(fig, use_container_width=True)
with right:
    st.subheader("Connection status")
    status_counts = traffic["status"].value_counts().rename_axis("Status").reset_index(name="Count")
    fig = px.pie(status_counts, names="Status", values="Count", hole=0.58, template="plotly_dark")
    fig.update_layout(margin=dict(l=10, r=10, t=15, b=10), legend_title="")
    st.plotly_chart(fig, use_container_width=True)

left2, right2 = st.columns(2)
with left2:
    st.subheader("Top source hosts")
    top_sources = traffic["src_ip"].value_counts().head(10).rename_axis("Source IP").reset_index(name="Connections")
    fig = px.bar(top_sources, x="Connections", y="Source IP", orientation="h", template="plotly_dark")
    fig.update_layout(yaxis={"categoryorder": "total ascending"}, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)
with right2:
    st.subheader("Most-targeted destination ports")
    top_ports = traffic["dst_port"].value_counts().head(10).rename_axis("Destination port").reset_index(name="Connections")
    fig = px.bar(top_ports, x="Destination port", y="Connections", template="plotly_dark")
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)

st.divider()
st.subheader("🚨 Detection alerts")
if alerts.empty:
    st.success("No alerts matched the current rules and thresholds.")
else:
    sev_filter = st.multiselect("Filter severity", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
    visible = alerts[alerts["severity"].isin(sev_filter)]
    st.dataframe(visible, use_container_width=True, hide_index=True,
                 column_config={"timestamp": st.column_config.DatetimeColumn("Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss")})
    st.download_button("Download alerts CSV", visible.to_csv(index=False).encode("utf-8"),
                       file_name="netsleuth_alerts.csv", mime="text/csv")
    report = [
        "# NetSleuth Investigation Report", "",
        f"- Data source: {source_label}",
        f"- Valid traffic records: {len(traffic)}",
        f"- Alerts generated: {len(alerts)}",
        f"- High severity: {high}",
        f"- Medium severity: {medium}", "",
        "> These findings are heuristic indicators, not proof of malicious activity.", "",
        alerts.to_markdown(index=False)
    ]
    st.download_button("Download report (Markdown)", "\n".join(report).encode("utf-8"),
                       file_name="netsleuth_report.md", mime="text/markdown")

with st.expander("View normalized traffic records"):
    st.dataframe(traffic, use_container_width=True, hide_index=True)

st.caption("NetSleuth is an educational triage tool. Validate alerts with context before taking action; benign behavior can trigger rules.")
