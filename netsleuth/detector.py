"""Rule-based network traffic analysis for NetSleuth.

This is a learning/demo detector, not a replacement for a production IDS.
It analyzes exported connection records and does not capture network traffic.
"""
from __future__ import annotations
import pandas as pd

REQUIRED_COLUMNS = {
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes", "duration_seconds", "status"
}

def validate_traffic(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and normalize an uploaded traffic table."""
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    numeric = ["src_port", "dst_port", "bytes", "duration_seconds"]
    for col in numeric:
        out[col] = pd.to_numeric(out[col], errors="coerce")
    out["src_ip"] = out["src_ip"].astype("string").str.strip()
    out["dst_ip"] = out["dst_ip"].astype("string").str.strip()
    out["protocol"] = out["protocol"].astype("string").str.upper().str.strip()
    out["status"] = out["status"].astype("string").str.lower().str.strip()
    out = out.dropna(subset=["timestamp", "src_ip", "dst_ip", *numeric])
    out = out[(out["src_port"].between(0, 65535)) & (out["dst_port"].between(0, 65535))]
    out = out[(out["bytes"] >= 0) & (out["duration_seconds"] >= 0)]
    return out.sort_values("timestamp").reset_index(drop=True)

def detect_threats(
    traffic: pd.DataFrame,
    port_scan_threshold: int = 8,
    connection_burst_threshold: int = 25,
    large_transfer_bytes: int = 5_000_000,
) -> pd.DataFrame:
    """Apply transparent heuristic rules and return one row per alert."""
    df = validate_traffic(traffic)
    alerts = []

    # Many distinct destination ports from one source can indicate scanning.
    ports = df.groupby("src_ip")["dst_port"].nunique()
    for src, count in ports.items():
        if count >= port_scan_threshold:
            rows = df[df["src_ip"] == src]
            alerts.append({
                "timestamp": rows["timestamp"].max(), "severity": "High",
                "rule": "Possible port scan", "src_ip": src,
                "evidence": f"{count} unique destination ports observed",
                "recommendation": "Review source activity and confirm whether scanning was authorized."
            })

    # Many records from one source can indicate a connection burst.
    counts = df.groupby("src_ip").size()
    for src, count in counts.items():
        if count >= connection_burst_threshold:
            rows = df[df["src_ip"] == src]
            alerts.append({
                "timestamp": rows["timestamp"].max(), "severity": "Medium",
                "rule": "Connection burst", "src_ip": src,
                "evidence": f"{count} connections in the uploaded dataset",
                "recommendation": "Check the time window and destination distribution for abnormal activity."
            })

    # Large individual transfers deserve review, but are not inherently malicious.
    large = df[df["bytes"] >= large_transfer_bytes]
    for _, row in large.iterrows():
        alerts.append({
            "timestamp": row["timestamp"], "severity": "Medium",
            "rule": "Large data transfer", "src_ip": row["src_ip"],
            "evidence": f"{int(row['bytes']):,} bytes to {row['dst_ip']}:{int(row['dst_port'])}",
            "recommendation": "Verify the destination and whether the transfer was expected."
        })

    columns = ["timestamp", "severity", "rule", "src_ip", "evidence", "recommendation"]
    if not alerts:
        return pd.DataFrame(columns=columns)
    result = pd.DataFrame(alerts, columns=columns)
    rank = {"High": 0, "Medium": 1, "Low": 2}
    result["_rank"] = result["severity"].map(rank)
    return result.sort_values(["_rank", "timestamp"], ascending=[True, False]).drop(columns="_rank").reset_index(drop=True)
