import pandas as pd
from netsleuth.detector import detect_threats, validate_traffic

def sample(rows):
    return pd.DataFrame(rows, columns=[
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "bytes", "duration_seconds", "status"
    ])

def test_detects_possible_port_scan():
    rows = []
    for i, port in enumerate([21, 22, 23, 25]):
        rows.append([f"2026-01-01T00:00:0{i}Z", "192.0.2.10", "198.51.100.5",
                     50000+i, port, "TCP", 100, 0.1, "blocked"])
    alerts = detect_threats(sample(rows), port_scan_threshold=4, connection_burst_threshold=50)
    assert "Possible port scan" in alerts["rule"].tolist()

def test_large_transfer_alert():
    df = sample([["2026-01-01T00:00:00Z", "192.0.2.2", "198.51.100.8",
                  50001, 443, "TCP", 6_000_000, 10, "allowed"]])
    alerts = detect_threats(df, large_transfer_bytes=5_000_000)
    assert "Large data transfer" in alerts["rule"].tolist()

def test_validation_drops_invalid_timestamp():
    df = sample([["not-a-date", "192.0.2.2", "198.51.100.8",
                  50001, 443, "TCP", 500, 1, "allowed"]])
    assert validate_traffic(df).empty
