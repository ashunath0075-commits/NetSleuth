"""Create safe, synthetic network-connection records for the demo."""
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(17)
out = Path("data/sample_traffic.csv")
out.parent.mkdir(exist_ok=True)
start = datetime.now(timezone.utc) - timedelta(hours=2)
rows = []
normal_sources = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.20"]
destinations = ["10.0.0.5", "10.0.0.8", "10.0.0.12", "10.0.0.25"]
ports = [53, 80, 123, 443, 445, 8080]
for i in range(150):
    ts = start + timedelta(seconds=i * 35 + random.randint(0, 12))
    src = random.choice(normal_sources)
    rows.append({
        "timestamp": ts.isoformat(), "src_ip": src,
        "dst_ip": random.choice(destinations), "src_port": random.randint(49152, 65535),
        "dst_port": random.choice(ports), "protocol": random.choice(["TCP", "TCP", "UDP"]),
        "bytes": random.randint(200, 180000), "duration_seconds": round(random.uniform(0.01, 8), 3),
        "status": random.choice(["allowed", "allowed", "allowed", "blocked"])
    })

# Synthetic scan pattern: one host touches many destination ports.
for j, port in enumerate([20, 21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]):
    ts = start + timedelta(minutes=75, seconds=j * 3)
    rows.append({
        "timestamp": ts.isoformat(), "src_ip": "192.168.1.99",
        "dst_ip": "10.0.0.5", "src_port": 52000 + j, "dst_port": port,
        "protocol": "TCP", "bytes": random.randint(60, 500),
        "duration_seconds": round(random.uniform(0.01, 0.2), 3), "status": "blocked"
    })

# Synthetic high-volume source and a large transfer for visible dashboard alerts.
for j in range(28):
    ts = start + timedelta(minutes=95, seconds=j * 2)
    rows.append({
        "timestamp": ts.isoformat(), "src_ip": "192.168.1.77",
        "dst_ip": "10.0.0.25", "src_port": 53000 + j,
        "dst_port": 443, "protocol": "TCP", "bytes": random.randint(1000, 9000),
        "duration_seconds": round(random.uniform(0.1, 2.5), 3), "status": "allowed"
    })
rows.append({
    "timestamp": (start + timedelta(minutes=100)).isoformat(),
    "src_ip": "192.168.1.20", "dst_ip": "10.0.0.25",
    "src_port": 54001, "dst_port": 443, "protocol": "TCP",
    "bytes": 7200000, "duration_seconds": 14.8, "status": "allowed"
})
rows.sort(key=lambda r: r["timestamp"])
with out.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
print(f"Created {len(rows)} synthetic records at {out}")
