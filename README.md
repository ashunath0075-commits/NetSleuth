# NetSleuth 🛡️
**Rule-based network traffic analysis and threat triage dashboard**

NetSleuth is a Python + Streamlit portfolio project that analyzes exported network connection records, flags unusual patterns with transparent heuristic rules, visualizes traffic, and exports findings for review.

> **Scope:** This project analyzes CSV records. It does not capture live traffic, block connections, or prove that a host is compromised. Alerts are indicators for human investigation.

## Features
- CSV upload and input validation
- Possible port-scan heuristic based on unique destination ports per source
- Connection-burst heuristic based on total records per source
- Large-transfer review rule
- Interactive charts for traffic timeline, connection status, top sources, and destination ports
- Severity filters and CSV / Markdown report export
- Synthetic sample data and automated tests

## Quick start (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python generate_sample_data.py
streamlit run app.py
```
Open the local URL printed in the terminal, usually `http://localhost:8501`.

If PowerShell blocks virtual-environment activation, run commands with the environment's interpreter:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## CSV schema
Required columns:
- `timestamp` (ISO date/time recommended)
- `src_ip`, `dst_ip`
- `src_port`, `dst_port` (0–65535)
- `protocol` (for example TCP or UDP)
- `bytes` (non-negative)
- `duration_seconds` (non-negative)
- `status` (for example allowed or blocked)

## Detection logic
1. **Possible port scan:** one source connects to at least the configured number of distinct destination ports.
2. **Connection burst:** one source has at least the configured number of records in the uploaded dataset.
3. **Large data transfer:** an individual record meets the configured byte threshold.

These baseline rules intentionally favor explainability. They may produce false positives and should be calibrated against representative, authorized data. The connection-burst rule currently uses the entire uploaded dataset, not a rolling time window.

## Tests
```powershell
python -m pytest -q
```

## Project structure
```text
NetSleuth/
├── app.py
├── generate_sample_data.py
├── requirements.txt
├── README.md
├── .gitignore
├── netsleuth/
│   ├── __init__.py
│   └── detector.py
├── data/
│   └── sample_traffic.csv
└── tests/
    └── test_detector.py
```

## Next improvements
- Use a rolling time window for connection-rate detection
- Parse authorized Zeek or firewall exports
- Add configurable allowlists and alert deduplication
- Add JSON export and a CI workflow
- Compare results against a labeled public intrusion-detection dataset

## Resume bullet (adjust to match what you have tested)
**NetSleuth | Python, Pandas, Streamlit, Plotly, Pytest**  
Built a network traffic triage dashboard with rule-based detection for possible port scans, connection bursts, and large transfers; added interactive visualizations, CSV report exports, input validation, synthetic test data, and automated tests.
