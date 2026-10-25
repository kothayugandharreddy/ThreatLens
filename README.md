# ThreatLens — Round 2 Prototype

AI-driven passive threat detection for one-way (data-diode) IP traffic.

## What this prototype demonstrates
- Strict read-only simulated/PCAP-style streaming input
- Incremental flow/window feature extraction
- Six threat families: DDoS, C2 beaconing, DGA/DNS tunnelling, encrypted-session anomaly, reconnaissance/port scan, data exfiltration
- Hybrid detection: statistical/rule scores + ML anomaly/classification components
- Standardized alerts with timestamp, flow_id, threat_class, severity, confidence and evidence
- Live dashboard with replay controls, threat counts, latency and throughput
- No probes, handshakes, payload decryption, blocking, or return-path action

## Run
```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app/main.py
```

## Demo
1. Open the dashboard.
2. Select **Attack Scenario**.
3. Start the stream.
4. Watch live flow rate and alerts.
5. Open an alert to show evidence.
6. Change to **Benign** and show the detector settling down.

## Architecture
Traffic replay -> read-only ingest -> rolling feature windows -> hybrid detectors -> standardized alerts -> dashboard.

## Important scope statement
This is a hackathon prototype using synthetic/replayed flow metadata. TLS/QUIC detection uses metadata-style features only; no payload is decrypted. The prototype does not send any traffic or mitigation command back to a source.

## Benchmark
The dashboard measures observed flows/sec and detection latency. For the final report/video, record the actual values produced on the demo machine rather than claiming unmeasured performance.
