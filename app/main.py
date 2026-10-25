import time, math, random
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="wide")

# ---------- Lightweight synthetic training ----------
@st.cache_resource
def train_models():
    rng = np.random.default_rng(42)

    # DGA-like classifier trained on synthetic lexical statistics.
    X_b, X_d = [], []
    for _ in range(500):
        X_b.append([rng.normal(3.0,.35), rng.normal(18,4), rng.normal(.28,.08),
                    rng.normal(.20,.06)])
        X_d.append([rng.normal(4.6,.35), rng.normal(31,6), rng.normal(.48,.08),
                    rng.normal(.40,.08)])
    X = np.array(X_b + X_d)
    y = np.array([0]*len(X_b) + [1]*len(X_d))
    dga = RandomForestClassifier(n_estimators=80, random_state=42)
    dga.fit(X, y)

    # Generic anomaly model for flow behaviour.
    normal = rng.normal(loc=[80, 12000, 4, 2, .55],
                         scale=[25, 4000, 2, 1, .15], size=(1200,5))
    anomaly = IsolationForest(n_estimators=100, contamination=.08, random_state=42)
    anomaly.fit(normal)
    return dga, anomaly

DGA_MODEL, ANOMALY_MODEL = train_models()

THREATS = ["DDoS", "C2 Beaconing", "DGA / DNS Tunnelling",
           "Encrypted Session Anomaly", "Recon / Port Scan", "Data Exfiltration"]

def entropy(values):
    if not values: return 0.0
    _, counts = np.unique(values, return_counts=True)
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())

def make_flow(scenario, i):
    rng = random.Random(1000 + i)
    src = f"10.10.{rng.randint(1,20)}.{rng.randint(2,254)}"
    dst = f"10.20.{rng.randint(1,8)}.{rng.randint(2,254)}"
    sport = rng.randint(1024,65535)
    dport = rng.choice([53,80,443,22,123,445,8080,3389,4444,31337])
    proto = rng.choice(["TCP","UDP"])
    packet_count = rng.randint(8,90)
    bytes_out = rng.randint(800,30000)
    bytes_in = rng.randint(500,28000)
    interval = rng.uniform(.01,2.0)
    unique_ports = rng.randint(1,8)
    unique_hosts = rng.randint(1,6)
    syn_rate = 0.0
    dns_entropy = rng.uniform(2.2,3.8)
    query_len = rng.randint(10,30)
    txt_ratio = rng.uniform(0,.15)
    periodicity = rng.uniform(.05,.45)
    tls_size_var = rng.uniform(.1,.8)
    ja4_novelty = rng.uniform(.05,.45)

    if scenario == "DDoS":
        packet_count = rng.randint(300,800)
        bytes_out = rng.randint(60000,150000)
        bytes_in = rng.randint(50,1500)
        unique_ports = rng.randint(1,4)
        unique_hosts = 1
        syn_rate = rng.uniform(250,900)
    elif scenario == "C2 Beaconing":
        packet_count = rng.randint(15,35)
        interval = rng.uniform(.95,1.08)
        periodicity = rng.uniform(.88,.99)
        unique_hosts = rng.randint(1,2)
        bytes_out, bytes_in = rng.randint(500,2500), rng.randint(300,1800)
    elif scenario == "DGA / DNS Tunnelling":
        proto, dport = "UDP", 53
        dns_entropy = rng.uniform(4.3,5.4)
        query_len = rng.randint(45,85)
        txt_ratio = rng.uniform(.65,.95)
        packet_count = rng.randint(80,220)
    elif scenario == "Encrypted Session Anomaly":
        proto, dport = "TCP", 443
        tls_size_var = rng.uniform(.85,1.3)
        ja4_novelty = rng.uniform(.8,1.0)
        packet_count = rng.randint(80,250)
    elif scenario == "Recon / Port Scan":
        packet_count = rng.randint(100,400)
        unique_ports = rng.randint(40,180)
        unique_hosts = rng.randint(10,60)
        bytes_in = rng.randint(20,600)
    elif scenario == "Data Exfiltration":
        packet_count = rng.randint(150,500)
        bytes_out = rng.randint(500000,2000000)
        bytes_in = rng.randint(500,10000)
        unique_hosts = rng.randint(1,3)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow_id": f"{src}:{sport}>{dst}:{dport}/{proto}",
        "src_ip": src, "dst_ip": dst, "protocol": proto,
        "packets": packet_count, "bytes_out": bytes_out, "bytes_in": bytes_in,
        "interval": interval, "unique_ports": unique_ports,
        "unique_hosts": unique_hosts, "syn_rate": syn_rate,
        "dns_entropy": dns_entropy, "query_len": query_len,
        "txt_ratio": txt_ratio, "periodicity": periodicity,
        "tls_size_var": tls_size_var, "ja4_novelty": ja4_novelty
    }

def detect(f):
    scores = {t: 0.0 for t in THREATS}
    evidence = {}

    scores["DDoS"] = min(1, .55*min(f["syn_rate"]/250,1) + .45*min(f["packets"]/350,1))
    evidence["DDoS"] = {"syn_rate": round(f["syn_rate"],2), "packets": f["packets"]}

    scores["C2 Beaconing"] = min(1, .75*f["periodicity"] + .25*(1 if f["unique_hosts"]<=2 else 0))
    evidence["C2 Beaconing"] = {"periodicity_score": round(f["periodicity"],3),
                                 "unique_dest_hosts": f["unique_hosts"],
                                 "interarrival": round(f["interval"],3)}

    dga_x = np.array([[f["dns_entropy"], f["query_len"],
                       f["txt_ratio"], min(f["query_len"]/80,1)]])
    dga_p = float(DGA_MODEL.predict_proba(dga_x)[0,1])
    scores["DGA / DNS Tunnelling"] = dga_p
    evidence["DGA / DNS Tunnelling"] = {"name_entropy": round(f["dns_entropy"],2),
                                        "avg_query_len": f["query_len"],
                                        "txt_record_ratio": round(f["txt_ratio"],2)}

    scores["Encrypted Session Anomaly"] = min(1, .55*f["ja4_novelty"] + .45*min(f["tls_size_var"],1))
    evidence["Encrypted Session Anomaly"] = {"ja4_novelty": round(f["ja4_novelty"],2),
                                             "packet_size_variance": round(f["tls_size_var"],2),
                                             "payload_decryption": False}

    scores["Recon / Port Scan"] = min(1, .65*min(f["unique_ports"]/60,1) +
                                      .35*min(f["unique_hosts"]/20,1))
    evidence["Recon / Port Scan"] = {"unique_ports": f["unique_ports"],
                                     "unique_hosts": f["unique_hosts"]}

    ratio = f["bytes_out"] / max(f["bytes_in"],1)
    scores["Data Exfiltration"] = min(1, ratio/80)
    evidence["Data Exfiltration"] = {"outbound_bytes": f["bytes_out"],
                                     "inbound_bytes": f["bytes_in"],
                                     "out_in_ratio": round(ratio,2)}

    # Pick strongest signal; suppress weak benign noise.
    threat = max(scores, key=scores.get)
    confidence = scores[threat]
    if confidence < .62:
        return None

    severity = "CRITICAL" if confidence >= .9 else "HIGH" if confidence >= .75 else "MEDIUM"
    return {
        "timestamp": f["timestamp"],
        "flow_id": f["flow_id"],
        "threat_class": threat,
        "severity": severity,
        "confidence": round(confidence,3),
        "evidence": evidence[threat],
        "model": "ThreatLens-hybrid-v1"
    }

# ---------- UI ----------
st.title("🛡️ ThreatLens")
st.caption("AI-driven passive threat detection for one-way (data-diode) IP traffic")

with st.sidebar:
    st.header("Replay Controls")
    scenario = st.selectbox("Traffic scenario",
        ["Benign"] + THREATS)
    rate = st.slider("Replay rate (flows/sec)", 1, 50, 12)
    duration = st.slider("Replay duration (seconds)", 5, 60, 20)
    start = st.button("▶ Start streaming", use_container_width=True)
    st.divider()
    st.success("READ-ONLY INGEST")
    st.info("No probes • No handshakes • No blocking • No payload decryption")

if "alerts" not in st.session_state: st.session_state.alerts = []
if "metrics" not in st.session_state: st.session_state.metrics = []
if "running" not in st.session_state: st.session_state.running = False

c1,c2,c3,c4 = st.columns(4)
m1,m2,m3,m4 = c1.empty(),c2.empty(),c3.empty(),c4.empty()
chart_slot = st.empty()
alert_slot = st.empty()

if start:
    st.session_state.alerts = []
    st.session_state.metrics = []
    st.session_state.running = True
    t0 = time.perf_counter()
    total = rate * duration
    for i in range(total):
        f = make_flow(scenario, i)
        a0 = time.perf_counter()
        alert = detect(f)
        latency = (time.perf_counter()-a0)*1000
        elapsed = max(time.perf_counter()-t0, 1e-6)
        st.session_state.metrics.append({
            "elapsed": elapsed, "flows": i+1,
            "fps": (i+1)/elapsed, "latency_ms": latency
        })
        if alert:
            st.session_state.alerts.insert(0, alert)
            st.session_state.alerts = st.session_state.alerts[:100]

        metrics = st.session_state.metrics
        latest_fps = metrics[-1]["fps"]
        latest_lat = metrics[-1]["latency_ms"]
        crit = sum(x["severity"]=="CRITICAL" for x in st.session_state.alerts)
        m1.metric("Flows processed", i+1)
        m2.metric("Observed flows/sec", f"{latest_fps:.1f}")
        m3.metric("Alerts", len(st.session_state.alerts))
        m4.metric("Latest inference", f"{latest_lat:.2f} ms")

        if metrics:
            dfm = pd.DataFrame(metrics)
            fig = px.line(dfm, x="elapsed", y="fps", title="Streaming throughput")
            chart_slot.plotly_chart(fig, use_container_width=True)

        if st.session_state.alerts:
            dfa = pd.DataFrame(st.session_state.alerts)
            show = dfa[["timestamp","threat_class","severity","confidence","flow_id"]].copy()
            alert_slot.dataframe(show, use_container_width=True, hide_index=True)

        time.sleep(1/max(rate,1))

    st.session_state.running = False
    st.success("Replay completed. The pipeline remained read-only throughout the run.")

if not st.session_state.metrics:
    m1.metric("Flows processed", 0)
    m2.metric("Observed flows/sec", "0")
    m3.metric("Alerts", 0)
    m4.metric("Latest inference", "—")
    st.markdown("### Start a replay to see live detection")

st.divider()
st.subheader("Alert Evidence")
if st.session_state.alerts:
    selected = st.selectbox(
        "Select alert",
        range(len(st.session_state.alerts)),
        format_func=lambda i: f'{st.session_state.alerts[i]["severity"]} — {st.session_state.alerts[i]["threat_class"]}'
    )
    st.json(st.session_state.alerts[selected])
else:
    st.caption("No alerts yet. Run an attack scenario to populate evidence.")

st.caption("ThreatLens: see everything, touch nothing.")
