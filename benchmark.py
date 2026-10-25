import time, sys
sys.path.insert(0, "app")
from main import make_flow, detect

def run(n=10000):
    t = time.perf_counter()
    alerts = 0
    for i in range(n):
        a = detect(make_flow("DDoS" if i % 2 else "Benign", i))
        alerts += bool(a)
    elapsed = time.perf_counter() - t
    print(f"Flows: {n}")
    print(f"Elapsed: {elapsed:.3f}s")
    print(f"Detection throughput: {n/elapsed:.1f} flows/sec")
    print(f"Alerts: {alerts}")
if __name__ == "__main__":
    run()
