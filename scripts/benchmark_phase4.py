import time
import statistics
from compliancebot.engine import ComplianceEngine

def benchmark_engine():
 print("Starting Phase 4 Benchmark")
 
 # 1. Initialize Engine
 config = {"thresholds": {"risk_score": 50}}
 start_init = time.time()
 engine = ComplianceEngine(config)
 init_time = (time.time() - start_init) * 1000
 print(f"Engine Intialized in {init_time:.2f}ms")
 print(f"Rules Loaded: {len(engine.policies)}")
 
 # 2. Mock Signals (Complex Scenario)
 signals = {
 # Core inputs
 "deployment.risk_score": 85,
 "secrets.detected": True,
 "secrets.severity": "HIGH",
 "approvals.count": 1, 
 "total_churn": 150,
 "additions": 100,
 "deletions": 50,
 "files_changed": ["config.json", "auth.py"],
 "per_file_churn": {"config.json": 50, "auth.py": 50},
 # Diff context (triggers Phase 3 checks internally, but we mock output mainly)
 "diff": {"config.json": "+password"},
 # Mocking phase 3 signals via monkey-patching for stability
 }
 
 # Monkey patch registry to avoid external IO overhead during benchmark
 # We want to measure POLICY EVALUATION logic speed, not I/O speed.
 engine.control_registry.run_all = lambda ctx: {
 "signals": {
 "secrets.detected": True,
 "secrets.severity": "HIGH",
 "approvals.count": 1,
 "approvals.security_review": 1,
 "privileged.is_sensitive": True, 
 "env.production_violation": False,
 "licenses.banned_detected": False
 }, 
 "findings": []
 }
 
 # 3. Running Loop
 iterations = 1000
 latencies = []
 
 print(f"\nrunning {iterations} iterations...")
 for _ in range(iterations):
 start = time.time()
 engine.evaluate(signals)
 duration = (time.time() - start) * 1000
 latencies.append(duration)
 
 # 4. Stats
 avg = statistics.mean(latencies)
 p95 = statistics.quantiles(latencies, n=20)[18] # 95th percentile
 p99 = statistics.quantiles(latencies, n=100)[98] # 99th percentile
 
 print(f"\nBenchmark Results:")
 print(f" Average: {avg:.2f}ms")
 print(f" p95: {p95:.2f}ms")
 print(f" p99: {p99:.2f}ms")
 
 if avg > 50:
 print("Performance Regression: Average > 50ms")
 exit(1)
 
 print("Performance Requirement Met (<50ms)")

if __name__ == "__main__":
 benchmark_engine()
