# Phase 7 Perf Benchmarks

Run benchmarks outside normal pytest runs:

```bash
python tests/perf/run_perf.py --count 1000
```

What this measures:
- `decision_replay_1k`
- `policy_simulation_1k`
- `proof_pack_export_1k`

Each benchmark reports:
- `count`
- `total_ms`
- `p50_ms`
- `p95_ms`
- `p99_ms`
- `max_ms`
- `ops_per_sec`

Reports are written to `tests/perf/results/` (gitignored).
Runner behavior:
- uses monotonic clock (`perf_counter`)
- performs a 1-run warmup per benchmark path before sampling
