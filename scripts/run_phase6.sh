#!/usr/bin/env bash
set -e

echo "=== Running Phase 6: Explanation Engine ==="
python3 scripts/verify_phase6_explanations.py

echo "=== Running Phase 6: Analytics & Dashboard ==="
python3 scripts/verify_phase6_analytics.py

echo "=== Running Phase 6: End-to-End UX ==="
python3 scripts/verify_phase6_complete.py

echo " Phase 6 FULLY VERIFIED"
