#!/usr/bin/env bash
set -e

echo "=== Phase 7: AI Explanations ==="
python3 scripts/verify_phase7_ai_explanations.py

echo "=== Phase 7: Fix Suggestions ==="
python3 scripts/verify_phase7_fix_suggestions.py

echo "=== Phase 7: Safety Gate ==="
python3 scripts/verify_phase7_ai_safety.py

echo "=== Phase 7: End-to-End ==="
python3 scripts/verify_phase7_complete.py

echo " Phase 7 FULLY VERIFIED"
