#!/bin/bash

# RiskBot Doctor - Diagnostic Script

echo "========================================"
echo "🩺  RiskBot Doctor"
echo "========================================"

# 1. Check Token
echo ""
echo "[1] Checking GITHUB_TOKEN..."
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌  GITHUB_TOKEN is NOT set."
    echo "    Fix: export GITHUB_TOKEN=\$(grep GITHUB_TOKEN .env | cut -d '=' -f2)"
    exit 1
else
    LEN=${#GITHUB_TOKEN}
    if [ "$LEN" -lt 40 ]; then
        echo "⚠️   GITHUB_TOKEN seems too short (length: $LEN). Expected ~40 chars."
    else
        echo "✅  GITHUB_TOKEN is set (length: $LEN)."
    fi
fi

# 2. Check API Connectivity & Auth
echo ""
echo "[2] Checking GitHub API Auth..."
USER_RESP=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user)
LOGIN=$(echo "$USER_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('login', ''))")

if [ -z "$LOGIN" ]; then
    echo "❌  Authentication FAILED."
    echo "    Response: $USER_RESP"
    exit 1
else
    echo "✅  Authenticated as: $LOGIN"
fi

# 3. Check Rate Limits
echo ""
echo "[3] Checking Rate Limits..."
RATE_RESP=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/rate_limit)
REMAINING=$(echo "$RATE_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('rate', {}).get('remaining', 'UNKNOWN'))")

if [ "$REMAINING" == "UNKNOWN" ] || [ "$REMAINING" -lt 10 ]; then
    echo "⚠️   Low Rate Limit! Remaining: $REMAINING"
else
    echo "✅  Rate Limit OK. Remaining: $REMAINING"
fi

# 4. Check RiskBot CLI
echo ""
echo "[4] Checking RiskBot CLI..."
if command -v riskbot &> /dev/null; then
    echo "✅  'riskbot' command found."
    python3 -c "import riskbot; print(f'    Version: {riskbot.__version__}')" 2>/dev/null || echo "    (Version check failed)"
else
    echo "❌  'riskbot' command NOT found in PATH."
    echo "    Run: pip install -e ."
fi

echo ""
echo "========================================"
echo "🎉  Diagnostics Complete."
echo "========================================"
