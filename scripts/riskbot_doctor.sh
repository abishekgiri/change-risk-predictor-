#!/bin/bash

# ComplianceBot Doctor - Diagnostic Script

echo "========================================"
echo " ComplianceBot Doctor"
echo "========================================"

# 1. Check Token
echo ""
echo "[1] Checking GITHUB_TOKEN..."
if [ -z "$GITHUB_TOKEN" ]; then
 echo "[FAIL] GITHUB_TOKEN is NOT set."
 echo " Fix: export GITHUB_TOKEN=\$(grep '^GITHUB_TOKEN=' .env | cut -d '=' -f2- | tr -d '\"' | tr -d \"'\")"
 exit 1
else
 LEN=${#GITHUB_TOKEN}
 if [ "$LEN" -lt 40 ]; then
 echo "[WARN] GITHUB_TOKEN seems too short (length: $LEN). Expected ~40 chars."
 else
 echo "[OK] GITHUB_TOKEN is set."
 fi
fi

# 2. Check API Connectivity & Auth
echo ""
echo "[2] Checking GitHub API Auth..."
USER_RESP=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user)
LOGIN=$(echo "$USER_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('login', ''))")

if [ -z "$LOGIN" ]; then
 echo "[FAIL] Authentication FAILED."
 echo " Response: $USER_RESP"
 exit 1
else
 echo "[OK] Authenticated as: $LOGIN"
fi

# 3. Check Rate Limits
echo ""
echo "[3] Checking Rate Limits..."
RATE_RESP=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/rate_limit)
REMAINING=$(echo "$RATE_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('rate', {}).get('remaining', 'UNKNOWN'))")

if [ "$REMAINING" == "UNKNOWN" ] || [ "$REMAINING" -lt 10 ]; then
 echo "[WARN] Low Rate Limit! Remaining: $REMAINING"
else
 echo "[OK] Rate Limit OK. Remaining: $REMAINING"
fi

# 4. Check ComplianceBot CLI
echo ""
echo "[4] Checking ComplianceBot CLI..."
if command -v compliancebot &> /dev/null; then
  echo "[OK] 'compliancebot' command found."
else
  # Try python module check
  if python3 -c "import compliancebot" &> /dev/null; then
     echo "[OK] 'compliancebot' python module found."
  else
     echo "[FAIL] 'compliancebot' NOT found."
     echo " Run: pip install -e ."
  fi
fi

echo ""
echo "========================================"
echo " Diagnostics Complete."
echo "========================================"
