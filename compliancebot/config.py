from pathlib import Path
import os
from dotenv import load_dotenv

# Load params from .env file
load_dotenv()

# Data storage
DB_PATH = os.getenv("COMPLIANCE_DB_PATH", os.getenv("DB_PATH", "data/compliancebot.db"))
JSONL_PATH = os.getenv("COMPLIANCE_JSONL_PATH", os.getenv("JSONL_PATH", "data/runs.jsonl"))

# Webhook URL (for details_url in Check Runs)
WEBHOOK_URL = os.getenv("COMPLIANCEBOT_WEBHOOK_URL", os.getenv("RISKBOT_WEBHOOK_URL", ""))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Policy Boundaries (formerly Risk Thresholds)
SEVERITY_THRESHOLD_HIGH = 75
SEVERITY_THRESHOLD_MEDIUM = 40

# Scoring weights
# Adjusted for stricter V1 enforcement
WEIGHT_CRITICAL_PATH = 25
WEIGHT_HIGH_CHURN = 20
WEIGHT_LARGE_CHANGE = 25
WEIGHT_NO_TESTS = 25

# Review requirements
REVIEWERS_DEFAULT = 1
REVIEWERS_HIGH_RISK = 2

# Path patterns
CRITICAL_PATHS = [
 "auth/",
 "db/",
 "payments/",
 "security/",
 "api/v1/",
]

# File types to track
SRC_EXTENSIONS = {
 ".py", ".js", ".ts", ".go", ".rs", ".java", ".cpp", ".c", ".h"
}

TEST_PATHS = [
 "tests/",
 "test/",
 "__tests__/",
]
