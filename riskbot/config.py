from pathlib import Path
import os

# Data storage
RISK_DB_PATH = os.getenv("RISK_DB_PATH", "data/riskbot.db")
RISK_JSONL_PATH = os.getenv("RISK_JSONL_PATH", "data/runs.jsonl")

# Risk thresholds
RISK_THRESHOLD_HIGH = 75
RISK_THRESHOLD_MEDIUM = 40

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
