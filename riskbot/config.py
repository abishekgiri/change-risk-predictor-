from pathlib import Path

# Risk thresholds
RISK_THRESHOLD_HIGH = 70
RISK_THRESHOLD_MEDIUM = 40

# Scoring weights
WEIGHT_CRITICAL_PATH = 20
WEIGHT_HIGH_CHURN = 20
WEIGHT_LARGE_CHANGE = 15
WEIGHT_NO_TESTS = 15

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
