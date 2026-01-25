from typing import List

# Static Remediation Rules
# Maps explanation_key -> list of actions

REMEDIATION_MAP = {
    # Churn Factors
    "high_churn": [
        "Split this PR into smaller, atomic changes.",
        "Add comprehensive regression tests for the affected module.",
        "Request a senior reviewer (Principal/Staff)."
    ],
    "medium_churn": [
        "Ensure unit test coverage is above 80%.",
        "Verify changes in a staging environment."
    ],

    # Dependency Factors
    "tier0_dependency": [
        "Requires Security Engineering review.",
        "Must be deployed during off-peak window.",
        "Feature flag must be enabled for rollout."
    ],
    "new_dependency": [
        "Verify license compliance (OSI approved).",
        "Check for known CVEs in the artifact."
    ],

    # Hotspots & Quality
    "hotspot_file": [
        "Refactor this module to reduce complexity (Cost: High, Value: High).",
        "Add extra integration tests."
    ],
    "low_test_coverage": [
        "Add unit tests to cover new logic.",
        "Update existing test snapshots."
    ],

    # Security Specific
    "secrets_risk": [
        "Remove potential secrets from commit history.",
        "Rotate any exposed credentials immediately."
    ],
    "sensitive_file": [
        "Requires CODEOWNER approval.",
        "Audit log verification required."
    ],

    # Default
    "general_high_risk": [
        "Consult with team lead before merging.",
        "Perform manual QA verification."
    ]
}

def get_remediation(key: str) -> List[str]:
    return REMEDIATION_MAP.get(key, REMEDIATION_MAP["general_high_risk"])

