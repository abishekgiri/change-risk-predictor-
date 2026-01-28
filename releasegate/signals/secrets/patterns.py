"""
Secret detection patterns and rules.

Each rule has a unique ID and deterministic regex pattern.
"""
import re
from dataclasses import dataclass
from typing import List, Pattern

@dataclass
class SecretRule:
    """A secret detection rule."""
    rule_id: str
    name: str
    pattern: Pattern
    severity: str # HIGH/MEDIUM/LOW
    requires_context: bool # If True, needs context check (2-factor)
    
    
# Known secret prefixes (high confidence, no context needed)
KNOWN_PREFIX_RULES = [
    SecretRule(
        rule_id="SEC-PR-002.RULE-001",
        name="AWS Access Key",
        pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
        severity="HIGH",
        requires_context=False
    ),
    SecretRule(
        rule_id="SEC-PR-002.RULE-002",
        name="GitHub Personal Access Token",
        pattern=re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        severity="HIGH",
        requires_context=False
    ),
    SecretRule(
        rule_id="SEC-PR-002.RULE-003",
        name="GitHub OAuth Token",
        pattern=re.compile(r'gho_[a-zA-Z0-9]{36}'),
        severity="HIGH",
        requires_context=False
    ),
    SecretRule(
        rule_id="SEC-PR-002.RULE-004",
        name="Stripe Test Key",
        pattern=re.compile(r'sk_test_[a-zA-Z0-9]{24,}'),
        severity="MEDIUM",
        requires_context=False
    ),
    SecretRule(
        rule_id="SEC-PR-002.RULE-005",
        name="Stripe Live Key",
        pattern=re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),
        severity="HIGH",
        requires_context=False
    ),
]

# Generic patterns (require context check)
GENERIC_PATTERNS = [
    SecretRule(
        rule_id="SEC-PR-002.RULE-010",
        name="Private Key",
        pattern=re.compile(r'-----BEGIN.*PRIVATE KEY-----'),
        severity="HIGH",
        requires_context=False # Private key header is specific enough
    ),
    SecretRule(
        rule_id="SEC-PR-002.RULE-011",
        name="Generic High Entropy String",
        pattern=re.compile(r'[A-Za-z0-9+/]{32,}={0,2}'), # Base64-like
        severity="MEDIUM",
        requires_context=True # Needs context check
    ),
]

# Context keywords indicating a secret
SECRET_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "key",
    "token",
    "auth",
    "credential",
    "api_key",
    "access_key",
    "private_key"
]

def get_all_rules() -> List[SecretRule]:
    """Get all secret detection rules."""
    return KNOWN_PREFIX_RULES + GENERIC_PATTERNS

def check_context(line: str, match_start: int, match_end: int) -> bool:
    """
    Check if a match has secret-related context nearby.
    """
    # Check 50 chars before and after the match
    context_start = max(0, match_start - 50)
    context_end = min(len(line), match_end + 50)
    context = line[context_start:context_end].lower()
    
    # Check for any secret keyword
    for keyword in SECRET_KEYWORDS:
        if keyword in context:
            return True
    
    return False
