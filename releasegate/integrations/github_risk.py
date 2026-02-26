from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Dict, Any, Set

from releasegate.governance.signal_freshness import compute_risk_signal_hash


RISK_SCORE_MAP = {
    "LOW": 25,
    "MEDIUM": 60,
    "HIGH": 85,
}


@dataclass(frozen=True)
class PRRiskInput:
    changed_files: int = 0
    additions: int = 0
    deletions: int = 0

    @property
    def total_churn(self) -> int:
        return max(0, int(self.additions or 0)) + max(0, int(self.deletions or 0))


def classify_pr_risk(
    metrics: PRRiskInput,
    *,
    high_changed_files: int = 20,
    medium_additions: int = 300,
    high_total_churn: int = 800,
) -> str:
    """
    Minimal heuristic risk classifier for GitHub->Jira bridge.

    This intentionally uses only metadata counters and avoids deep code analysis.
    """
    if int(metrics.changed_files or 0) > high_changed_files:
        return "HIGH"
    if metrics.total_churn > high_total_churn:
        return "HIGH"
    if int(metrics.additions or 0) > medium_additions:
        return "MEDIUM"
    return "LOW"


def score_for_risk_level(level: str) -> int:
    return int(RISK_SCORE_MAP.get(level.upper(), 0))


def build_issue_risk_property(
    *,
    repo: str,
    pr_number: int,
    risk_level: str,
    metrics: PRRiskInput,
    source: str = "github",
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    risk_level = (risk_level or "LOW").upper()
    risk_score = score_for_risk_level(risk_level)
    payload = {
        "releasegate_risk": risk_level,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "source": source,
        "pr_number": int(pr_number),
        "repo": repo,
        "computed_at": now,
        "metrics": {
            "changed_files_count": int(metrics.changed_files or 0),
            "additions": int(metrics.additions or 0),
            "deletions": int(metrics.deletions or 0),
            "total_churn": int(metrics.total_churn),
        },
    }
    payload["signal_hash"] = compute_risk_signal_hash(payload)
    return payload


_JIRA_KEY_RE = re.compile(r"\b[A-Z][A-Z0-9]+-\d+\b")


def extract_jira_issue_keys(*texts: str) -> Set[str]:
    keys: Set[str] = set()
    for text in texts:
        if not text:
            continue
        for key in _JIRA_KEY_RE.findall(str(text)):
            keys.add(key)
    return keys
