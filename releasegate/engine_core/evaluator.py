from typing import Any, Callable, Dict, List

from releasegate.engine_core.decision_model import PolicyResult
from releasegate.policy.policy_types import Policy


def evaluate_policy(
    policy: Policy,
    signals: Dict[str, Any],
    *,
    check_condition: Callable[[Any, str, Any], bool],
) -> PolicyResult:
    violations: List[str] = []
    triggered = False

    triggers: List[str] = []
    for ctrl in policy.controls:
        signal_name = getattr(ctrl, "signal", None)
        operator = getattr(ctrl, "operator", None)
        expected = getattr(ctrl, "value", None)
        actual_val = signals.get(signal_name)
        if check_condition(actual_val, operator, expected):
            triggers.append(f"{signal_name} ({actual_val}) {operator} {expected}")

    if len(triggers) == len(policy.controls):
        triggered = True
        violations = triggers
        status = policy.enforcement.result
    else:
        status = "COMPLIANT"

    return PolicyResult(
        policy_id=policy.policy_id,
        name=policy.name,
        status=status,
        triggered=triggered,
        violations=violations,
        evidence={},
        traceability=policy.metadata or {},
    )
