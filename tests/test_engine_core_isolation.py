from releasegate.engine import ComplianceEngine, PolicyResult as EnginePolicyResult
from releasegate.engine_core.decision_model import PolicyResult as CorePolicyResult
from releasegate.engine_core.policy_parser import flatten_signals


def test_engine_reexports_core_policy_result():
    assert EnginePolicyResult is CorePolicyResult


def test_engine_core_flatten_signals_behavior():
    data = {
        "core_risk": {"severity_level": "HIGH"},
        "raw": {"risk": {"level": "HIGH"}},
        "files_changed": ["a.py"],
    }
    flattened = flatten_signals(data)
    assert flattened["core_risk.severity_level"] == "HIGH"
    assert flattened["raw.risk.level"] == "HIGH"
    assert flattened["files_changed"] == ["a.py"]


def test_engine_condition_logic_uses_core_parser():
    engine = ComplianceEngine({})
    assert engine._check_condition(["admin", "security"], "in", ["security"]) is True
    assert engine._check_condition(["admin"], "not in", ["security"]) is True
