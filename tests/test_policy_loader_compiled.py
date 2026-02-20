import unittest

from releasegate.policy.loader import PolicyLoader
from releasegate.policy.policy_types import Policy


class TestPolicyLoaderCompiled(unittest.TestCase):
    def test_load_compiled_policies(self):
        loader = PolicyLoader(policy_dir="releasegate/policy/compiled", schema="compiled")
        policies = loader.load_policies()
        self.assertTrue(len(policies) > 0)
        self.assertIsInstance(policies[0], Policy)
        self.assertTrue(hasattr(policies[0], "policy_id"))

    def test_compiled_policy_accepts_phase1_governance_fields(self):
        policy = Policy.model_validate(
            {
                "policy_id": "RG-GOV-001",
                "version": "1.0.0",
                "name": "Governance strict policy",
                "scope": "pull_request",
                "enabled": True,
                "controls": [{"signal": "raw.risk.level", "operator": "==", "value": "LOW"}],
                "enforcement": {"result": "WARN", "message": "warn"},
                "strict_fail_closed": True,
                "overrides": {
                    "enabled": True,
                    "max_ttl_seconds": 3600,
                    "default_ttl_seconds": 600,
                    "require_expires_at": True,
                },
                "separation_of_duties": {
                    "enabled": True,
                    "deny_self_approval": True,
                    "rules": [
                        {
                            "name": "requester-cannot-approve-own-override",
                            "left": "override_requested_by",
                            "right": "override_approved_by",
                        }
                    ],
                },
            }
        )
        self.assertTrue(policy.strict_fail_closed)
        self.assertIsNotNone(policy.overrides)
        self.assertIsNotNone(policy.separation_of_duties)


if __name__ == "__main__":
    unittest.main()
