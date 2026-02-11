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


if __name__ == "__main__":
    unittest.main()
