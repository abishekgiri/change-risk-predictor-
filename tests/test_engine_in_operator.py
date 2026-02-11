import unittest

from releasegate.engine import ComplianceEngine


class TestEngineInOperator(unittest.TestCase):
    def test_in_operator_with_list_actual(self):
        engine = ComplianceEngine({})
        self.assertTrue(engine._check_condition(["bug", "incident"], "in", ["incident", "sev1"]))
        self.assertFalse(engine._check_condition(["docs"], "in", ["incident", "sev1"]))

    def test_not_in_operator_with_list_actual(self):
        engine = ComplianceEngine({})
        self.assertTrue(engine._check_condition(["docs"], "not in", ["incident", "sev1"]))
        self.assertFalse(engine._check_condition(["incident"], "not in", ["incident", "sev1"]))


if __name__ == "__main__":
    unittest.main()
