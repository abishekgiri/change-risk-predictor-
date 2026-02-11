import unittest

from releasegate.enforcement.licenses import LicensesControl
from releasegate.enforcement.types import ControlContext


class TestLicensesControlDiffOnly(unittest.TestCase):
    def test_diff_only_skips(self):
        ctrl = LicensesControl()
        ctx = ControlContext(
            repo="owner/repo",
            pr_number=1,
            diff={"package-lock.json": "diff --git a/package-lock.json b/package-lock.json\n@@\n+ foo"},
            config={},
            provider=None
        )
        result = ctrl.execute(ctx)
        self.assertTrue(result.signals.get("licenses.skipped_diff_only"))
        self.assertEqual(result.signals.get("licenses.scanned"), False)


if __name__ == "__main__":
    unittest.main()
