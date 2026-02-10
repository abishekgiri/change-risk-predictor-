import unittest
from datetime import datetime

from releasegate.signals.approvals.types import Review
from releasegate.signals.approvals.validator import is_review_stale


class TestApprovalsStale(unittest.TestCase):
    def test_missing_head_sha_not_stale(self):
        review = Review(
            reviewer="alice",
            state="APPROVED",
            submitted_at=datetime.utcnow(),
            commit_id="abc123"
        )
        self.assertFalse(is_review_stale(review, ""))


if __name__ == "__main__":
    unittest.main()
