import unittest

from main import governance_decision


class TestDocumentGovernanceDecision(unittest.TestCase):
    def test_clean_document_is_allowed(self):
        result = governance_decision(0.0, "HIGH")
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["action"], "ALLOW")
        self.assertEqual(result["color"], "GREEN")

    def test_high_consequence_escalates_nonzero_corruption(self):
        result = governance_decision(0.21, "HIGH")
        self.assertEqual(result["decision"], "ESCALATE")
        self.assertEqual(result["action"], "REQUIRE_HUMAN_REVIEW")
        self.assertEqual(result["severity"], "HIGH")

    def test_critical_consequence_blocks_nonzero_corruption(self):
        result = governance_decision(0.01, "CRITICAL")
        self.assertEqual(result["decision"], "BLOCK_AND_ESCALATE")
        self.assertEqual(result["action"], "BLOCK_AND_ESCALATE")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_invalid_score_fails_closed(self):
        result = governance_decision(float("nan"), "HIGH")
        self.assertEqual(result["decision"], "BLOCK_AND_ESCALATE")


if __name__ == "__main__":
    unittest.main()
