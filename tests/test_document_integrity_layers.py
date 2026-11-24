import unittest

from main import DocumentVerifyRequest, detect_semantic_corruption


class TestDocumentIntegrityLayers(unittest.TestCase):
    def test_numeric_changes_are_detected(self):
        result = detect_semantic_corruption(
            original_text="The payment limit is USD 25,000 and the review period is 30 days.",
            generated_text="The payment limit is USD 250,000 and the review period is 300 days.",
            document_type="financial",
            agent_id="unit-test-agent",
            consequence="HIGH",
        )
        vector = result["corruption_vectors"]["numerical_inconsistency"]
        self.assertTrue(vector["detected"])
        self.assertTrue(vector["issues"])
        self.assertIn("NUMBERS_REMOVED", {issue["type"] for issue in vector["issues"]})

    def test_document_request_preserves_workflow_id(self):
        request = DocumentVerifyRequest(
            original_text="baseline",
            current_text="candidate",
            workflow_id="workflow-unit-001",
        )
        self.assertEqual(request.workflow_id, "workflow-unit-001")


if __name__ == "__main__":
    unittest.main()
