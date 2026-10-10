import unittest

from core.evaluation.metrics import evaluate_binary, roc_curve_points


class EvaluateBinaryTests(unittest.TestCase):
    def test_confusion_metrics(self):
        result = evaluate_binary([1, 1, 0, 0], [1, 0, 1, 0])
        self.assertEqual(result["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(result["counts"], {"tp": 1, "tn": 1, "fp": 1, "fn": 1})
        self.assertAlmostEqual(result["accuracy"], 0.5)
        self.assertAlmostEqual(result["precision"], 0.5)
        self.assertAlmostEqual(result["recall"], 0.5)
        self.assertAlmostEqual(result["f1"], 0.5)
        self.assertAlmostEqual(result["specificity"], 0.5)
        self.assertAlmostEqual(result["balanced_accuracy"], 0.5)

    def test_rejects_mismatched_lengths(self):
        with self.assertRaisesRegex(ValueError, "lengths differ"):
            evaluate_binary([0, 1], [1])

    def test_rejects_non_binary_labels(self):
        with self.assertRaisesRegex(ValueError, "must be 0 or 1"):
            evaluate_binary([0, 2], [0, 1])

    def test_rejects_empty_input(self):
        with self.assertRaisesRegex(ValueError, "At least one"):
            evaluate_binary([], [])


class RocCurveTests(unittest.TestCase):
    def test_perfect_auc(self):
        result = roc_curve_points([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1])
        self.assertAlmostEqual(result["auc"], 1.0)
        self.assertEqual(result["points"][0]["fpr"], 0.0)
        self.assertEqual(result["points"][-1]["tpr"], 1.0)
        self.assertEqual(result["points"][-1]["fpr"], 1.0)

    def test_tied_scores_have_half_auc(self):
        result = roc_curve_points([1, 0], [0.5, 0.5])
        self.assertAlmostEqual(result["auc"], 0.5)

    def test_auc_undefined_for_single_class(self):
        result = roc_curve_points([1, 1], [0.7, 0.2])
        self.assertIsNone(result["auc"])

    def test_rejects_probability_outside_unit_interval(self):
        with self.assertRaisesRegex(ValueError, r"within|in \[0, 1\]"):
            roc_curve_points([0, 1], [0.2, 1.2])


if __name__ == "__main__":
    unittest.main()
