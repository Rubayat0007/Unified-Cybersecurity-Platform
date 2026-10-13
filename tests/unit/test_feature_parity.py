import unittest

from core.evaluation.feature_parity import (
    FEATURE_NAMES,
    compare_feature_records,
)


def make_record(flow_id, offset=0.0):
    """Build a deterministic synthetic feature record for comparator tests."""
    record = {"flow_id": flow_id}
    record.update({
        name: float(index + 1) + offset
        for index, name in enumerate(FEATURE_NAMES)
    })
    return record


class TestFeatureParity(unittest.TestCase):
    def test_identical_records_are_equivalent(self):
        reference = [make_record("flow-001")]
        candidate = [make_record("flow-001")]

        result = compare_feature_records(reference, candidate)

        self.assertTrue(result["valid"])
        self.assertTrue(result["equivalent"])
        self.assertEqual(result["summary"]["matched_flow_count"], 1)
        self.assertEqual(
            result["summary"]["feature_values_compared"], 20
        )
        self.assertEqual(
            result["summary"]["feature_mismatch_count"], 0
        )

    def test_small_difference_within_tolerance_passes(self):
        reference = make_record("flow-001")
        candidate = make_record("flow-001")
        candidate["flow_bytes"] += 5e-7

        result = compare_feature_records(
            [reference],
            [candidate],
            abs_tol=1e-6,
            rel_tol=0.0,
        )

        self.assertTrue(result["valid"])
        self.assertTrue(result["equivalent"])

    def test_feature_difference_is_reported(self):
        reference = make_record("flow-001")
        candidate = make_record("flow-001")
        candidate["flow_bytes"] += 1.0

        result = compare_feature_records(
            [reference],
            [candidate],
            abs_tol=0.0,
            rel_tol=0.0,
        )

        self.assertTrue(result["valid"])
        self.assertFalse(result["equivalent"])
        self.assertEqual(
            result["summary"]["feature_mismatch_count"], 1
        )
        self.assertEqual(len(result["mismatches"]), 1)
        self.assertEqual(
            result["mismatches"][0]["feature"], "flow_bytes"
        )

    def test_missing_and_extra_flow_ids_are_reported(self):
        reference = [
            make_record("flow-001"),
            make_record("flow-002"),
        ]
        candidate = [
            make_record("flow-001"),
            make_record("flow-003"),
        ]

        result = compare_feature_records(reference, candidate)

        self.assertTrue(result["valid"])
        self.assertFalse(result["equivalent"])
        summary = result["summary"]
        self.assertEqual(summary["matched_flow_count"], 1)
        self.assertEqual(summary["missing_candidate_flow_count"], 1)
        self.assertEqual(summary["missing_reference_flow_count"], 1)
        self.assertEqual(
            summary["missing_candidate_flow_ids_sample"], ["flow-002"]
        )
        self.assertEqual(
            summary["missing_reference_flow_ids_sample"], ["flow-003"]
        )

    def test_duplicate_flow_id_invalidates_comparison(self):
        reference = [
            make_record("flow-001"),
            make_record("flow-001"),
        ]
        candidate = [make_record("flow-001")]

        result = compare_feature_records(reference, candidate)

        self.assertFalse(result["valid"])
        self.assertFalse(result["equivalent"])
        self.assertTrue(
            any("duplicate flow_id" in error for error in result["errors"])
        )

    def test_missing_feature_invalidates_comparison(self):
        reference = make_record("flow-001")
        del reference["idle_time"]

        result = compare_feature_records(
            [reference],
            [make_record("flow-001")],
        )

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("idle_time" in error for error in result["errors"])
        )

    def test_non_finite_feature_invalidates_comparison(self):
        reference = make_record("flow-001")
        reference["flow_duration"] = "nan"

        result = compare_feature_records(
            [reference],
            [make_record("flow-001")],
        )

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("must be finite" in error for error in result["errors"])
        )

    def test_boolean_feature_is_rejected(self):
        reference = make_record("flow-001")
        reference["flow_duration"] = True

        result = compare_feature_records(
            [reference],
            [make_record("flow-001")],
        )

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("not boolean" in error for error in result["errors"])
        )

    def test_empty_records_are_invalid(self):
        result = compare_feature_records([], [])

        self.assertFalse(result["valid"])
        self.assertFalse(result["equivalent"])
        self.assertTrue(result["errors"])

    def test_negative_tolerance_is_rejected(self):
        result = compare_feature_records(
            [make_record("flow-001")],
            [make_record("flow-001")],
            abs_tol=-1.0,
        )

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("abs_tol" in error for error in result["errors"])
        )

    def test_mismatch_examples_are_capped(self):
        reference = make_record("flow-001")
        candidate = make_record("flow-001", offset=100.0)

        result = compare_feature_records(
            [reference],
            [candidate],
            abs_tol=0.0,
            rel_tol=0.0,
            max_mismatches=2,
        )

        self.assertTrue(result["valid"])
        self.assertFalse(result["equivalent"])
        self.assertEqual(len(result["mismatches"]), 2)
        self.assertTrue(result["mismatch_examples_truncated"])
        self.assertEqual(
            result["summary"]["feature_mismatch_count"], 20
        )


if __name__ == "__main__":
    unittest.main()
