import copy
import unittest

from core.evaluation.paired_manifest import validate_paired_manifest


HASH_A = "a" * 64
HASH_B = "b" * 64


def source_record(record_id, input_hash, model_hash, score, score_semantics):
    return {
        "record_id": record_id,
        "input_sha256": input_hash,
        "model_sha256": model_hash,
        "true_label": 1,
        "predicted_label": 1,
        "score": score,
        "score_semantics": score_semantics,
    }


def valid_manifest():
    return {
        "schema_version": 1,
        "manifest_id": "test-manifest",
        "purpose": "paired_fusion_evaluation",
        "fusion_target": {
            "name": "event_security_incident",
            "positive_class_meaning": "A security incident was confirmed for the linked event.",
            "label_definition": "Independent event-level adjudication using incident records.",
        },
        "events": [
            {
                "event_id": "event-001",
                "group_id": "incident-group-001",
                "split": "train",
                "event_time_utc": "2026-01-02T03:04:05Z",
                "pairing_basis": {
                    "method": "analyst_adjudication",
                    "reference": "case-record-001",
                },
                "event_label": {
                    "security_incident": True,
                    "incident_type": "multi_stage",
                    "adjudication_source": "independent_case_review",
                },
                "sources": {
                    "ai_nids": source_record("nids-001", HASH_A, HASH_B, 0.91, "attack_probability"),
                    "phishvision": source_record("phish-001", HASH_B, HASH_A, 0.88, "phishing_probability"),
                },
            }
        ],
    }


class PairedManifestValidationTests(unittest.TestCase):
    def test_valid_manifest_passes(self):
        result = validate_paired_manifest(valid_manifest())
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["summary"]["event_count"], 1)
        self.assertEqual(result["summary"]["source_record_counts"], {"ai_nids": 1, "phishvision": 1})

    def test_rejects_non_object_manifest(self):
        result = validate_paired_manifest([])
        self.assertFalse(result["valid"])
        self.assertIn("manifest must be a JSON object", result["errors"])

    def test_rejects_missing_source(self):
        payload = valid_manifest()
        del payload["events"][0]["sources"]["phishvision"]
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("sources missing" in error for error in result["errors"]))

    def test_rejects_bad_score_and_hash(self):
        payload = valid_manifest()
        payload["events"][0]["sources"]["ai_nids"]["score"] = 1.4
        payload["events"][0]["sources"]["phishvision"]["input_sha256"] = "bad"
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("score must be a number in [0, 1]" in error for error in result["errors"]))
        self.assertTrue(any("input_sha256 must be a 64-character" in error for error in result["errors"]))

    def test_rejects_group_leakage_across_splits(self):
        payload = valid_manifest()
        second = copy.deepcopy(payload["events"][0])
        second["event_id"] = "event-002"
        second["split"] = "test"
        second["sources"]["ai_nids"]["record_id"] = "nids-002"
        second["sources"]["phishvision"]["record_id"] = "phish-002"
        payload["events"].append(second)
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("appears across splits" in error for error in result["errors"]))

    def test_rejects_duplicate_event_and_source_ids(self):
        payload = valid_manifest()
        second = copy.deepcopy(payload["events"][0])
        second["group_id"] = "different-group"
        payload["events"].append(second)
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("duplicate event_id" in error for error in result["errors"]))
        self.assertTrue(any("duplicate ai_nids record_id" in error for error in result["errors"]))

    def test_rejects_timezone_naive_timestamp(self):
        payload = valid_manifest()
        payload["events"][0]["event_time_utc"] = "2026-01-02T03:04:05"
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("event_time_utc must be an ISO-8601 UTC datetime" in error for error in result["errors"]))

    def test_rejects_non_utc_event_timestamp(self):
        payload = valid_manifest()
        payload["events"][0]["event_time_utc"] = "2026-01-02T11:04:05+08:00"
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("event_time_utc must be an ISO-8601 UTC datetime" in error for error in result["errors"]))

    def test_rejects_non_utc_prediction_timestamp(self):
        payload = valid_manifest()
        payload["events"][0]["sources"]["ai_nids"]["prediction_timestamp_utc"] = "2026-01-02T11:04:05+08:00"
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("prediction_timestamp_utc must be an ISO-8601 UTC datetime" in error for error in result["errors"]))

    def test_rejects_non_rfc3339_timestamp_spellings(self):
        invalid_values = (
            "2026-01-02 03:04:05+00:00",  # space separator
            "2026-01-02T03:04:05+00:00:00",  # offset includes seconds
            "2026-01-02T03:04:05+0000",  # compact offset
        )
        for value in invalid_values:
            with self.subTest(value=value):
                payload = valid_manifest()
                payload["events"][0]["event_time_utc"] = value
                result = validate_paired_manifest(payload)
                self.assertFalse(result["valid"])
                self.assertTrue(
                    any("event_time_utc must be an ISO-8601 UTC datetime" in error
                        for error in result["errors"]),
                    result["errors"],
                )

    def test_rejects_non_binary_labels(self):
        payload = valid_manifest()
        payload["events"][0]["sources"]["ai_nids"]["true_label"] = 2
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("true_label must be integer 0 or 1" in error for error in result["errors"]))

    def test_malformed_enum_values_return_validation_errors_not_exceptions(self):
        for field_path, value in (
            (("split",), []),
            (("pairing_basis", "method"), []),
            (("event_label", "incident_type"), []),
        ):
            with self.subTest(field_path=field_path):
                payload = valid_manifest()
                target = payload["events"][0]
                if len(field_path) == 1:
                    target[field_path[0]] = value
                else:
                    target[field_path[0]][field_path[1]] = value
                result = validate_paired_manifest(payload)
                self.assertFalse(result["valid"])
                self.assertTrue(result["errors"])

    def test_boolean_schema_version_is_not_integer_one(self):
        payload = valid_manifest()
        payload["schema_version"] = True
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("schema_version must equal integer 1" in error for error in result["errors"]))

    def test_rejects_unknown_fields_at_all_schema_levels(self):
        mutations = (
            lambda p: p.update(unexpected=True),
            lambda p: p["fusion_target"].update(unexpected=True),
            lambda p: p["events"][0].update(unexpected=True),
            lambda p: p["events"][0]["pairing_basis"].update(unexpected=True),
            lambda p: p["events"][0]["event_label"].update(unexpected=True),
            lambda p: p["events"][0]["sources"].update(extra_source={}),
            lambda p: p["events"][0]["sources"]["ai_nids"].update(unexpected=True),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                payload = valid_manifest()
                mutation(payload)
                result = validate_paired_manifest(payload)
                self.assertFalse(result["valid"])
                self.assertTrue(
                    any("unsupported" in error for error in result["errors"]),
                    result["errors"],
                )

    def test_rejects_whitespace_only_required_strings(self):
        payload = valid_manifest()
        payload["manifest_id"] = "   "
        result = validate_paired_manifest(payload)
        self.assertFalse(result["valid"])
        self.assertTrue(any("manifest_id must be a non-empty string" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
