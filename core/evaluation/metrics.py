"""Binary classification metrics and ROC helpers, using only the stdlib."""

from __future__ import annotations

import math
from typing import Iterable, Sequence


def _binary_sequence(values: Iterable[int], name: str) -> list[int]:
    result: list[int] = []
    for index, raw in enumerate(values):
        if isinstance(raw, bool):
            value = int(raw)
        else:
            try:
                value = int(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name}[{index}] must be 0 or 1; got {raw!r}") from exc
            if str(raw).strip() not in {"0", "1"} and not (
                isinstance(raw, float) and raw in (0.0, 1.0)
            ):
                raise ValueError(f"{name}[{index}] must be 0 or 1; got {raw!r}")
        if value not in (0, 1):
            raise ValueError(f"{name}[{index}] must be 0 or 1; got {raw!r}")
        result.append(value)
    return result


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def evaluate_binary(actual: Iterable[int], predicted: Iterable[int]) -> dict:
    """Return confusion counts and binary/per-class metrics (positive class = 1).

    Empty inputs and unequal sequence lengths are rejected. Undefined ratios are
    reported as 0.0 and should be interpreted together with the support counts.
    """
    y_true = _binary_sequence(actual, "actual")
    y_pred = _binary_sequence(predicted, "predicted")
    if not y_true:
        raise ValueError("At least one prediction row is required.")
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"actual and predicted lengths differ: {len(y_true)} != {len(y_pred)}"
        )

    tp = tn = fp = fn = 0
    for truth, prediction in zip(y_true, y_pred):
        if truth == 1 and prediction == 1:
            tp += 1
        elif truth == 0 and prediction == 0:
            tn += 1
        elif truth == 0 and prediction == 1:
            fp += 1
        else:
            fn += 1

    total = len(y_true)
    positive_support = tp + fn
    negative_support = tn + fp

    precision_1 = _ratio(tp, tp + fp)
    recall_1 = _ratio(tp, tp + fn)
    f1_1 = _ratio(2 * precision_1 * recall_1, precision_1 + recall_1)

    # For class 0 treated as the class of interest:
    precision_0 = _ratio(tn, tn + fn)
    recall_0 = _ratio(tn, tn + fp)
    f1_0 = _ratio(2 * precision_0 * recall_0, precision_0 + recall_0)

    accuracy = _ratio(tp + tn, total)
    specificity = recall_0
    balanced_accuracy = (recall_1 + specificity) / 2

    per_class = {
        "0": {
            "precision": precision_0,
            "recall": recall_0,
            "f1": f1_0,
            "support": negative_support,
        },
        "1": {
            "precision": precision_1,
            "recall": recall_1,
            "f1": f1_1,
            "support": positive_support,
        },
    }
    macro = {
        "precision": (precision_0 + precision_1) / 2,
        "recall": (recall_0 + recall_1) / 2,
        "f1": (f1_0 + f1_1) / 2,
        "support": total,
    }
    weighted = {
        "precision": _ratio(
            precision_0 * negative_support + precision_1 * positive_support, total
        ),
        "recall": _ratio(
            recall_0 * negative_support + recall_1 * positive_support, total
        ),
        "f1": _ratio(f1_0 * negative_support + f1_1 * positive_support, total),
        "support": total,
    }

    return {
        "positive_class": 1,
        "sample_count": total,
        "class_counts": {"0": negative_support, "1": positive_support},
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "counts": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": accuracy,
        "precision": precision_1,
        "recall": recall_1,
        "f1": f1_1,
        "specificity": specificity,
        "balanced_accuracy": balanced_accuracy,
        "per_class": per_class,
        "macro_avg": macro,
        "weighted_avg": weighted,
    }


def roc_curve_points(actual: Iterable[int], scores: Iterable[float]) -> dict:
    """Build ROC points and trapezoidal AUC for scores where larger means class 1.

    Tied scores are advanced as a group, preventing arbitrary ordering from
    changing the curve. The initial point uses an infinite threshold.
    AUC is None if the supplied labels contain only one class.
    """
    y_true = _binary_sequence(actual, "actual")
    y_score: list[float] = []
    for index, raw in enumerate(scores):
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"scores[{index}] must be numeric; got {raw!r}") from exc
        if not math.isfinite(value):
            raise ValueError(f"scores[{index}] must be finite; got {raw!r}")
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"scores[{index}] must be in [0, 1]; got {raw!r}")
        y_score.append(value)

    if not y_true:
        raise ValueError("At least one score row is required.")
    if len(y_true) != len(y_score):
        raise ValueError(
            f"actual and scores lengths differ: {len(y_true)} != {len(y_score)}"
        )

    positives = sum(y_true)
    negatives = len(y_true) - positives
    sorted_pairs = sorted(zip(y_score, y_true), key=lambda pair: pair[0], reverse=True)
    points = [{"threshold": None, "fpr": 0.0, "tpr": 0.0}]
    tp = fp = 0
    index = 0
    while index < len(sorted_pairs):
        threshold = sorted_pairs[index][0]
        while index < len(sorted_pairs) and sorted_pairs[index][0] == threshold:
            if sorted_pairs[index][1] == 1:
                tp += 1
            else:
                fp += 1
            index += 1
        points.append(
            {
                "threshold": threshold,
                "fpr": _ratio(fp, negatives),
                "tpr": _ratio(tp, positives),
            }
        )

    if positives == 0 or negatives == 0:
        auc = None
    else:
        auc = 0.0
        for left, right in zip(points, points[1:]):
            auc += (right["fpr"] - left["fpr"]) * (
                right["tpr"] + left["tpr"]
            ) / 2

    return {
        "auc": auc,
        "positive_count": positives,
        "negative_count": negatives,
        "points": points,
    }
