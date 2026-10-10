"""Reusable, dependency-free evaluation utilities for binary classifiers."""

from .metrics import evaluate_binary, roc_curve_points

__all__ = ["evaluate_binary", "roc_curve_points"]
