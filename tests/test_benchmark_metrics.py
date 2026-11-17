"""Tests verifying MCP-Guard achieves high recall and zero false positives on benchmarks/."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "benchmarks") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "benchmarks"))

from evaluate_benchmark import evaluate_dataset  # noqa: E402


def test_benchmark_recall_and_zero_false_positives() -> None:
    metrics = evaluate_dataset(REPO_ROOT / "benchmarks")
    assert metrics["benign_count"] == 25
    assert metrics["poisoned_count"] == 25
    assert metrics["false_positives"] == 0, f"False positives: {metrics['false_positive_cases']}"
    assert metrics["benign_schema_violations"] == 0
    assert metrics["recall"] >= 0.95, f"Missed cases: {metrics['missed_cases']}"
    assert metrics["rule_recall"] >= 0.95, f"Missed cases: {metrics['missed_cases']}"
    assert metrics["precision"] == 1.0
