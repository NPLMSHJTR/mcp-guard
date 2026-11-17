"""Automated benchmark evaluation script for MCP-Guard security & schema detection."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

# Allow direct execution via `python benchmarks/evaluate_benchmark.py`
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from mcp_guard.analyzers.poisoning_scanner import PoisoningScanner  # noqa: E402
from mcp_guard.analyzers.schema_validator import SchemaValidator  # noqa: E402
from mcp_guard.models import ToolDefinition  # noqa: E402


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            records.append(json.loads(stripped))
    return records


def evaluate_dataset(bench_dir: Path | None = None) -> dict[str, Any]:
    bdir = bench_dir or Path(__file__).resolve().parent
    benign_records = _load_jsonl(bdir / "benign_tools.jsonl")
    poisoned_records = _load_jsonl(bdir / "poisoned_tools.jsonl")

    sec_scanner = PoisoningScanner()
    schema_validator = SchemaValidator()

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    rule_hits = 0
    rule_expected_total = 0
    benign_schema_violations = 0
    latencies_ms: list[float] = []
    missed_cases: list[dict[str, Any]] = []
    false_positive_cases: list[dict[str, Any]] = []

    for rec in benign_records:
        raw_tools = rec["tools"] if "tools" in rec else [rec["tool"]]
        tools = [ToolDefinition.from_dict(t) for t in raw_tools]

        t0 = time.perf_counter()
        sec_findings = sec_scanner.scan_tools(tools)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        schema_findings = schema_validator.scan_tools(tools)
        benign_schema_violations += len(schema_findings)

        if sec_findings:
            fp += 1
            false_positive_cases.append(
                {
                    "id": rec["id"],
                    "triggered": [f.rule_id for f in sec_findings],
                }
            )
        else:
            tn += 1

    for rec in poisoned_records:
        raw_tools = rec["tools"] if "tools" in rec else [rec["tool"]]
        tools = [ToolDefinition.from_dict(t) for t in raw_tools]
        expected = set(rec.get("expected_rule_ids", []))
        rule_expected_total += len(expected)

        t0 = time.perf_counter()
        sec_findings = sec_scanner.scan_tools(tools)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        triggered = {f.rule_id for f in sec_findings}
        matched = expected & triggered
        rule_hits += len(matched)

        if expected.issubset(triggered) and len(triggered) > 0:
            tp += 1
        elif triggered:
            # Detected as malicious, though missing a specific expected sub-rule
            fn += 1
            missed_cases.append(
                {
                    "id": rec["id"],
                    "expected": sorted(expected),
                    "triggered": sorted(triggered),
                }
            )
        else:
            fn += 1
            missed_cases.append(
                {
                    "id": rec["id"],
                    "expected": sorted(expected),
                    "triggered": [],
                }
            )

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall) / max(1e-9, precision + recall)
    fpr = fp / max(1, fp + tn)
    rule_recall = rule_hits / max(1, rule_expected_total)
    avg_latency_ms = sum(latencies_ms) / max(1, len(latencies_ms))

    return {
        "benign_count": len(benign_records),
        "poisoned_count": len(poisoned_records),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "rule_recall": round(rule_recall, 4),
        "benign_schema_violations": benign_schema_violations,
        "avg_latency_ms": round(avg_latency_ms, 3),
        "missed_cases": missed_cases,
        "false_positive_cases": false_positive_cases,
    }


def main() -> int:
    metrics = evaluate_dataset()
    print("=" * 64)
    print("  MCP-Guard Benchmark Evaluation Results")
    print("=" * 64)
    print(f"Samples Evaluated        : {metrics['benign_count']} benign + {metrics['poisoned_count']} poisoned")
    print(f"Sample Precision         : {metrics['precision'] * 100:.2f}%")
    print(f"Sample Recall            : {metrics['recall'] * 100:.2f}%")
    print(f"Sample F1 Score          : {metrics['f1'] * 100:.2f}%")
    print(f"False Positive Rate      : {metrics['false_positive_rate'] * 100:.2f}%")
    print(f"Rule-Level Recall        : {metrics['rule_recall'] * 100:.2f}%")
    print(f"Benign Schema Violations : {metrics['benign_schema_violations']}")
    print(f"Avg Scan Latency / Sample: {metrics['avg_latency_ms']:.3f} ms")
    print("=" * 64)

    if metrics["missed_cases"]:
        print("Missed/Partial Cases:", json.dumps(metrics["missed_cases"], indent=2))
    if metrics["false_positive_cases"]:
        print("False Positive Cases:", json.dumps(metrics["false_positive_cases"], indent=2))

    ok = (
        metrics["recall"] >= 0.95
        and metrics["false_positive_rate"] <= 0.02
        and metrics["benign_schema_violations"] == 0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
