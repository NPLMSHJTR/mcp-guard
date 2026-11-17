# Contributing to MCP-Guard & Studio

Thank you for your interest in contributing to `mcp-guard`!

## Development Setup

`mcp-guard` requires Python 3.10+ and has **zero mandatory runtime dependencies**.

```bash
git clone https://github.com/<owner>/mcp-guard.git
cd mcp-guard
python -m pip install -e ".[dev]"
```

Or run directly without installation:

```bash
PYTHONPATH=src python -m pytest tests/ -v
PYTHONPATH=src python benchmarks/evaluate_benchmark.py
```

## Project Layout

* `src/mcp_guard/rules_catalog.py`: Central registry of `MCP-SEC-*` and `MCP-SCHEMA-*` rules.
* `src/mcp_guard/analyzers/`: Static security scanner, JSON Schema validator, and live fuzz engine.
* `src/mcp_guard/transport/`: JSON-RPC 2.0 codec, `stdio` MCP client, and chaos fault injection proxy.
* `src/mcp_guard/recorder/`: Deterministic trace recorder and offline contract replayer.
* `src/mcp_guard/reporters/`: Console, SARIF 2.1.0, Markdown, and standalone HTML reporters.
* `src/mcp_guard/studio/`: Zero-dependency HTTP Studio and optional Gradio Space adapter.

## Adding a New Detection Rule

1. Register the rule metadata in `src/mcp_guard/rules_catalog.py` (`MCP-SEC-xxx` or `MCP-SCHEMA-xxx`).
2. Implement the detection logic in `poisoning_scanner.py` or `schema_validator.py`.
3. Add both **positive (trigger)** and **negative (benign lookalike)** test cases in `tests/`.
4. Add synthetic samples to `benchmarks/poisoned_tools.jsonl` and verify `benchmarks/evaluate_benchmark.py` maintains >= 95% recall and 0% false positives on `benign_tools.jsonl`.

## License

By contributing, you agree that code contributions are licensed under the **Apache-2.0** license and benchmark dataset additions under **CC-BY-4.0**.
