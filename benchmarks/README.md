---
language:
- en
license: cc-by-4.0
task_categories:
- text-classification
tags:
- mcp
- model-context-protocol
- agent-security
- prompt-injection
- tool-poisoning
- benchmark
pretty_name: MCP Security & Schema Benchmark (MCP-Guard-Bench)
size_categories:
- n<1K
---

# MCP-Guard-Bench (`benchmarks/`)

A synthetic, license-clean benchmark dataset of **50 Model Context Protocol (MCP) tool definitions** (25 benign production-grade tools + 25 poisoned/risky tools covering all 12 `MCP-SEC-*` threat categories).

## Dataset Composition

* `benign_tools.jsonl` (25 records): Well-structured, schema-hardened MCP tool definitions spanning filesystem workspace readers, weather, currency conversion, read-only SQL/Git/calendar helpers, and arithmetic utilities.
* `poisoned_tools.jsonl` (25 records): Synthetic adversarial payloads covering:
  * `MCP-SEC-001`: Direct Prompt Injection / `<IMPORTANT>` Overrides
  * `MCP-SEC-002`: SSH Key, `.env`, and Cloud Credential Exfiltration
  * `MCP-SEC-003`: Zero-Width & Bidirectional Steganography
  * `MCP-SEC-004`: Cross-Tool Shadowing & Hijacking
  * `MCP-SEC-005`: Covert Webhook / Context Exfiltration Channels
  * `MCP-SEC-006`: Unconstrained Shell / Code Execution Sinks
  * `MCP-SEC-007`: Unbounded Path Traversal Parameters
  * `MCP-SEC-008`: User Concealment / Deception Instructions
  * `MCP-SEC-009`: Destructive Actions Without Confirmation Guards
  * `MCP-SEC-010`: Base64 / Hex Encoded Obfuscation Payloads
  * `MCP-SEC-011`: SSRF / Internal Metadata Endpoint Exposure
  * `MCP-SEC-012`: Duplicate / Homoglyph / Typosquatted Tool Names

## Schema Format

Each line in the JSONL files is a JSON object with:

```json
{
  "id": "poisoned-001",
  "category": "poisoned",
  "attack_type": "prompt_injection",
  "tool": { "name": "...", "description": "...", "inputSchema": { ... } },
  "expected_rule_ids": ["MCP-SEC-001"]
}
```

*(Multi-tool naming conflict cases use `"tools": [...]` instead of `"tool"`.)*

## Running the Evaluator

```bash
PYTHONPATH=src python benchmarks/evaluate_benchmark.py
```

## License & Provenance

Released under **CC-BY-4.0**. All entries are 100% synthetically authored test fixtures containing zero user PII or real secrets.
