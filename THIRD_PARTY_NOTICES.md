# Third-Party Notices & License Compliance

`MCP-Guard & Studio` is designed with strict open-source license hygiene so that teams can integrate it freely into open-source and commercial CI/CD pipelines.

## Core Engine (`src/mcp_guard/`)

* **License**: Apache-2.0
* **Runtime Dependencies**: **Zero mandatory third-party packages**. The core CLI, JSON-RPC 2.0 transport, static security scanner, JSON Schema validator, fuzz engine, chaos proxy, trace recorder/replayer, SARIF/HTML/Markdown reporters, and built-in Studio HTTP server rely exclusively on the Python Standard Library (PSF-2.0 License).

## Optional Extras

| Component | Package | License | Usage Scope |
| :--- | :--- | :--- | :--- |
| Studio Gradio Adapter | `gradio` (`>=4.0`) | Apache-2.0 | Optional UI adapter for Hugging Face Gradio Spaces (`pip install mcp-guard[studio]`) |
| Test Runner | `pytest` (`>=7.0`) | MIT | Development and CI test suite (`pip install mcp-guard[dev]`) |

## Benchmark Dataset (`benchmarks/`)

* **License**: CC-BY-4.0 (Creative Commons Attribution 4.0 International)
* **Provenance**: All benign and poisoned MCP tool definitions in `benchmarks/benign_tools.jsonl` and `benchmarks/poisoned_tools.jsonl` are 100% synthetically authored test vectors created specifically for MCP security & schema benchmarking. They contain no scraped proprietary code, no personal identifiable information (PII), and no leaked credentials.
