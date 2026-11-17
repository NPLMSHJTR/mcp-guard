# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `0.1.x` | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `mcp-guard` (such as a sandbox escape in the Studio UI, a parser Denial-of-Service, or a bypass in a high-severity detection rule):

1. **Do NOT open a public GitHub Issue** with active exploit details against third-party servers.
2. Please use **GitHub Private Vulnerability Reporting** under the repository's **Security** tab (or contact the maintainers privately if enabled).
3. Include:
   - Affected version and Python environment
   - Minimal reproduction payload or trace
   - Suggested remediation (if available)

We aim to acknowledge reports within 48 hours and provide a verified patch release within 7 days for critical issues.

## Safe Usage Disclaimer

The `examples/vulnerable_mcp_server.py` and `benchmarks/poisoned_tools.jsonl` files contain **synthetic, harmless demonstration vectors** for defensive testing and benchmarking only. Do not deploy `vulnerable_mcp_server.py` in any production or untrusted network environment.
