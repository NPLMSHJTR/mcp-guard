"""Dynamic boundary and malformed-input fuzz engine for live MCP tools."""

from __future__ import annotations

import time
from typing import Any, Callable

from mcp_guard.models import FuzzCaseResult, FuzzOutcome, ToolDefinition
from mcp_guard.transport.jsonrpc import is_valid_jsonrpc_response

STACK_TRACE_MARKERS: tuple[str, ...] = (
    "Traceback (most recent call last):",
    "ZeroDivisionError",
    "KeyError:",
    "TypeError:",
    "ValueError:",
    "AttributeError:",
    "IndexError:",
    'File "/',
    'File "C:\\',
    'File "d:\\',
    'File "D:\\',
    "at Object.<anonymous>",
    "UnhandledPromiseRejection",
)


def _baseline_valid_value(prop_schema: dict[str, Any]) -> Any:
    if not isinstance(prop_schema, dict):
        return "sample"
    if "enum" in prop_schema and isinstance(prop_schema["enum"], list) and prop_schema["enum"]:
        return prop_schema["enum"][0]
    if "default" in prop_schema:
        return prop_schema["default"]
    ptype = prop_schema.get("type")
    if isinstance(ptype, list) and ptype:
        ptype = ptype[0]
    if ptype == "string":
        return "safe_sample"
    if ptype == "integer":
        return 1
    if ptype == "number":
        return 1.0
    if ptype == "boolean":
        return False
    if ptype == "array":
        return []
    if ptype == "object":
        return {}
    return "sample"


def generate_fuzz_cases(tool: ToolDefinition) -> list[tuple[str, dict[str, Any]]]:
    """Generate deterministic boundary and adversarial payloads from a tool's inputSchema."""
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []

    baseline: dict[str, Any] = {
        name: _baseline_valid_value(pschema) for name, pschema in props.items() if isinstance(name, str)
    }

    cases: list[tuple[str, dict[str, Any]]] = []

    # 1. Missing required parameters
    if required:
        cases.append(("missing_required", {}))

    # 2. Unexpected extra / prototype-pollution-like property
    extra_payload = dict(baseline)
    extra_payload["__unexpected_fuzz_field__"] = {"injected": True}
    cases.append(("unexpected_extra_field", extra_payload))

    # 3. Per-parameter boundary & injection probes
    for prop_name, prop_schema in props.items():
        if not isinstance(prop_schema, dict):
            continue
        ptype = prop_schema.get("type")
        if isinstance(ptype, list) and ptype:
            ptype = ptype[0]

        # Null injection
        p_null = dict(baseline)
        p_null[prop_name] = None
        cases.append((f"{prop_name}__null", p_null))

        if ptype == "string":
            p_empty = dict(baseline)
            p_empty[prop_name] = ""
            cases.append((f"{prop_name}__empty_string", p_empty))

            p_long = dict(baseline)
            p_long[prop_name] = "A" * 4096
            cases.append((f"{prop_name}__oversized_string", p_long))

            p_type = dict(baseline)
            p_type[prop_name] = 123456
            cases.append((f"{prop_name}__type_confusion_int", p_type))

            p_trav = dict(baseline)
            p_trav[prop_name] = "../../../../etc/passwd"
            cases.append((f"{prop_name}__path_traversal_probe", p_trav))

            p_shell = dict(baseline)
            p_shell[prop_name] = "; id && echo mcp_guard_probe"
            cases.append((f"{prop_name}__shell_metachar_probe", p_shell))

            p_sqli = dict(baseline)
            p_sqli[prop_name] = "' OR '1'='1'; --"
            cases.append((f"{prop_name}__sqli_probe", p_sqli))

        elif ptype in {"integer", "number"}:
            p_zero = dict(baseline)
            p_zero[prop_name] = 0
            cases.append((f"{prop_name}__zero", p_zero))

            p_neg = dict(baseline)
            p_neg[prop_name] = -1
            cases.append((f"{prop_name}__negative", p_neg))

            p_huge = dict(baseline)
            p_huge[prop_name] = 10**18
            cases.append((f"{prop_name}__extreme_large", p_huge))

            p_str = dict(baseline)
            p_str[prop_name] = "not_a_number"
            cases.append((f"{prop_name}__type_confusion_str", p_str))

        elif ptype == "boolean":
            p_str = dict(baseline)
            p_str[prop_name] = "true_string"
            cases.append((f"{prop_name}__type_confusion_str", p_str))

        elif ptype == "array":
            p_empty_arr = dict(baseline)
            p_empty_arr[prop_name] = []
            cases.append((f"{prop_name}__empty_array", p_empty_arr))

            p_not_arr = dict(baseline)
            p_not_arr[prop_name] = "not_an_array"
            cases.append((f"{prop_name}__type_confusion_str", p_not_arr))

    # Deduplicate by case_name while preserving order
    seen: set[str] = set()
    unique_cases: list[tuple[str, dict[str, Any]]] = []
    for cname, payload in cases:
        if cname not in seen:
            seen.add(cname)
            unique_cases.append((cname, payload))
    return unique_cases


def _extract_response_text(resp: dict[str, Any]) -> str:
    parts: list[str] = []
    if "error" in resp and isinstance(resp["error"], dict):
        parts.append(str(resp["error"].get("message", "")))
        if "data" in resp["error"]:
            parts.append(str(resp["error"]["data"]))
    result = resp.get("result")
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and "text" in item:
                    parts.append(str(item["text"]))
        elif content is not None:
            parts.append(str(content))
    return "\n".join(parts)


class FuzzEngine:
    """Executes generated fuzz cases against an MCP server tool invocation callable."""

    def fuzz_tool(
        self,
        tool: ToolDefinition,
        call_fn: Callable[[str, dict[str, Any]], dict[str, Any]],
        max_cases: int | None = None,
    ) -> list[FuzzCaseResult]:
        cases = generate_fuzz_cases(tool)
        if max_cases is not None:
            cases = cases[:max_cases]

        results: list[FuzzCaseResult] = []
        for case_name, payload in cases:
            start = time.perf_counter()
            try:
                resp = call_fn(tool.name, payload)
                elapsed_ms = (time.perf_counter() - start) * 1000.0
            except TimeoutError as exc:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                results.append(
                    FuzzCaseResult(
                        tool_name=tool.name,
                        case_name=case_name,
                        payload=payload,
                        outcome=FuzzOutcome.TIMEOUT,
                        latency_ms=elapsed_ms,
                        detail=f"Server timed out: {exc}",
                    )
                )
                continue
            except (EOFError, BrokenPipeError, ConnectionError, RuntimeError) as exc:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                results.append(
                    FuzzCaseResult(
                        tool_name=tool.name,
                        case_name=case_name,
                        payload=payload,
                        outcome=FuzzOutcome.CRASH,
                        latency_ms=elapsed_ms,
                        detail=f"Server process crashed or disconnected: {exc}",
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                results.append(
                    FuzzCaseResult(
                        tool_name=tool.name,
                        case_name=case_name,
                        payload=payload,
                        outcome=FuzzOutcome.CRASH,
                        latency_ms=elapsed_ms,
                        detail=f"Unexpected transport exception ({type(exc).__name__}): {exc}",
                    )
                )
                continue

            outcome, detail = self._classify_response(resp)
            results.append(
                FuzzCaseResult(
                    tool_name=tool.name,
                    case_name=case_name,
                    payload=payload,
                    outcome=outcome,
                    latency_ms=elapsed_ms,
                    detail=detail,
                )
            )
        return results

    def fuzz_tools(
        self,
        tools: list[ToolDefinition],
        call_fn: Callable[[str, dict[str, Any]], dict[str, Any]],
        max_cases_per_tool: int | None = None,
    ) -> list[FuzzCaseResult]:
        all_results: list[FuzzCaseResult] = []
        for tool in tools:
            all_results.extend(self.fuzz_tool(tool, call_fn, max_cases=max_cases_per_tool))
        return all_results

    @staticmethod
    def _classify_response(resp: Any) -> tuple[FuzzOutcome, str]:
        if not is_valid_jsonrpc_response(resp):
            return (
                FuzzOutcome.PROTOCOL_VIOLATION,
                f"Response is not a valid JSON-RPC 2.0 envelope: {repr(resp)[:160]}",
            )

        text = _extract_response_text(resp)
        for marker in STACK_TRACE_MARKERS:
            if marker in text:
                return (
                    FuzzOutcome.STACK_LEAK,
                    f"Server leaked internal traceback/exception details ({marker}): {text[:180]}",
                )

        if "error" in resp:
            err = resp["error"]
            return (
                FuzzOutcome.GRACEFUL_ERROR,
                f"Clean JSON-RPC error code={err.get('code')}: {str(err.get('message', ''))[:120]}",
            )

        result = resp.get("result", {})
        if isinstance(result, dict) and result.get("isError") is True:
            return (
                FuzzOutcome.GRACEFUL_ERROR,
                f"Clean MCP tool error (isError=true): {text[:120]}",
            )

        return (FuzzOutcome.PASS, "Handled input cleanly without crash or trace leak.")
