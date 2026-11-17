"""Chaos fault injection proxy and resilience testing suite for MCP tool calls."""

from __future__ import annotations

import copy
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from mcp_guard.transport.jsonrpc import is_valid_jsonrpc_response, make_error


class ChaosFaultType(str, Enum):
    """Supported chaos fault modes for MCP tool responses."""

    TIMEOUT = "timeout"
    RATE_LIMIT_429 = "rate_limit_429"
    INTERNAL_ERROR_500 = "internal_error_500"
    MALFORMED_JSON = "malformed_json"
    SCHEMA_DRIFT = "schema_drift"
    EMPTY_RESULT = "empty_result"


@dataclass
class ChaosPolicy:
    """Configuration controlling when and how faults are injected."""

    fault_type: ChaosFaultType
    probability: float = 1.0
    target_tools: set[str] | None = None
    delay_ms: float = 0.0
    seed: int | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError(f"probability must be in [0.0, 1.0], got {self.probability}")


@dataclass
class ChaosInjectionRecord:
    """Audit trail entry for a single proxied tool invocation."""

    tool_name: str
    fault_injected: bool
    fault_type: str | None
    latency_ms: float
    upstream_called: bool
    response: dict[str, Any] | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "fault_injected": self.fault_injected,
            "fault_type": self.fault_type,
            "latency_ms": round(self.latency_ms, 2),
            "upstream_called": self.upstream_called,
            "response": self.response,
            "detail": self.detail,
        }


class ChaosProxy:
    """Transparent middleware that injects controlled faults around MCP `tools/call` calls."""

    def __init__(
        self,
        upstream_call: Callable[[str, dict[str, Any]], dict[str, Any]],
        policy: ChaosPolicy,
    ) -> None:
        self.upstream_call = upstream_call
        self.policy = policy
        self._rng = random.Random(policy.seed)
        self.records: list[ChaosInjectionRecord] = []

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        request_id: int | str = 1,
    ) -> dict[str, Any]:
        args = arguments or {}
        should_target = (
            self.policy.target_tools is None or tool_name in self.policy.target_tools
        )
        should_inject = should_target and (self._rng.random() < self.policy.probability)

        if not should_inject:
            start = time.perf_counter()
            resp = self.upstream_call(tool_name, args)
            elapsed = (time.perf_counter() - start) * 1000.0
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=False,
                    fault_type=None,
                    latency_ms=elapsed,
                    upstream_called=True,
                    response=resp,
                    detail="Passed through cleanly to upstream.",
                )
            )
            return resp

        if self.policy.delay_ms > 0:
            time.sleep(self.policy.delay_ms / 1000.0)

        fault = self.policy.fault_type
        start = time.perf_counter()

        if fault == ChaosFaultType.TIMEOUT:
            elapsed = (time.perf_counter() - start) * 1000.0 + self.policy.delay_ms
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=True,
                    fault_type=fault.value,
                    latency_ms=elapsed,
                    upstream_called=False,
                    response=None,
                    detail="Injected simulated transport TimeoutError.",
                )
            )
            raise TimeoutError(f"ChaosProxy injected timeout on tool {tool_name!r}")

        if fault == ChaosFaultType.RATE_LIMIT_429:
            resp = make_error(
                request_id,
                -32029,
                "Too Many Requests: upstream rate limit exceeded (chaos injection)",
                data={"httpStatus": 429, "retryAfterSeconds": 2, "chaos": True},
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=True,
                    fault_type=fault.value,
                    latency_ms=elapsed,
                    upstream_called=False,
                    response=resp,
                    detail="Injected JSON-RPC 429 rate-limit error with retryAfterSeconds=2.",
                )
            )
            return resp

        if fault == ChaosFaultType.INTERNAL_ERROR_500:
            resp = make_error(
                request_id,
                -32603,
                "Internal Server Error: simulated upstream 500 failure (chaos injection)",
                data={"httpStatus": 500, "chaos": True},
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=True,
                    fault_type=fault.value,
                    latency_ms=elapsed,
                    upstream_called=False,
                    response=resp,
                    detail="Injected JSON-RPC -32603 internal error.",
                )
            )
            return resp

        if fault == ChaosFaultType.MALFORMED_JSON:
            resp = {
                "_raw_invalid_frame": '{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"truncated...',
                "chaos": True,
            }
            elapsed = (time.perf_counter() - start) * 1000.0
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=True,
                    fault_type=fault.value,
                    latency_ms=elapsed,
                    upstream_called=False,
                    response=resp,
                    detail="Injected truncated/malformed JSON-RPC frame.",
                )
            )
            return resp

        if fault == ChaosFaultType.SCHEMA_DRIFT:
            upstream_resp = self.upstream_call(tool_name, args)
            drifted = copy.deepcopy(upstream_resp) if isinstance(upstream_resp, dict) else {}
            drifted["jsonrpc"] = "2.0"
            drifted.setdefault("id", request_id)
            drifted["result"] = {
                "unexpected_nested_v2_payload": {"legacy_content_removed": True},
                "isError": False,
            }
            elapsed = (time.perf_counter() - start) * 1000.0
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=True,
                    fault_type=fault.value,
                    latency_ms=elapsed,
                    upstream_called=True,
                    response=drifted,
                    detail="Mutated upstream result structure to simulate breaking schema drift.",
                )
            )
            return drifted

        if fault == ChaosFaultType.EMPTY_RESULT:
            resp = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [], "isError": False},
            }
            elapsed = (time.perf_counter() - start) * 1000.0
            self.records.append(
                ChaosInjectionRecord(
                    tool_name=tool_name,
                    fault_injected=True,
                    fault_type=fault.value,
                    latency_ms=elapsed,
                    upstream_called=False,
                    response=resp,
                    detail="Injected empty content array response.",
                )
            )
            return resp

        raise ValueError(f"Unsupported fault type: {fault}")


def run_chaos_suite(
    upstream_call: Callable[[str, dict[str, Any]], dict[str, Any]],
    tool_name: str,
    sample_args: dict[str, Any] | None = None,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Exercise all 6 ChaosFaultType modes against a target tool and return structured diagnostics."""
    results: list[dict[str, Any]] = []
    args = sample_args or {}

    for fault in ChaosFaultType:
        proxy = ChaosProxy(
            upstream_call=upstream_call,
            policy=ChaosPolicy(fault_type=fault, probability=1.0, seed=seed, delay_ms=5.0),
        )
        try:
            resp = proxy.call_tool(tool_name, args)
            valid_rpc = is_valid_jsonrpc_response(resp)
            results.append(
                {
                    "fault_type": fault.value,
                    "raised_exception": None,
                    "valid_jsonrpc_envelope": valid_rpc,
                    "record": proxy.records[-1].to_dict(),
                }
            )
        except TimeoutError as exc:
            results.append(
                {
                    "fault_type": fault.value,
                    "raised_exception": f"TimeoutError: {exc}",
                    "valid_jsonrpc_envelope": False,
                    "record": proxy.records[-1].to_dict(),
                }
            )
    return results
