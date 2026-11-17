"""JSON-RPC 2.0 protocol helpers for Model Context Protocol (MCP) messages."""

from __future__ import annotations

import json
from typing import Any


def make_request(
    request_id: int | str,
    method: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 request object."""
    msg: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
    }
    if params is not None:
        msg["params"] = params
    return msg


def make_notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 notification object (no id)."""
    msg: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": method,
    }
    if params is not None:
        msg["params"] = params
    return msg


def make_response(request_id: int | str | None, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response object."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def make_error(
    request_id: int | str | None,
    code: int,
    message: str,
    data: Any | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response object."""
    err: dict[str, Any] = {
        "code": int(code),
        "message": str(message),
    }
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": err,
    }


def parse_message(raw_line: str) -> dict[str, Any]:
    """Parse a newline-delimited JSON-RPC 2.0 message frame."""
    parsed = json.loads(raw_line)
    if not isinstance(parsed, dict):
        raise ValueError(f"JSON-RPC message must be a JSON object, got {type(parsed).__name__}")
    return parsed


def is_valid_jsonrpc_response(msg: Any) -> bool:
    """Validate whether `msg` conforms to the JSON-RPC 2.0 response envelope."""
    if not isinstance(msg, dict):
        return False
    if msg.get("jsonrpc") != "2.0":
        return False
    if "id" not in msg:
        return False
    has_result = "result" in msg
    has_error = "error" in msg
    if has_result == has_error:
        return False
    if has_error:
        err = msg["error"]
        if not isinstance(err, dict):
            return False
        if not isinstance(err.get("code"), int) or not isinstance(err.get("message"), str):
            return False
    return True
