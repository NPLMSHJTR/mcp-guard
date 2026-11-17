#!/usr/bin/env python3
"""Hardened reference MCP stdio server that passes all MCP-Guard security, schema, and fuzz checks."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

_SAFE_REL_PATH_RE = re.compile(r"^[A-Za-z0-9_]+(?:/[A-Za-z0-9_.-]+)*$")
_SAFE_TITLE_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,80}$")

TOOLS: list[dict[str, Any]] = [
    {
        "name": "add_workspace_note",
        "description": "Store a short plain-text note with a validated title inside the current workspace session.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Alphanumeric note title (1-80 chars).",
                    "maxLength": 80,
                    "pattern": "^[A-Za-z0-9 _.-]{1,80}$",
                },
                "body": {
                    "type": "string",
                    "description": "Plain-text note content (max 2000 chars).",
                    "maxLength": 2000,
                },
                "tags": {
                    "type": "array",
                    "description": "Optional list of short tag labels.",
                    "items": {"type": "string", "maxLength": 32},
                },
            },
            "required": ["title", "body"],
        },
    },
    {
        "name": "convert_currency",
        "description": "Convert a non-negative monetary amount between supported ISO currency codes using fixed demo rates.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "amount": {
                    "type": "number",
                    "description": "Non-negative monetary value to convert.",
                },
                "from_currency": {
                    "type": "string",
                    "description": "Source ISO 4217 currency code.",
                    "enum": ["USD", "EUR", "JPY"],
                },
                "to_currency": {
                    "type": "string",
                    "description": "Target ISO 4217 currency code.",
                    "enum": ["USD", "EUR", "JPY"],
                },
            },
            "required": ["amount", "from_currency", "to_currency"],
        },
    },
    {
        "name": "calculate_ratio",
        "description": "Divide a numeric numerator by a non-zero numeric denominator with strict input validation.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "numerator": {
                    "type": "number",
                    "description": "Dividend numeric value.",
                },
                "denominator": {
                    "type": "number",
                    "description": "Non-zero divisor numeric value.",
                },
            },
            "required": ["numerator", "denominator"],
        },
    },
    {
        "name": "read_workspace_doc",
        "description": "Read a simulated documentation snippet using a sandboxed relative workspace path.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "relative_path": {
                    "type": "string",
                    "description": "Relative document path without parent directory traversal.",
                    "maxLength": 160,
                    "pattern": "^[A-Za-z0-9_]+(?:/[A-Za-z0-9_.-]+)*$",
                }
            },
            "required": ["relative_path"],
        },
    },
]

_RATES_USD = {"USD": 1.0, "EUR": 0.92, "JPY": 150.0}


def _reply(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _invalid_params(req_id: Any, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": message}}


def _is_number(val: Any) -> bool:
    return isinstance(val, (int, float)) and not isinstance(val, bool)


def _handle_tool_call(req_id: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    schema_map = {t["name"]: t["inputSchema"] for t in TOOLS}
    if name not in schema_map:
        return _invalid_params(req_id, f"Unknown tool '{name}'.")

    allowed_keys = set(schema_map[name]["properties"].keys())
    extra_keys = set(args.keys()) - allowed_keys
    if extra_keys:
        return _invalid_params(req_id, f"Unexpected parameter(s): {sorted(extra_keys)}")

    for req_field in schema_map[name].get("required", []):
        if req_field not in args or args[req_field] is None:
            return _invalid_params(req_id, f"Missing required parameter '{req_field}'.")

    if name == "add_workspace_note":
        title = args["title"]
        body = args["body"]
        if not isinstance(title, str) or not _SAFE_TITLE_RE.match(title):
            return _invalid_params(req_id, "Parameter 'title' must be a valid 1-80 char identifier.")
        if not isinstance(body, str) or len(body) > 2000:
            return _invalid_params(req_id, "Parameter 'body' must be a string <= 2000 chars.")
        tags = args.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) and len(t) <= 32 for t in tags):
            return _invalid_params(req_id, "Parameter 'tags' must be a list of strings (<= 32 chars).")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"Note '{title}' stored."}], "isError": False},
        }

    if name == "convert_currency":
        amount = args["amount"]
        src = args["from_currency"]
        dst = args["to_currency"]
        if not _is_number(amount) or float(amount) < 0 or float(amount) > 1e12:
            return _invalid_params(req_id, "Parameter 'amount' must be between 0 and 1e12.")
        if src not in _RATES_USD or dst not in _RATES_USD:
            return _invalid_params(req_id, "Unsupported currency code; expected USD, EUR, or JPY.")
        converted = (float(amount) / _RATES_USD[src]) * _RATES_USD[dst]
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"{converted:.2f} {dst}"}], "isError": False},
        }

    if name == "calculate_ratio":
        num = args["numerator"]
        den = args["denominator"]
        if not _is_number(num) or not _is_number(den):
            return _invalid_params(req_id, "Both 'numerator' and 'denominator' must be numbers.")
        if float(den) == 0.0:
            return _invalid_params(req_id, "Parameter 'denominator' cannot be zero.")
        ratio = float(num) / float(den)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"{ratio:.6g}"}], "isError": False},
        }

    if name == "read_workspace_doc":
        rel = args["relative_path"]
        if not isinstance(rel, str) or len(rel) > 160 or ".." in rel or not _SAFE_REL_PATH_RE.match(rel):
            return _invalid_params(req_id, "Parameter 'relative_path' violates workspace path policy.")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"Preview of {rel}: OK"}], "isError": False},
        }

    return _invalid_params(req_id, f"Unhandled tool '{name}'.")


def main() -> None:
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            req = json.loads(stripped)
        except json.JSONDecodeError:
            _reply({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        if method == "initialize":
            _reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "hardened-demo-mcp", "version": "0.1.0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _reply({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            tname = str(params.get("name", ""))
            targs = params.get("arguments")
            if not isinstance(targs, dict):
                _reply(_invalid_params(req_id, "'arguments' must be a JSON object."))
            else:
                _reply(_handle_tool_call(req_id, tname, targs))
        elif req_id is not None:
            _reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main()
