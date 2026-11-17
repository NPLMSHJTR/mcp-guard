"""Unit tests for JSON Schema contract validation (MCP-SCHEMA-001..008)."""

from __future__ import annotations

from mcp_guard.analyzers.schema_validator import SchemaValidator
from mcp_guard.models import ToolDefinition


def test_clean_hardened_schema_has_zero_findings() -> None:
    tool = ToolDefinition.from_dict(
        {
            "name": "query_metrics",
            "description": "Query aggregated service latency metrics for a time window.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service identifier.",
                        "maxLength": 64,
                        "pattern": "^[a-z0-9-]+$",
                    },
                    "buckets": {
                        "type": "array",
                        "description": "Histogram percentiles.",
                        "items": {"type": "number"},
                    },
                },
                "required": ["service"],
            },
        }
    )
    findings = SchemaValidator().scan_tool(tool)
    assert findings == []


def test_missing_schema_and_short_description() -> None:
    tool = ToolDefinition.from_dict({"name": "ping", "description": "hi"})
    findings = SchemaValidator().scan_tool(tool)
    rule_ids = {f.rule_id for f in findings}
    assert "MCP-SCHEMA-001" in rule_ids
    assert "MCP-SCHEMA-002" in rule_ids


def test_required_undefined_property_and_missing_constraints() -> None:
    tool = ToolDefinition.from_dict(
        {
            "name": "create_item",
            "description": "Create an item in the catalog with tags.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "tags": {"type": "array", "description": "Item tags."},
                },
                "required": ["title", "non_existent_field"],
            },
        }
    )
    findings = SchemaValidator().scan_tool(tool)
    rule_ids = {f.rule_id for f in findings}
    assert "MCP-SCHEMA-003" in rule_ids  # title missing description
    assert "MCP-SCHEMA-004" in rule_ids  # non_existent_field missing in properties
    assert "MCP-SCHEMA-005" in rule_ids  # additionalProperties: false missing
    assert "MCP-SCHEMA-006" in rule_ids  # title string missing constraints
    assert "MCP-SCHEMA-007" in rule_ids  # tags array missing items


def test_invalid_schema_type_broken_ref_and_cyclic_ref() -> None:
    tool = ToolDefinition.from_dict(
        {
            "name": "bad_refs",
            "description": "Tool containing broken and cyclic JSON Schema refs.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "$defs": {
                    "NodeA": {"$ref": "#/$defs/NodeB"},
                    "NodeB": {"$ref": "#/$defs/NodeA"},
                },
                "properties": {
                    "weird": {"type": "varchar", "description": "Invalid type name."},
                    "broken": {"$ref": "#/$defs/DoesNotExist", "description": "Broken pointer."},
                    "cycle": {"$ref": "#/$defs/NodeA", "description": "Cyclic pointer."},
                },
                "required": ["weird"],
            },
        }
    )
    findings = SchemaValidator().scan_tool(tool)
    schema_008 = [f for f in findings if f.rule_id == "MCP-SCHEMA-008"]
    assert len(schema_008) >= 3
