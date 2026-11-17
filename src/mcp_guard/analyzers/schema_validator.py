"""JSON Schema contract validator for MCP tool definitions."""

from __future__ import annotations

from typing import Any

from mcp_guard.models import Finding, ToolDefinition
from mcp_guard.rules_catalog import get_rule

VALID_JSON_SCHEMA_TYPES = frozenset(
    {"string", "integer", "number", "boolean", "array", "object", "null"}
)
STRING_CONSTRAINTS = frozenset({"maxLength", "pattern", "format", "enum", "const"})
MAX_SCHEMA_DEPTH = 16


class SchemaValidator:
    """Validates MCP tool metadata and inputSchema structure against MCP-SCHEMA-001..008."""

    def scan_tools(self, tools: list[ToolDefinition]) -> list[Finding]:
        findings: list[Finding] = []
        for tool in tools:
            findings.extend(self.scan_tool(tool))
        return findings

    def scan_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []

        # MCP-SCHEMA-002: Missing or too-short top-level description
        desc = (tool.description or "").strip()
        if len(desc) < 10:
            findings.append(
                self._make_finding(
                    rule_id="MCP-SCHEMA-002",
                    tool_name=tool.name,
                    location="description",
                    message=(
                        "Tool is missing a description."
                        if not desc
                        else f"Tool description is too short ({len(desc)} chars; minimum recommended is 10)."
                    ),
                    evidence=repr(tool.description),
                )
            )

        # MCP-SCHEMA-001: Missing inputSchema or root type != 'object'
        schema = tool.input_schema
        if not isinstance(schema, dict) or schema.get("type") != "object":
            actual_type = None if not isinstance(schema, dict) else schema.get("type")
            findings.append(
                self._make_finding(
                    rule_id="MCP-SCHEMA-001",
                    tool_name=tool.name,
                    location="inputSchema",
                    message=(
                        "Tool is missing 'inputSchema'."
                        if not isinstance(schema, dict)
                        else f"Root inputSchema 'type' must be 'object', got {actual_type!r}."
                    ),
                    evidence=repr(actual_type),
                )
            )
            return findings

        # Validate local $ref integrity & cycles (MCP-SCHEMA-008)
        self._check_refs(schema, tool.name, findings)

        # Recursively validate root object and nested properties
        self._validate_object_node(
            node=schema,
            tool_name=tool.name,
            location="inputSchema",
            findings=findings,
            depth=0,
        )
        return findings

    def _validate_object_node(
        self,
        node: dict[str, Any],
        tool_name: str,
        location: str,
        findings: list[Finding],
        depth: int,
    ) -> None:
        if depth > MAX_SCHEMA_DEPTH:
            return

        # Check object node's declared type if present
        self._check_type_validity(node, tool_name, location, findings)

        properties = node.get("properties")
        if properties is not None and not isinstance(properties, dict):
            findings.append(
                self._make_finding(
                    rule_id="MCP-SCHEMA-008",
                    tool_name=tool_name,
                    location=f"{location}.properties",
                    message=f"'properties' must be a JSON object, got {type(properties).__name__}.",
                    evidence=repr(properties),
                )
            )
            properties = {}

        prop_dict: dict[str, Any] = properties if isinstance(properties, dict) else {}

        # MCP-SCHEMA-005: additionalProperties: false check
        if node.get("additionalProperties") is not False:
            findings.append(
                self._make_finding(
                    rule_id="MCP-SCHEMA-005",
                    tool_name=tool_name,
                    location=f"{location}.additionalProperties",
                    message="Object schema does not explicitly set 'additionalProperties: false'.",
                    evidence=repr(node.get("additionalProperties")),
                )
            )

        # MCP-SCHEMA-004: required array references undefined property
        required = node.get("required")
        if required is not None:
            if not isinstance(required, list):
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-008",
                        tool_name=tool_name,
                        location=f"{location}.required",
                        message=f"'required' must be an array of strings, got {type(required).__name__}.",
                        evidence=repr(required),
                    )
                )
            else:
                for req_key in required:
                    if not isinstance(req_key, str) or req_key not in prop_dict:
                        findings.append(
                            self._make_finding(
                                rule_id="MCP-SCHEMA-004",
                                tool_name=tool_name,
                                location=f"{location}.required",
                                message=f"Required field {req_key!r} is not defined in 'properties'.",
                                evidence=repr(req_key),
                            )
                        )

        # Validate each property
        for prop_name, prop_schema in prop_dict.items():
            prop_loc = f"{location}.properties.{prop_name}"
            if not isinstance(prop_schema, dict):
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-008",
                        tool_name=tool_name,
                        location=prop_loc,
                        message=f"Property schema for {prop_name!r} must be an object.",
                        evidence=repr(prop_schema),
                    )
                )
                continue

            self._validate_property_node(prop_name, prop_schema, tool_name, prop_loc, findings, depth + 1)

    def _validate_property_node(
        self,
        prop_name: str,
        prop_schema: dict[str, Any],
        tool_name: str,
        location: str,
        findings: list[Finding],
        depth: int,
    ) -> None:
        if depth > MAX_SCHEMA_DEPTH:
            return

        has_combinator = any(k in prop_schema for k in ("anyOf", "oneOf", "allOf", "$ref"))
        prop_type = prop_schema.get("type")
        prop_desc = prop_schema.get("description")

        # MCP-SCHEMA-003: missing type or description
        missing_parts: list[str] = []
        if prop_type is None and not has_combinator:
            missing_parts.append("'type'")
        if not isinstance(prop_desc, str) or not prop_desc.strip():
            missing_parts.append("'description'")

        if missing_parts:
            findings.append(
                self._make_finding(
                    rule_id="MCP-SCHEMA-003",
                    tool_name=tool_name,
                    location=location,
                    message=f"Parameter {prop_name!r} is missing {' and '.join(missing_parts)}.",
                    evidence=repr({k: prop_schema.get(k) for k in ("type", "description")}),
                )
            )

        # MCP-SCHEMA-008: valid JSON Schema types
        types_list = self._check_type_validity(prop_schema, tool_name, location, findings)

        # MCP-SCHEMA-006: string parameter missing length/format/pattern/enum constraint
        if "string" in types_list:
            if not any(k in prop_schema for k in STRING_CONSTRAINTS):
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-006",
                        tool_name=tool_name,
                        location=location,
                        message=(
                            f"String parameter {prop_name!r} lacks length or format constraints "
                            "(maxLength, pattern, format, or enum)."
                        ),
                        evidence=repr(prop_schema),
                    )
                )

        # MCP-SCHEMA-007: array parameter missing 'items'
        if "array" in types_list:
            items = prop_schema.get("items")
            if not isinstance(items, dict):
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-007",
                        tool_name=tool_name,
                        location=location,
                        message=f"Array parameter {prop_name!r} is missing an 'items' sub-schema object.",
                        evidence=repr(items),
                    )
                )
            else:
                self._check_type_validity(items, tool_name, f"{location}.items", findings)
                if items.get("type") == "object" or "properties" in items:
                    self._validate_object_node(items, tool_name, f"{location}.items", findings, depth + 1)

        # Nested object validation
        if "object" in types_list or "properties" in prop_schema:
            self._validate_object_node(prop_schema, tool_name, location, findings, depth + 1)

    def _check_type_validity(
        self,
        node: dict[str, Any],
        tool_name: str,
        location: str,
        findings: list[Finding],
    ) -> list[str]:
        raw_type = node.get("type")
        if raw_type is None:
            return []

        if isinstance(raw_type, str):
            types = [raw_type]
        elif isinstance(raw_type, list) and all(isinstance(t, str) for t in raw_type) and len(raw_type) > 0:
            types = list(raw_type)
        else:
            findings.append(
                self._make_finding(
                    rule_id="MCP-SCHEMA-008",
                    tool_name=tool_name,
                    location=f"{location}.type",
                    message=f"Malformed JSON Schema 'type' value: {raw_type!r}.",
                    evidence=repr(raw_type),
                )
            )
            return []

        for t in types:
            if t not in VALID_JSON_SCHEMA_TYPES:
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-008",
                        tool_name=tool_name,
                        location=f"{location}.type",
                        message=f"Invalid JSON Schema type {t!r}.",
                        evidence=repr(t),
                    )
                )
        return types

    def _check_refs(self, root_schema: dict[str, Any], tool_name: str, findings: list[Finding]) -> None:
        refs_found: list[tuple[str, str]] = []

        def _collect(obj: Any, loc: str, depth: int) -> None:
            if depth > MAX_SCHEMA_DEPTH:
                return
            if isinstance(obj, dict):
                if "$ref" in obj:
                    refs_found.append((loc, str(obj["$ref"])))
                for k, v in obj.items():
                    _collect(v, f"{loc}.{k}", depth + 1)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    _collect(item, f"{loc}[{idx}]", depth + 1)

        _collect(root_schema, "inputSchema", 0)

        for loc, ref_str in refs_found:
            if not ref_str.startswith("#/"):
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-008",
                        tool_name=tool_name,
                        location=loc,
                        message=f"External or unsupported '$ref' pointer {ref_str!r}.",
                        evidence=ref_str,
                    )
                )
                continue

            if self._resolve_pointer(root_schema, ref_str) is None:
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-008",
                        tool_name=tool_name,
                        location=loc,
                        message=f"Broken local '$ref' target {ref_str!r} does not exist in schema.",
                        evidence=ref_str,
                    )
                )
                continue

            if self._has_ref_cycle(root_schema, ref_str, visited=set()):
                findings.append(
                    self._make_finding(
                        rule_id="MCP-SCHEMA-008",
                        tool_name=tool_name,
                        location=loc,
                        message=f"Cyclic '$ref' chain detected starting at {ref_str!r}.",
                        evidence=ref_str,
                    )
                )

    @staticmethod
    def _resolve_pointer(root: dict[str, Any], pointer: str) -> Any:
        parts = pointer[2:].split("/")
        cur: Any = root
        for part in parts:
            unescaped = part.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict) and unescaped in cur:
                cur = cur[unescaped]
            else:
                return None
        return cur

    def _has_ref_cycle(self, root: dict[str, Any], pointer: str, visited: set[str]) -> bool:
        if pointer in visited:
            return True
        target = self._resolve_pointer(root, pointer)
        if not isinstance(target, dict):
            return False
        next_visited = visited | {pointer}
        nested_refs: list[str] = []

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                if "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("#/"):
                    nested_refs.append(node["$ref"])
                for v in node.values():
                    _walk(v)
            elif isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(target)
        return any(self._has_ref_cycle(root, ref, next_visited) for ref in nested_refs)

    @staticmethod
    def _make_finding(
        rule_id: str,
        tool_name: str,
        location: str,
        message: str,
        evidence: str = "",
    ) -> Finding:
        rule = get_rule(rule_id)
        return Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            tool_name=tool_name or "<unnamed>",
            location=location,
            message=message,
            evidence=evidence[:240],
            remediation=rule.remediation,
        )
