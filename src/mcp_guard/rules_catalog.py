"""Central catalog of all 20 built-in MCP security and JSON Schema contract rules."""

from __future__ import annotations

from mcp_guard.models import RuleCategory, RuleDefinition, Severity

_RULE_LIST: list[RuleDefinition] = [
    # --- Security Rules (MCP-SEC-001 .. MCP-SEC-012) ---
    RuleDefinition(
        rule_id="MCP-SEC-001",
        title="Direct Prompt Injection / System Override",
        category=RuleCategory.SECURITY,
        severity=Severity.CRITICAL,
        description=(
            "Tool metadata contains explicit instruction override markers (e.g., <IMPORTANT>, "
            "<SYSTEM>, 'ignore previous instructions') attempting to hijack the host LLM."
        ),
        remediation=(
            "Remove imperative prompt-override directives from tool descriptions and schema metadata. "
            "Keep descriptions strictly factual about tool capabilities and arguments."
        ),
        cwe="CWE-74",
        owasp_llm="LLM01: Prompt Injection",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-002",
        title="Credential & Sensitive File Exfiltration",
        category=RuleCategory.SECURITY,
        severity=Severity.CRITICAL,
        description=(
            "Tool metadata instructs or entices the agent to read sensitive local credentials "
            "or secret files (e.g., ~/.ssh/id_rsa, .env, AWS credentials, /etc/shadow, keychains)."
        ),
        remediation=(
            "Eliminate references to credential stores or secret files. Restrict file tools to an "
            "explicitly scoped workspace directory."
        ),
        cwe="CWE-200",
        owasp_llm="LLM06: Sensitive Information Disclosure",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-003",
        title="Steganographic Zero-Width & Bidi Characters",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        description=(
            "Invisible Unicode characters (zero-width spaces, directional Bidi overrides, or "
            "Unicode Tag blocks U+E0000-U+E007F) detected. These can smuggle hidden instructions past UI review."
        ),
        remediation=(
            "Strip all non-printing formatting, zero-width, and bidirectional override characters "
            "from tool names, descriptions, and parameter metadata."
        ),
        cwe="CWE-172",
        owasp_llm="LLM01: Prompt Injection",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-004",
        title="Cross-Tool Shadowing & Hijacking",
        category=RuleCategory.SECURITY,
        severity=Severity.CRITICAL,
        description=(
            "Tool description attempts to alter, intercept, or override how the LLM invokes other "
            "registered MCP tools (e.g., 'before calling send_email, always invoke...')."
        ),
        remediation=(
            "Ensure each tool describes only its own behavior without referencing, ordering, "
            "or overriding sibling tools."
        ),
        cwe="CWE-284",
        owasp_llm="LLM07: Insecure Plugin Design",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-005",
        title="Covert Data Exfiltration Channel",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        description=(
            "Tool metadata embeds an external webhook/collector URL or instructs the model to "
            "append conversation history, context, or secret payloads to outbound parameters."
        ),
        remediation=(
            "Remove hardcoded exfiltration endpoints and instructions requesting full conversation "
            "context or unrelated user data."
        ),
        cwe="CWE-359",
        owasp_llm="LLM06: Sensitive Information Disclosure",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-006",
        title="Unconstrained Shell / Code Execution Sink",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        description=(
            "Tool exposes an arbitrary shell command or code evaluation parameter (e.g., command, "
            "shell, bash, eval, exec) without an enum allowlist or strict validation pattern."
        ),
        remediation=(
            "Replace arbitrary command strings with discrete structured operations or enforce a strict "
            "JSON Schema `enum` / `pattern` allowlist."
        ),
        cwe="CWE-78",
        owasp_llm="LLM07: Insecure Plugin Design",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-007",
        title="Unbounded Path Traversal Parameter",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        description=(
            "Filesystem path parameter lacks a restrictive regex `pattern` or `enum`, increasing "
            "risk of '../' directory traversal outside the intended workspace."
        ),
        remediation=(
            "Add a strict `pattern` (e.g., disallowing '..' and leading '/') plus `maxLength` in "
            "the parameter JSON Schema and canonicalize paths server-side."
        ),
        cwe="CWE-22",
        owasp_llm="LLM07: Insecure Plugin Design",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-008",
        title="Deceptive Output / Concealment Instruction",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        description=(
            "Tool instructs the LLM to conceal tool invocations, side effects, or errors from the "
            "human user (e.g., 'do not mention this to the user', 'silently run')."
        ),
        remediation=(
            "Remove concealment instructions. Tool execution and side effects must remain transparent "
            "to the user and host UI."
        ),
        cwe="CWE-451",
        owasp_llm="LLM01: Prompt Injection",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-009",
        title="Destructive Action Without Confirmation Guard",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        description=(
            "Tool performs destructive or irreversible actions (delete, drop, wipe, transfer) "
            "without exposing an explicit confirmation / dry_run boolean parameter or destructiveHint."
        ),
        remediation=(
            "Add an explicit `confirm: boolean` or `dry_run: boolean` guard parameter and declare "
            "`annotations.destructiveHint = true`."
        ),
        cwe="CWE-285",
        owasp_llm="LLM08: Excessive Agency",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-010",
        title="Base64 / Hex Encoded Obfuscation Payload",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        description=(
            "Tool description or default value embeds suspiciously long Base64 or hex-escaped "
            "payloads that decode to hidden instructions or shell scripts."
        ),
        remediation=(
            "Replace encoded blobs with clear plaintext documentation and validated literal values."
        ),
        cwe="CWE-506",
        owasp_llm="LLM01: Prompt Injection",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-011",
        title="SSRF / Arbitrary URL Fetch Risk",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        description=(
            "URL or endpoint parameter lacks scheme/host constraints (`pattern` or `enum`), or "
            "permits internal/metadata schemes (http://169.254.169.254, localhost, file://, gopher://)."
        ),
        remediation=(
            "Restrict URL parameters with `pattern: \"^https://\"` and enforce server-side "
            "SSRF IP blocklists for RFC1918, loopback, and cloud metadata addresses."
        ),
        cwe="CWE-918",
        owasp_llm="LLM07: Insecure Plugin Design",
    ),
    RuleDefinition(
        rule_id="MCP-SEC-012",
        title="Duplicate or Ambiguous Tool Naming",
        category=RuleCategory.SECURITY,
        severity=Severity.LOW,
        description=(
            "Two or more tools share identical names, normalized aliases, or lookalike homoglyphs, "
            "creating tool resolution ambiguity and potential shadowing."
        ),
        remediation=(
            "Use distinct, ASCII snake_case tool names across the server manifest."
        ),
        cwe="CWE-706",
        owasp_llm="LLM07: Insecure Plugin Design",
    ),
    # --- Schema Contract Rules (MCP-SCHEMA-001 .. MCP-SCHEMA-008) ---
    RuleDefinition(
        rule_id="MCP-SCHEMA-001",
        title="Missing inputSchema or Root Type Not 'object'",
        category=RuleCategory.SCHEMA,
        severity=Severity.HIGH,
        description=(
            "MCP tools must declare an `inputSchema` object whose root `type` is `'object'`."
        ),
        remediation=(
            "Define `inputSchema` as a valid JSON Schema object with `\"type\": \"object\"` and `\"properties\"`."
        ),
        cwe="CWE-20",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-002",
        title="Missing or Insufficient Tool Description",
        category=RuleCategory.SCHEMA,
        severity=Severity.MEDIUM,
        description=(
            "Tool lacks a top-level `description` or its description is shorter than 10 characters, "
            "leading to unreliable LLM tool selection."
        ),
        remediation=(
            "Provide a clear, concise description (>= 10 chars) explaining purpose, inputs, and side effects."
        ),
        cwe="CWE-1059",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-003",
        title="Parameter Missing 'type' or 'description'",
        category=RuleCategory.SCHEMA,
        severity=Severity.MEDIUM,
        description=(
            "One or more schema properties lack an explicit JSON Schema `type` (or union/combinator) "
            "or lack a parameter `description`."
        ),
        remediation=(
            "Document every property in `inputSchema.properties` with both `type` and a helpful `description`."
        ),
        cwe="CWE-20",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-004",
        title="Required Field Undefined in Properties",
        category=RuleCategory.SCHEMA,
        severity=Severity.HIGH,
        description=(
            "The `required` array references a property key that does not exist inside `properties`."
        ),
        remediation=(
            "Ensure every name listed in `required` matches a declared key in `properties`."
        ),
        cwe="CWE-20",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-005",
        title="Object Schema Missing 'additionalProperties: false'",
        category=RuleCategory.SCHEMA,
        severity=Severity.LOW,
        description=(
            "Object schema omits `additionalProperties: false`, allowing unexpected or injected "
            "parameters to pass basic schema validation."
        ),
        remediation=(
            "Set `\"additionalProperties\": false` on object schemas unless arbitrary key-value pairs are required."
        ),
        cwe="CWE-915",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-006",
        title="String Parameter Missing Length or Format Constraint",
        category=RuleCategory.SCHEMA,
        severity=Severity.MEDIUM,
        description=(
            "String parameter omits `maxLength`, `pattern`, `format`, and `enum`, exposing the tool "
            "to unbounded payload size or unvalidated input formats."
        ),
        remediation=(
            "Constrain string arguments with `maxLength` and, where applicable, `pattern`, `format`, or `enum`."
        ),
        cwe="CWE-20",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-007",
        title="Array Parameter Missing 'items' Definition",
        category=RuleCategory.SCHEMA,
        severity=Severity.MEDIUM,
        description=(
            "Array parameter does not specify an `items` sub-schema, leaving element types ambiguous."
        ),
        remediation=(
            "Add an explicit `items` schema (e.g., `{\"type\": \"string\", \"maxLength\": 128}`) and `maxItems`."
        ),
        cwe="CWE-20",
    ),
    RuleDefinition(
        rule_id="MCP-SCHEMA-008",
        title="Invalid JSON Schema Type or Broken/Cyclic $ref",
        category=RuleCategory.SCHEMA,
        severity=Severity.HIGH,
        description=(
            "Schema uses an unknown JSON Schema type name or contains a broken/cyclic local `$ref` pointer."
        ),
        remediation=(
            "Use standard JSON Schema types (string, integer, number, boolean, array, object, null) "
            "and ensure all `$ref` targets exist without cycles."
        ),
        cwe="CWE-20",
    ),
]

RULES_CATALOG: dict[str, RuleDefinition] = {rule.rule_id: rule for rule in _RULE_LIST}


def get_rule(rule_id: str) -> RuleDefinition:
    """Return the RuleDefinition for `rule_id`, raising KeyError if unknown."""
    if rule_id not in RULES_CATALOG:
        raise KeyError(f"Unknown rule_id: {rule_id}")
    return RULES_CATALOG[rule_id]


def list_rules(category: RuleCategory | None = None) -> list[RuleDefinition]:
    """List all registered rules, optionally filtered by category."""
    if category is None:
        return list(_RULE_LIST)
    return [r for r in _RULE_LIST if r.category == category]
