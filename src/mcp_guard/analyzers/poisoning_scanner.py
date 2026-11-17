"""Security scanner for MCP tool poisoning, prompt injection, steganography, and sink risks."""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any

from mcp_guard.models import Finding, ToolDefinition
from mcp_guard.rules_catalog import get_rule

# Invisible / Zero-Width / Bidirectional override codepoints commonly abused for smuggling
INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2060,  # WORD JOINER
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)

# MCP-SEC-001: Direct Prompt Injection / System Override
_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|OVERRIDE|ADMIN|PROMPT)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*(?:SYSTEM|IMPORTANT|ADMIN\s+OVERRIDE|OVERRIDE)\s*\]", re.IGNORECASE),
    re.compile(
        r"\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|existing|system)\s+"
        r"(?:instructions?|prompts?|rules?|directives?|guidelines?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:new|updated)\s+system\s+(?:instruction|prompt|directive)\b", re.IGNORECASE),
    re.compile(
        r"\byou\s+must\s+(?:now\s+)?(?:obey|follow)\s+these\s+(?:hidden|secret|new)\s+instructions?\b",
        re.IGNORECASE,
    ),
)

# MCP-SEC-002: Credential & Sensitive File Exfiltration
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:~/|\$HOME/|%USERPROFILE%[/\\]|/home/[^/\s]+/)?\.ssh(?:[/\\])?(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)?\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:\.aws[/\\]credentials|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)", re.IGNORECASE),
    re.compile(r"(?:/etc/shadow|/etc/passwd)\b"),
    re.compile(r"(?:\.npmrc|\.netrc|\.pypirc|\.kube[/\\]config|\.docker[/\\]config\.json)\b", re.IGNORECASE),
    re.compile(
        r"(?:~/|\./|/)?\.env(?:\.(?:local|prod|production|dev))?\b.*?\b(?:read|load|send|include|cat|dump|exfiltrate|pass|contents?)\b"
        r"|\b(?:read|load|send|include|cat|dump|exfiltrate|steal)\b.{0,40}(?:~/|\./|/)?\.env(?:\.(?:local|prod|production|dev))?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:read|steal|exfiltrate|dump|extract|leak|send)\b.{0,45}\b"
        r"(?:api[_\s-]?keys?|secret[_\s-]?tokens?|private[_\s-]?keys?|credentials?|keychain|browser\s+cookies?|login\s+data)\b",
        re.IGNORECASE,
    ),
)

# MCP-SEC-004: Cross-Tool Shadowing & Hijacking
_SHADOWING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:before|prior\s+to|instead\s+of|whenever|after)\s+(?:calling|invoking|using|executing|running)\s+"
        r"(?:any\s+other\s+tool|(?:the\s+)?[a-zA-Z0-9_.-]+\s+tool|[a-zA-Z0-9]+_[a-zA-Z0-9_]+)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:override|intercept|hijack|replace|shadow|re-?route)\s+(?:calls?\s+to\s+|behavior\s+of\s+)?(?:other\s+)?(?:tools?|functions?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\balways\s+(?:call|invoke|run)\s+this\s+tool\s+first\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+(?:call|use|invoke)\s+(?:the\s+)?[a-zA-Z0-9_.-]+\s+tool\b", re.IGNORECASE),
)

# MCP-SEC-005: Covert Data Exfiltration Channel
_EXFIL_DOMAIN_PATTERN = re.compile(
    r"https?://(?:[a-z0-9-]+\.)*(?:webhook\.site|requestbin\.[a-z]+|pipedream\.net|ngrok\.(?:io|app|free)|"
    r"burpcollaborator\.net|oastify\.com|interact\.sh|pastebin\.com)\b",
    re.IGNORECASE,
)
_EXFIL_IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s'\"]*)?", re.IGNORECASE)
_EXFIL_CONTEXT_PATTERN = re.compile(
    r"\b(?:exfiltrate|forward|relay|upload|post|send|transmit|append|embed)\b.{0,70}"
    r"\b(?:conversation|chat\s+history|entire\s+context|user\s+prompt|system\s+prompt|all\s+messages|secrets?|tokens?|file\s+contents?)\b",
    re.IGNORECASE,
)

# MCP-SEC-006: Unconstrained Shell / Code Execution Sink
_EXEC_PARAM_NAMES: frozenset[str] = frozenset(
    {"cmd", "command", "shell", "shell_cmd", "bash", "sh", "powershell", "pwsh", "eval", "exec", "python_code", "code", "script", "cli_command"}
)
_EXEC_DESC_PATTERN = re.compile(
    r"\b(?:execute|run|eval(?:uate)?)\s+(?:arbitrary|any|raw|unrestricted)\s+(?:shell|bash|os|system|python|javascript|code|commands?)\b",
    re.IGNORECASE,
)

# MCP-SEC-007: Unbounded Path Traversal Parameter
_PATH_PARAM_NAMES: frozenset[str] = frozenset(
    {"path", "file_path", "filepath", "filename", "file", "dir", "directory", "folder", "target_path", "source_path", "dest_path", "output_path", "input_path"}
)

# MCP-SEC-008: Deceptive Output / Concealment Instruction
_CONCEALMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:do\s+not|don'?t|never)\s+(?:mention|tell|inform|reveal|show|disclose|display|notify|alert)\s+"
        r"(?:this|that|it|anything)?\s*(?:to\s+)?(?:the\s+)?(?:user|human|caller|operator)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:hide|conceal|mask|omit)\s+(?:this|the)\s+(?:action|tool\s+call|invocation|output|step|error)\b", re.IGNORECASE),
    re.compile(r"\bsilently\s+(?:send|read|upload|execute|run|forward|exfiltrate|delete|write)\b", re.IGNORECASE),
    re.compile(r"\bwithout\s+(?:telling|notifying|informing|alerting|asking)\s+(?:the\s+)?(?:user|human)\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+(?:that|to\s+the\s+user)\b", re.IGNORECASE),
)

# MCP-SEC-009: Destructive Action Without Confirmation Guard
_DESTRUCTIVE_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:delete|drop|truncate|purge|wipe|destroy|erase|rm|remove_all|transfer_funds|wire_money|format_disk|overwrite)(?:_|$)",
    re.IGNORECASE,
)
_DESTRUCTIVE_DESC_PATTERN = re.compile(
    r"\b(?:permanently\s+delete|irreversibly\s+(?:delete|remove|wipe|destroy)|drop\s+table|truncate\s+table|transfer\s+funds|wire\s+money)\b",
    re.IGNORECASE,
)
_CONFIRM_PARAM_NAMES: frozenset[str] = frozenset(
    {"confirm", "confirmed", "acknowledge", "acknowledged", "dry_run", "force", "confirmation"}
)

# MCP-SEC-010: Base64 / Hex Encoded Obfuscation Payload
_BASE64_CANDIDATE_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_DECODE_COMMAND_PATTERN = re.compile(r"\b(?:base64\s+-d|atob\(|frombase64)\b", re.IGNORECASE)

# MCP-SEC-011: SSRF / Arbitrary URL Fetch Risk
_URL_PARAM_NAMES: frozenset[str] = frozenset(
    {"url", "uri", "endpoint", "webhook", "webhook_url", "callback_url", "target_url", "fetch_url", "href", "link"}
)
_SSRF_INTERNAL_PATTERN = re.compile(
    r"(?:169\.254\.169\.254|127\.0\.0\.1|0\.0\.0\.0|metadata\.google\.internal|\b(?:file|gopher|dict)://)",
    re.IGNORECASE,
)

_TRIVIAL_WILDCARD_PATTERNS = frozenset({".*", ".+", "^.*$", "^.+$"})


def _strip_invisible(text: str) -> str:
    return "".join(
        ch for ch in text
        if ord(ch) not in INVISIBLE_CODEPOINTS and not (0xE0000 <= ord(ch) <= 0xE007F)
    )


def _find_invisible_chars(text: str) -> list[str]:
    found: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in INVISIBLE_CODEPOINTS or (0xE0000 <= cp <= 0xE007F):
            found.append(f"U+{cp:04X}")
    return found


def _is_trivially_unbounded_pattern(pattern: Any) -> bool:
    if not isinstance(pattern, str) or not pattern.strip():
        return True
    return pattern.strip() in _TRIVIAL_WILDCARD_PATTERNS


def _decode_suspicious_base64(text: str) -> str | None:
    for match in _BASE64_CANDIDATE_PATTERN.finditer(text):
        token = match.group(0)
        if len(token) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
        except Exception:
            continue
        if len(raw) < 16:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
        if printable / max(1, len(decoded)) >= 0.85 and any(c == " " or c in ":/()[]{};" for c in decoded):
            return decoded
    return None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


class PoisoningScanner:
    """Scans MCP tool manifests for prompt injection, poisoning, steganography, and sink risks."""

    def scan_tools(self, tools: list[ToolDefinition]) -> list[Finding]:
        findings: list[Finding] = []
        for tool in tools:
            findings.extend(self.scan_tool(tool))
        findings.extend(self._scan_naming_ambiguities(tools))
        return findings

    def scan_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        seen_rules_per_location: set[tuple[str, str]] = set()

        def emit(rule_id: str, location: str, message: str, evidence: str = "") -> None:
            key = (rule_id, location)
            if key in seen_rules_per_location:
                return
            seen_rules_per_location.add(key)
            rule = get_rule(rule_id)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    category=rule.category,
                    severity=rule.severity,
                    tool_name=tool.name or "<unnamed>",
                    location=location,
                    message=message,
                    evidence=evidence[:240],
                    remediation=rule.remediation,
                )
            )

        # 1. Inspect tool name & all textual fields (descriptions, defaults, enums, examples)
        text_segments: list[tuple[str, str]] = [("name", tool.name), ("description", tool.description)]
        if isinstance(tool.input_schema, dict):
            self._collect_schema_texts(tool.input_schema, "inputSchema", text_segments, depth=0)

        for loc, raw_text in text_segments:
            if not raw_text:
                continue

            # MCP-SEC-003: Steganographic Zero-Width / Bidi / Tag chars
            inv = _find_invisible_chars(raw_text)
            if inv:
                unique_cps = sorted(set(inv))
                emit(
                    "MCP-SEC-003",
                    loc,
                    f"Detected {len(inv)} hidden/invisible Unicode character(s): {', '.join(unique_cps)}.",
                    evidence=f"Codepoints: {', '.join(unique_cps)} in {raw_text!r}",
                )

            # Normalize out invisible characters so obfuscated keywords still match downstream rules
            clean_text = _strip_invisible(raw_text)

            # MCP-SEC-001: Direct Prompt Injection
            for pat in _PROMPT_INJECTION_PATTERNS:
                m = pat.search(clean_text)
                if m:
                    emit(
                        "MCP-SEC-001",
                        loc,
                        "Prompt injection or system override directive detected in tool metadata.",
                        evidence=m.group(0),
                    )
                    break

            # MCP-SEC-002: Credential & Sensitive File Exfiltration
            for pat in _CREDENTIAL_PATTERNS:
                m = pat.search(clean_text)
                if m:
                    emit(
                        "MCP-SEC-002",
                        loc,
                        "Reference to sensitive credentials or secret files detected.",
                        evidence=m.group(0),
                    )
                    break

            # MCP-SEC-004: Cross-Tool Shadowing
            for pat in _SHADOWING_PATTERNS:
                m = pat.search(clean_text)
                if m:
                    emit(
                        "MCP-SEC-004",
                        loc,
                        "Cross-tool shadowing or invocation hijacking instruction detected.",
                        evidence=m.group(0),
                    )
                    break

            # MCP-SEC-005: Covert Data Exfiltration Channel
            exfil_match = (
                _EXFIL_DOMAIN_PATTERN.search(clean_text)
                or _EXFIL_IP_URL_PATTERN.search(clean_text)
                or _EXFIL_CONTEXT_PATTERN.search(clean_text)
            )
            if exfil_match:
                emit(
                    "MCP-SEC-005",
                    loc,
                    "Potential covert exfiltration endpoint or context-forwarding instruction detected.",
                    evidence=exfil_match.group(0),
                )

            # MCP-SEC-008: Deceptive Output / Concealment
            for pat in _CONCEALMENT_PATTERNS:
                m = pat.search(clean_text)
                if m:
                    emit(
                        "MCP-SEC-008",
                        loc,
                        "Deceptive instruction attempting to conceal tool behavior from the user.",
                        evidence=m.group(0),
                    )
                    break

            # MCP-SEC-010: Base64 / Hex Obfuscation Payload
            decoded_b64 = _decode_suspicious_base64(clean_text)
            if decoded_b64 is not None:
                emit(
                    "MCP-SEC-010",
                    loc,
                    "Suspicious Base64-encoded plaintext payload embedded in metadata.",
                    evidence=f"Decoded preview: {decoded_b64[:120]!r}",
                )
            else:
                hex_match = _HEX_ESCAPE_PATTERN.search(clean_text) or _DECODE_COMMAND_PATTERN.search(clean_text)
                if hex_match:
                    emit(
                        "MCP-SEC-010",
                        loc,
                        "Encoded/obfuscated hex sequence or decode instruction detected.",
                        evidence=hex_match.group(0),
                    )

            # MCP-SEC-011: Explicit internal/SSRF schemes in text
            ssrf_text_match = _SSRF_INTERNAL_PATTERN.search(clean_text)
            if ssrf_text_match:
                emit(
                    "MCP-SEC-011",
                    loc,
                    "Internal metadata address or dangerous URI scheme referenced.",
                    evidence=ssrf_text_match.group(0),
                )

            # MCP-SEC-006: Description explicitly advertises arbitrary shell/code execution
            if loc == "description" and _EXEC_DESC_PATTERN.search(clean_text):
                has_enum_guard = self._schema_has_any_enum(tool.input_schema)
                if not has_enum_guard:
                    emit(
                        "MCP-SEC-006",
                        loc,
                        "Tool advertises arbitrary command or code execution without an enum allowlist.",
                        evidence=clean_text[:160],
                    )

        # 2. Parameter-level sink & structural risk analysis
        if isinstance(tool.input_schema, dict):
            self._inspect_schema_parameters(tool, tool.input_schema, "inputSchema", emit, depth=0)

        # 3. MCP-SEC-009: Destructive action without confirmation parameter or destructiveHint
        clean_desc = _strip_invisible(tool.description)
        is_destructive = bool(
            _DESTRUCTIVE_NAME_PATTERN.search(tool.name) or _DESTRUCTIVE_DESC_PATTERN.search(clean_desc)
        )
        if is_destructive:
            prop_names_lower = self._collect_property_names(tool.input_schema)
            has_confirm_param = bool(prop_names_lower & _CONFIRM_PARAM_NAMES)
            has_destructive_hint = tool.annotations.get("destructiveHint") is True
            if not has_confirm_param and not has_destructive_hint:
                emit(
                    "MCP-SEC-009",
                    "inputSchema",
                    (
                        f"Destructive tool {tool.name!r} lacks a boolean confirmation/dry_run guard "
                        "parameter and annotations.destructiveHint."
                    ),
                    evidence=f"tool={tool.name}, properties={sorted(prop_names_lower)}",
                )

        return findings

    def _inspect_schema_parameters(
        self,
        tool: ToolDefinition,
        node: dict[str, Any],
        location: str,
        emit: Any,
        depth: int,
    ) -> None:
        if depth > 12 or not isinstance(node, dict):
            return
        props = node.get("properties")
        if not isinstance(props, dict):
            return

        for prop_name, prop_schema in props.items():
            if not isinstance(prop_schema, dict):
                continue
            prop_loc = f"{location}.properties.{prop_name}"
            norm_name = prop_name.strip().lower()
            has_enum = isinstance(prop_schema.get("enum"), list) and len(prop_schema["enum"]) > 0
            has_strict_pattern = not _is_trivially_unbounded_pattern(prop_schema.get("pattern"))

            # MCP-SEC-006: Shell / Code Execution parameter
            if norm_name in _EXEC_PARAM_NAMES and not has_enum and not has_strict_pattern:
                emit(
                    "MCP-SEC-006",
                    prop_loc,
                    f"Parameter {prop_name!r} acts as an unconstrained command/code execution sink.",
                    evidence=repr(prop_schema),
                )

            # MCP-SEC-007: Unbounded Path Traversal parameter
            if (
                norm_name in _PATH_PARAM_NAMES
                and prop_schema.get("type") == "string"
                and not has_enum
                and not has_strict_pattern
            ):
                emit(
                    "MCP-SEC-007",
                    prop_loc,
                    f"Filesystem path parameter {prop_name!r} has no regex 'pattern' or 'enum' restriction.",
                    evidence=repr(prop_schema),
                )

            # MCP-SEC-011: Unconstrained URL fetch parameter (SSRF)
            if (
                norm_name in _URL_PARAM_NAMES
                and prop_schema.get("type") == "string"
                and not has_enum
                and not has_strict_pattern
            ):
                emit(
                    "MCP-SEC-011",
                    prop_loc,
                    f"URL parameter {prop_name!r} lacks scheme/host 'pattern' or 'enum' allowlist (SSRF risk).",
                    evidence=repr(prop_schema),
                )

            if isinstance(prop_schema.get("properties"), dict):
                self._inspect_schema_parameters(tool, prop_schema, prop_loc, emit, depth + 1)
            if isinstance(prop_schema.get("items"), dict) and isinstance(prop_schema["items"].get("properties"), dict):
                self._inspect_schema_parameters(
                    tool, prop_schema["items"], f"{prop_loc}.items", emit, depth + 1
                )

    def _collect_schema_texts(
        self,
        node: Any,
        location: str,
        out: list[tuple[str, str]],
        depth: int,
    ) -> None:
        if depth > 12:
            return
        if isinstance(node, dict):
            for key in ("description", "title", "default"):
                val = node.get(key)
                if isinstance(val, str):
                    out.append((f"{location}.{key}", val))
            for list_key in ("enum", "examples"):
                vals = node.get(list_key)
                if isinstance(vals, list):
                    for idx, item in enumerate(vals):
                        if isinstance(item, str):
                            out.append((f"{location}.{list_key}[{idx}]", item))
            for k, v in node.items():
                if k in {"properties", "$defs", "definitions"} and isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        self._collect_schema_texts(sub_v, f"{location}.{k}.{sub_k}", out, depth + 1)
                elif k in {"items", "additionalProperties"} and isinstance(v, dict):
                    self._collect_schema_texts(v, f"{location}.{k}", out, depth + 1)
                elif k in {"anyOf", "oneOf", "allOf"} and isinstance(v, list):
                    for idx, item in enumerate(v):
                        self._collect_schema_texts(item, f"{location}.{k}[{idx}]", out, depth + 1)

    @staticmethod
    def _collect_property_names(schema: dict[str, Any] | None) -> set[str]:
        if not isinstance(schema, dict):
            return set()
        props = schema.get("properties")
        if not isinstance(props, dict):
            return set()
        return {str(k).strip().lower() for k in props.keys()}

    @staticmethod
    def _schema_has_any_enum(schema: dict[str, Any] | None) -> bool:
        if not isinstance(schema, dict):
            return False
        props = schema.get("properties")
        if not isinstance(props, dict):
            return False
        return any(
            isinstance(v, dict) and isinstance(v.get("enum"), list) and len(v["enum"]) > 0
            for v in props.values()
        )

    def _scan_naming_ambiguities(self, tools: list[ToolDefinition]) -> list[Finding]:
        """Detect MCP-SEC-012 across a server's registered tool list."""
        findings: list[Finding] = []
        rule = get_rule("MCP-SEC-012")
        seen_exact: dict[str, int] = {}
        seen_normalized: dict[str, str] = {}

        for idx, tool in enumerate(tools):
            name = tool.name
            if not name:
                continue

            # Non-ASCII homoglyph check inside tool name
            non_ascii = [ch for ch in name if ord(ch) > 127]
            if non_ascii:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        tool_name=name,
                        location="name",
                        message=(
                            f"Tool name {name!r} contains non-ASCII character(s) "
                            f"({', '.join(unicodedata.name(c, f'U+{ord(c):04X}') for c in non_ascii)}), "
                            "which may indicate homoglyph spoofing."
                        ),
                        evidence=name,
                        remediation=rule.remediation,
                    )
                )

            if name in seen_exact:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        tool_name=name,
                        location="name",
                        message=f"Duplicate tool name {name!r} registered multiple times (first at index {seen_exact[name]}).",
                        evidence=name,
                        remediation=rule.remediation,
                    )
                )
            else:
                seen_exact[name] = idx

            norm = re.sub(r"[-_\s]+", "", name.lower())
            if norm in seen_normalized and seen_normalized[norm] != name:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        tool_name=name,
                        location="name",
                        message=(
                            f"Tool name {name!r} collides with normalized form of {seen_normalized[norm]!r}."
                        ),
                        evidence=f"{seen_normalized[norm]} vs {name}",
                        remediation=rule.remediation,
                    )
                )
            else:
                seen_normalized[norm] = name

        # Check near-identical typosquatting (edit distance == 1 with shared prefix >= 4)
        unique_names = list(seen_exact.keys())
        flagged_pairs: set[tuple[str, str]] = set()
        for i in range(len(unique_names)):
            for j in range(i + 1, len(unique_names)):
                a, b = unique_names[i], unique_names[j]
                if min(len(a), len(b)) < 6:
                    continue
                if a[:4].lower() != b[:4].lower():
                    continue
                if _levenshtein(a.lower(), b.lower()) == 1:
                    pair = (min(a, b), max(a, b))
                    if pair not in flagged_pairs:
                        flagged_pairs.add(pair)
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                title=rule.title,
                                category=rule.category,
                                severity=rule.severity,
                                tool_name=b,
                                location="name",
                                message=f"Tool name {b!r} differs by only 1 character from {a!r} (typosquatting/ambiguity risk).",
                                evidence=f"{a} vs {b}",
                                remediation=rule.remediation,
                            )
                        )

        return findings
