"""Cross-platform stdio MCP client with timeout protection and trace recording."""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

from mcp_guard.models import ToolDefinition
from mcp_guard.transport.jsonrpc import make_notification, make_request, parse_message

if TYPE_CHECKING:
    from mcp_guard.recorder.trace_manager import TraceRecorder


def split_command(cmd: str | Sequence[str]) -> list[str]:
    """Split a shell command string safely across POSIX and Windows platforms."""
    if not isinstance(cmd, str):
        return [str(part) for part in cmd]
    tokens = shlex.split(cmd, posix=(os.name != "nt"))
    cleaned: list[str] = []
    for tok in tokens:
        if len(tok) >= 2 and ((tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'")):
            cleaned.append(tok[1:-1])
        else:
            cleaned.append(tok)
    return cleaned


class StdioMCPClient:
    """Manages an MCP server child process over newline-delimited JSON-RPC 2.0 stdio."""

    def __init__(
        self,
        command: str | Sequence[str],
        timeout: float = 5.0,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        recorder: "TraceRecorder | None" = None,
    ) -> None:
        self.command = split_command(command)
        self.timeout = float(timeout)
        self.cwd = str(cwd) if cwd is not None else None
        self.env = env
        self.recorder = recorder

        self._proc: subprocess.Popen[str] | None = None
        self._stdout_queue: queue.Queue[str | None] = queue.Queue()
        self._stderr_lines: list[str] = []
        self._next_id = 1
        self._initialized = False

    def __enter__(self) -> "StdioMCPClient":
        self.start()
        self.initialize()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def start(self) -> None:
        if self._proc is not None:
            return
        if not self.command:
            raise ValueError("MCP server command cannot be empty.")

        proc_env = os.environ.copy()
        proc_env.setdefault("PYTHONIOENCODING", "utf-8")
        proc_env.setdefault("PYTHONUTF8", "1")
        if self.env:
            proc_env.update(self.env)

        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=self.cwd,
            env=proc_env,
        )

        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                self._stdout_queue.put(line)
        finally:
            self._stdout_queue.put(None)

    def _pump_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            if len(self._stderr_lines) < 200:
                self._stderr_lines.append(line.rstrip("\r\n"))

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        self._initialized = False
        if proc is None:
            return
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
            except OSError:
                pass
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream and not stream.closed:
                    stream.close()
            except OSError:
                pass

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self._stderr_lines[-10:])

    def _send_raw(self, message: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("MCP stdio process is not running.")
        if self._proc.poll() is not None:
            raise EOFError(
                f"MCP server exited with code {self._proc.returncode}. Stderr: {self.stderr_tail}"
            )
        encoded = json.dumps(message, ensure_ascii=False) + "\n"
        try:
            self._proc.stdin.write(encoded)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise EOFError(f"Failed writing to MCP server stdin: {exc}. Stderr: {self.stderr_tail}") from exc

    def _read_response_for_id(self, expected_id: int | str) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out after {self.timeout:.1f}s waiting for JSON-RPC response id={expected_id}."
                )
            try:
                raw_line = self._stdout_queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError(
                    f"Timed out after {self.timeout:.1f}s waiting for JSON-RPC response id={expected_id}."
                ) from exc

            if raw_line is None:
                rc = self._proc.returncode if self._proc else None
                raise EOFError(
                    f"MCP server closed stdout unexpectedly (exit_code={rc}). Stderr: {self.stderr_tail}"
                )

            stripped = raw_line.strip()
            if not stripped:
                continue

            try:
                msg = parse_message(stripped)
            except Exception:
                # Non-JSON frame returned where a JSON-RPC response was expected
                return {"_raw_invalid_frame": stripped}

            # Skip server-initiated notifications without id while waiting for our response
            if "id" not in msg and "method" in msg:
                if self.recorder is not None:
                    self.recorder.record("server->client", str(msg.get("method", "")), None, msg, 0.0)
                continue

            if msg.get("id") == expected_id:
                return msg

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        req_msg = make_request(req_id, method, params)

        if self.recorder is not None:
            self.recorder.record("client->server", method, req_id, req_msg, 0.0)

        start = time.perf_counter()
        self._send_raw(req_msg)
        resp = self._read_response_for_id(req_id)
        latency_ms = (time.perf_counter() - start) * 1000.0

        if self.recorder is not None:
            self.recorder.record("server->client", method, req_id, resp, latency_ms)
        return resp

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        note = make_notification(method, params)
        if self.recorder is not None:
            self.recorder.record("client->server", method, None, note, 0.0)
        self._send_raw(note)

    def initialize(self) -> dict[str, Any]:
        if self._initialized:
            return {}
        resp = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-guard", "version": "0.1.0"},
            },
        )
        if "error" in resp:
            raise RuntimeError(f"MCP initialize failed: {resp['error']}")
        self.notify("notifications/initialized")
        self._initialized = True
        return resp

    def list_tools(self) -> list[ToolDefinition]:
        resp = self.request("tools/list", {})
        if "error" in resp:
            raise RuntimeError(f"tools/list failed: {resp['error']}")
        result = resp.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise ValueError(f"Malformed tools/list result payload: {resp!r}")
        return [ToolDefinition.from_dict(item) for item in result["tools"]]

    def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments or {},
            },
        )
