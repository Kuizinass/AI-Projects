"""Live MCP handshake adapter (stdio).

v0.1 reads whatever tool definitions are declared in config. But most servers
don't declare tools in config at all — the real definitions only appear when you
handshake with the running server. This adapter speaks minimal MCP over stdio to
enumerate the actual tools/resources a server exposes.

Safety: launching a server means EXECUTING it. This module never runs anything
without an explicit consent callback returning True. Scanning untrusted servers
should happen in a sandbox — the caller is responsible for that decision.

Implements just enough of the JSON-RPC handshake (initialize -> initialized ->
tools/list) to enumerate tools. No third-party MCP SDK dependency.
"""
from __future__ import annotations

import json
import subprocess
import time
from typing import Callable

from blastscope.models import ServerConfig, ToolDefinition

PROTOCOL_VERSION = "2024-11-05"


class HandshakeError(RuntimeError):
    pass


def _rpc(proc: subprocess.Popen, msg: dict, timeout: float) -> None:
    assert proc.stdin
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def _read_response(proc: subprocess.Popen, want_id: int, timeout: float) -> dict:
    assert proc.stdout
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise HandshakeError(f"server exited early (code {proc.returncode})")
            continue
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue  # servers sometimes emit log lines on stdout
        if msg.get("id") == want_id:
            return msg
    raise HandshakeError("timed out waiting for server response")


def enumerate_stdio_tools(server: ServerConfig,
                          consent: Callable[[ServerConfig], bool],
                          timeout: float = 10.0) -> list[ToolDefinition]:
    """Launch a stdio MCP server and return its live tool definitions."""
    if not server.command:
        raise HandshakeError("server has no command to launch")
    if not consent(server):
        raise HandshakeError("consent declined")

    cmd = [server.command] + server.args
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, env=_merged_env(server),
        )
    except (FileNotFoundError, OSError) as e:
        raise HandshakeError(f"could not launch server: {e}") from e

    try:
        _rpc(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "blastscope", "version": "0.5.0"},
            },
        }, timeout)
        _read_response(proc, 1, timeout)

        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout)

        _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, timeout)
        resp = _read_response(proc, 2, timeout)

        tools_raw = (resp.get("result") or {}).get("tools", [])
        tools = [
            ToolDefinition(
                name=str(t.get("name", "")),
                description=str(t.get("description", "")),
                input_schema=t.get("inputSchema", {}) or {},
                annotations=t.get("annotations", {}) or {},
            )
            for t in tools_raw
        ]
        return tools
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


def _merged_env(server: ServerConfig) -> dict | None:
    import os
    if not server.env:
        return None
    env = os.environ.copy()
    env.update(server.env)
    return env


def enrich_installation(inst, consent, timeout: float = 10.0) -> dict[str, str]:
    """Best-effort: populate each stdio server's .tools via live handshake.

    Returns {server_name: error_string} for servers that could not be enumerated.
    Servers that already carry declared tools are left untouched.
    """
    errors: dict[str, str] = {}
    for server in inst.servers:
        if server.tools:
            continue
        if server.transport not in ("stdio", ""):
            continue
        try:
            server.tools = enumerate_stdio_tools(server, consent, timeout)
        except HandshakeError as e:
            errors[server.name] = str(e)
    return errors
