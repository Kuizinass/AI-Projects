"""Static adapter: parse MCP client config files into the normalised model.

Supports the `mcpServers` object used by Claude Desktop, Claude Code, Cursor and
Windsurf, the `servers` object used by VS Code, and optional tool-manifest files
(a JSON list or {"tools": [...]}) for pre-handshake inspection of tool definitions.
"""
from __future__ import annotations

import json
import os
import platform
from pathlib import Path

from blastscope.models import Installation, ServerConfig, ToolDefinition

# Known client config locations, per OS. Expanded at runtime.
KNOWN_CONFIGS: dict[str, dict[str, list[str]]] = {
    "Claude Desktop": {
        "Darwin": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "Windows": ["%APPDATA%/Claude/claude_desktop_config.json"],
        "Linux": ["~/.config/Claude/claude_desktop_config.json"],
    },
    "Claude Code": {
        "*": ["~/.claude.json", ".mcp.json"],
    },
    "Cursor": {
        "*": ["~/.cursor/mcp.json", ".cursor/mcp.json"],
    },
    "Windsurf": {
        "*": ["~/.codeium/windsurf/mcp_config.json"],
    },
    "VS Code": {
        "*": ["~/.vscode/mcp.json", ".vscode/mcp.json"],
    },
}


def discover_config_paths() -> dict[str, list[Path]]:
    """Return {client_name: [existing config paths]} for this machine."""
    system = platform.system()
    found: dict[str, list[Path]] = {}
    for client, per_os in KNOWN_CONFIGS.items():
        candidates = per_os.get(system, []) + per_os.get("*", [])
        paths = []
        for c in candidates:
            p = Path(os.path.expandvars(os.path.expanduser(c)))
            if p.is_file():
                paths.append(p)
        if paths:
            found[client] = paths
    return found


def _parse_tools(obj) -> list[ToolDefinition]:
    tools = []
    items = obj.get("tools", obj) if isinstance(obj, dict) else obj
    if not isinstance(items, list):
        return tools
    for t in items:
        if isinstance(t, dict) and "name" in t:
            tools.append(ToolDefinition(
                name=str(t.get("name", "")),
                description=str(t.get("description", "")),
                input_schema=t.get("inputSchema", t.get("input_schema", {})) or {},
                annotations=t.get("annotations", {}) or {},
            ))
    return tools


def parse_config_file(path: Path, client: str = "unknown") -> list[ServerConfig]:
    """Parse one client config file into ServerConfig objects."""
    data = json.loads(path.read_text(encoding="utf-8"))
    servers_obj = data.get("mcpServers") or data.get("servers") or {}
    servers: list[ServerConfig] = []
    for name, cfg in servers_obj.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url", "") or cfg.get("serverUrl", "")
        transport = cfg.get("type", "") or ("sse" if url else "stdio")
        servers.append(ServerConfig(
            name=name,
            transport=str(transport),
            command=str(cfg.get("command", "")),
            args=[str(a) for a in cfg.get("args", [])],
            env={str(k): str(v) for k, v in (cfg.get("env") or {}).items()},
            url=str(url),
            source_client=client,
            source_path=str(path),
            tools=_parse_tools(cfg.get("tools", [])),
            raw=cfg,
        ))
    return servers


def parse_manifest_file(path: Path, server_name: str | None = None) -> ServerConfig:
    """Parse a standalone tool-manifest JSON into a pseudo-server for inspection."""
    data = json.loads(path.read_text(encoding="utf-8"))
    name = server_name or (data.get("name") if isinstance(data, dict) else None) or path.stem
    return ServerConfig(
        name=str(name),
        transport="manifest",
        source_client="manifest",
        source_path=str(path),
        tools=_parse_tools(data),
        raw=data if isinstance(data, dict) else {"tools": data},
    )


def build_installation(config_paths: list[Path] | None = None,
                       manifest_paths: list[Path] | None = None,
                       auto_discover: bool = True) -> Installation:
    inst = Installation()
    seen_paths: set[str] = set()

    if config_paths:
        for p in config_paths:
            inst.servers.extend(parse_config_file(p, client=f"--config {p.name}"))
            seen_paths.add(str(p.resolve()))
        inst.clients_found.append("explicit configs")

    if auto_discover and not config_paths:
        for client, paths in discover_config_paths().items():
            for p in paths:
                if str(p.resolve()) in seen_paths:
                    continue
                try:
                    inst.servers.extend(parse_config_file(p, client=client))
                    seen_paths.add(str(p.resolve()))
                    if client not in inst.clients_found:
                        inst.clients_found.append(client)
                except (json.JSONDecodeError, OSError):
                    continue

    for p in (manifest_paths or []):
        inst.servers.append(parse_manifest_file(p))

    return inst
