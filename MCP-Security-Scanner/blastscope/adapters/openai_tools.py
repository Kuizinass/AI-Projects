"""OpenAI function-calling adapter.

Parses a JSON file of OpenAI tool/function definitions into the normalised model
so the same rule engine and composition analysis run over non-MCP agents.

Accepted shapes:
  [{"type": "function", "function": {"name":..., "description":..., "parameters":...}}, ...]
  [{"name":..., "description":..., "parameters":...}, ...]
  {"tools": [...either shape...]}
"""
from __future__ import annotations

import json
from pathlib import Path

from blastscope.models import ServerConfig, ToolDefinition


def parse_openai_tools_file(path: Path, name: str | None = None) -> ServerConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data.get("tools", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError(f"{path}: expected a list of tool definitions")

    tools: list[ToolDefinition] = []
    for item in items:
        fn = item.get("function", item) if isinstance(item, dict) else {}
        if not isinstance(fn, dict) or "name" not in fn:
            continue
        tools.append(ToolDefinition(
            name=str(fn.get("name", "")),
            description=str(fn.get("description", "")),
            input_schema=fn.get("parameters", {}) or {},
        ))

    return ServerConfig(
        name=name or Path(path).stem,
        transport="openai-tools",
        source_client="openai",
        source_path=str(path),
        tools=tools,
    )
