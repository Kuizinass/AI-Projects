"""LangChain tools adapter.

Two entry points:
  1. parse_langchain_export(path) — reads a JSON export of tool metadata
     (list of {"name", "description", "args_schema"/"args"}).
  2. from_langchain_tools(tools, name) — accepts live LangChain BaseTool objects
     in-process (duck-typed: anything with .name and .description works):

         from blastscope.adapters.langchain_tools import from_langchain_tools
         server = from_langchain_tools(my_agent_tools, name="support-agent")
"""
from __future__ import annotations

import json
from pathlib import Path

from blastscope.models import ServerConfig, ToolDefinition


def parse_langchain_export(path: Path, name: str | None = None) -> ServerConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data.get("tools", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError(f"{path}: expected a list of tool definitions")
    tools = [
        ToolDefinition(
            name=str(t.get("name", "")),
            description=str(t.get("description", "")),
            input_schema=t.get("args_schema", t.get("args", {})) or {},
        )
        for t in items if isinstance(t, dict) and t.get("name")
    ]
    return ServerConfig(name=name or Path(path).stem, transport="langchain",
                        source_client="langchain", source_path=str(path), tools=tools)


def from_langchain_tools(tools, name: str = "langchain-agent") -> ServerConfig:
    defs = []
    for t in tools:
        tool_name = getattr(t, "name", None)
        if not tool_name:
            continue
        schema = {}
        args_schema = getattr(t, "args_schema", None)
        if args_schema is not None:
            try:
                schema = args_schema.model_json_schema()
            except Exception:
                try:
                    schema = args_schema.schema()
                except Exception:
                    schema = {}
        defs.append(ToolDefinition(name=str(tool_name),
                                   description=str(getattr(t, "description", "")),
                                   input_schema=schema))
    return ServerConfig(name=name, transport="langchain", source_client="langchain",
                        tools=defs)
