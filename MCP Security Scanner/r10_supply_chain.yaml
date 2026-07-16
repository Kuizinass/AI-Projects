"""Normalised data model. Adapters populate these; the rule engine only sees these."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


@dataclass
class ToolDefinition:
    """A tool exposed by a server (from a manifest; live handshake arrives in v0.5)."""
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerConfig:
    """One MCP server as configured in a client."""
    name: str
    transport: str = "stdio"            # stdio | sse | http
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    source_client: str = "unknown"
    source_path: str = ""
    tools: list[ToolDefinition] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Installation:
    """Everything found on this machine / in the scanned configs."""
    servers: list[ServerConfig] = field(default_factory=list)
    clients_found: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    risk_class: str
    severity: Severity
    title: str
    server: str
    location: str            # human-readable: "env.AWS_KEY", "args[2]", "tools.drop_db.description"
    evidence: str            # redacted snippet
    explanation: str
    remediation: str
    mappings: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d
