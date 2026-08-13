"""AI-BOM export — a bill of materials for your agent's capability surface.

SBOMs answer "what code am I running?". An AI-BOM answers "what can my agent
DO?" — every server, every tool, every classified capability, with provenance.
Useful as governance evidence (vendor DDQs, audits, risk registers) and as the
input to change review: diff two AI-BOMs to see exactly what an installation
gained between approvals.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from blastscope import __version__
from blastscope.capabilities import classify_installation
from blastscope.models import Installation


def render(inst: Installation) -> str:
    caps_by_server = {c.server: c for c in classify_installation(inst.servers)}
    servers = []
    for s in inst.servers:
        caps = caps_by_server.get(s.name)
        servers.append({
            "name": s.name,
            "transport": s.transport,
            "client": s.source_client,
            "launch": {"command": s.command, "args": s.args} if s.command else {"url": s.url},
            "capabilities": sorted(c.value for c in caps.capabilities) if caps else [],
            "capability_evidence": [
                {"capability": e.capability.value, "tool": e.tool, "signal": e.signal}
                for e in (caps.evidence if caps else [])
            ],
            "tools": [
                {"name": t.name, "description": t.description,
                 "annotations": t.annotations}
                for t in s.tools
            ],
        })
    doc = {
        "aibom_version": "0.1",
        "generator": {"name": "blastscope", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "installation": {
            "clients": inst.clients_found,
            "server_count": len(inst.servers),
            "tool_count": sum(len(s.tools) for s in inst.servers),
            "capability_union": sorted({c.value for sc in caps_by_server.values()
                                        for c in sc.capabilities}),
        },
        "servers": servers,
    }
    return json.dumps(doc, indent=2)
