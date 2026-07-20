"""v0.5 composition, capability, baseline, and live-handshake tests."""
import json
import tempfile
from pathlib import Path

import pytest

from blastscope.adapters.mcp_static import build_installation
from blastscope.capabilities import Capability, classify_installation, classify_server
from blastscope.composition import analyse_composition
from blastscope.models import Installation, ServerConfig, ToolDefinition, Severity

EXAMPLES = Path(__file__).parent.parent / "examples"


def _server(name, desc="", cmd="npx", args=None, tools=None):
    return ServerConfig(name=name, command=cmd, args=args or [name],
                        tools=[ToolDefinition(name=t[0], description=t[1]) for t in (tools or [])])


# ---- capability classification ----

def test_private_data_classified():
    s = _server("gmail", tools=[("read_email", "Read the user's email inbox")])
    caps = classify_server(s)
    assert Capability.PRIVATE_DATA in caps.capabilities


def test_untrusted_input_classified():
    s = _server("web", tools=[("fetch", "Fetch a web page and return its content")])
    caps = classify_server(s)
    assert Capability.UNTRUSTED_IN in caps.capabilities


def test_exfil_classified():
    s = _server("hook", tools=[("post", "Post data to any webhook url provided")])
    caps = classify_server(s)
    assert Capability.EXFIL in caps.capabilities


def test_destructive_classified():
    s = _server("db", tools=[("drop", "Delete all records permanently")])
    caps = classify_server(s)
    assert Capability.DESTRUCTIVE in caps.capabilities


def test_tool_can_hold_multiple_capabilities():
    s = _server("db", tools=[("wipe_and_notify", "Delete all records and send a payment to any account")])
    caps = classify_server(s)
    assert Capability.DESTRUCTIVE in caps.capabilities
    assert Capability.EXFIL in caps.capabilities


# ---- trifecta (R3) ----

def test_trifecta_fires_across_servers():
    inst = build_installation([EXAMPLES / "trifecta_config.json"], auto_discover=False)
    findings = analyse_composition(inst)
    assert any(f.rule_id == "BS-R3-001" and f.severity == Severity.CRITICAL for f in findings)


def test_trifecta_silent_when_leg_missing():
    # only private data + untrusted input, no exfil -> no trifecta
    inst = Installation(servers=[
        _server("notes", tools=[("read_file", "Read a file from disk")]),
        _server("web", tools=[("fetch", "Fetch a web page and return content")]),
    ])
    findings = analyse_composition(inst)
    assert not any(f.rule_id == "BS-R3-001" for f in findings)


def test_clean_install_no_composition_findings():
    inst = build_installation([EXAMPLES / "clean_config.json"], auto_discover=False)
    findings = analyse_composition(inst)
    assert not any(f.rule_id == "BS-R3-001" for f in findings)


# ---- excessive agency (R12) ----

def test_untrusted_to_destructive_chain():
    inst = Installation(servers=[
        _server("web", tools=[("fetch", "Fetch a web page and return content")]),
        _server("db", tools=[("drop", "Delete all records permanently")]),
    ])
    findings = analyse_composition(inst)
    assert any(f.rule_id == "BS-R12-001" for f in findings)


# ---- rug-pull baseline (R5) ----

def test_baseline_records_then_detects_drift(tmp_path):
    from blastscope.baseline import check_and_update
    bl = tmp_path / "bl.json"
    inst1 = Installation(servers=[_server("s", tools=[("t", "original description")])])
    first = check_and_update(inst1, path=bl, update=True)
    assert first == []  # nothing to compare against yet

    inst2 = Installation(servers=[_server("s", tools=[("t", "MUTATED description with new instructions")])])
    second = check_and_update(inst2, path=bl, update=True)
    assert any(f.rule_id == "BS-R5-001" for f in second)


def test_baseline_stable_when_unchanged(tmp_path):
    from blastscope.baseline import check_and_update
    bl = tmp_path / "bl.json"
    inst = Installation(servers=[_server("s", tools=[("t", "same description")])])
    check_and_update(inst, path=bl, update=True)
    inst2 = Installation(servers=[_server("s", tools=[("t", "same description")])])
    assert check_and_update(inst2, path=bl, update=True) == []


def test_new_tool_on_known_server_flagged(tmp_path):
    from blastscope.baseline import check_and_update
    bl = tmp_path / "bl.json"
    check_and_update(Installation(servers=[_server("s", tools=[("t1", "desc")])]), path=bl, update=True)
    grown = Installation(servers=[_server("s", tools=[("t1", "desc"), ("t2", "new tool")])])
    findings = check_and_update(grown, path=bl, update=True)
    assert any(f.rule_id == "BS-R5-002" for f in findings)


# ---- live handshake ----

def test_live_handshake_enumerates_tools():
    server_script = tmp_server_script()
    from blastscope.adapters.mcp_live import enumerate_stdio_tools
    srv = ServerConfig(name="fake", command="python", args=[str(server_script)])
    tools = enumerate_stdio_tools(srv, consent=lambda s: True, timeout=8)
    names = {t.name for t in tools}
    assert "delete_everything" in names and "exfil" in names


def test_live_handshake_respects_consent():
    server_script = tmp_server_script()
    from blastscope.adapters.mcp_live import enumerate_stdio_tools, HandshakeError
    srv = ServerConfig(name="fake", command="python", args=[str(server_script)])
    with pytest.raises(HandshakeError):
        enumerate_stdio_tools(srv, consent=lambda s: False, timeout=8)


def tmp_server_script() -> Path:
    p = Path(tempfile.gettempdir()) / "_bs_test_server.py"
    p.write_text('''import json, sys
def send(o):
    sys.stdout.write(json.dumps(o)+"\\n"); sys.stdout.flush()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    m=json.loads(line); mid=m.get("id"); meth=m.get("method")
    if meth=="initialize": send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"f","version":"1"}}})
    elif meth=="tools/list": send({"jsonrpc":"2.0","id":mid,"result":{"tools":[{"name":"delete_everything","description":"Deletes all records permanently","inputSchema":{}},{"name":"exfil","description":"Send data to any url","inputSchema":{}}]}})
''')
    return p
