"""BlastScope CLI."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from blastscope import __version__
from blastscope.adapters.mcp_static import build_installation, parse_config_file
from blastscope.engine import load_rules, scan_installation
from blastscope.models import Installation, ServerConfig, Severity
from blastscope.reporters import html_out, json_out, terminal
from blastscope.scoring import assess

console = Console()


def _consent_prompt(server: ServerConfig) -> bool:
    cmd = " ".join([server.command] + server.args)
    console.print(f"\n[yellow]Live inspection will EXECUTE this server:[/yellow]")
    console.print(f"  [mono]{cmd}[/mono]")
    console.print("[dim]Only do this for servers you're willing to run. Sandbox untrusted ones.[/dim]")
    return click.confirm("Proceed?", default=False)


def _run_scan(inst: Installation, rules_dirs, live, update_baseline, baseline_path):
    if live:
        from blastscope.adapters.mcp_live import enrich_installation
        errors = enrich_installation(inst, consent=_consent_prompt)
        for name, err in errors.items():
            console.print(f"[dim]live inspection skipped for {name}: {err}[/dim]")
    rules = load_rules(list(rules_dirs) or None)
    findings = scan_installation(
        inst, rules, include_composition=True,
        baseline_path=baseline_path, update_baseline=update_baseline,
    )
    return findings, assess(findings)


@click.group()
@click.version_option(__version__, prog_name="blastscope")
def main() -> None:
    """See your agent's blast radius before an attacker does.

    Local-first: nothing about your configuration ever leaves this machine.
    """


@main.command()
@click.option("--config", "configs", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Scan a specific config file (repeatable). Disables auto-discovery.")
@click.option("--manifest", "manifests", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Also scan a tool-manifest JSON file (repeatable).")
@click.option("--rules-dir", "rules_dirs", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Load additional YAML rule packs from a directory (repeatable).")
@click.option("--openai-tools", "openai_files", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Also assess an OpenAI function-calling tools JSON file (repeatable).")
@click.option("--langchain-export", "langchain_files", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Also assess a LangChain tools JSON export (repeatable).")
@click.option("--live", is_flag=True, help="Handshake with stdio servers to enumerate real tools (executes them; asks first).")
@click.option("--policy", "policy_file", type=click.Path(exists=True, path_type=Path),
              help="Evaluate the installation against an organisational policy YAML.")
@click.option("--llm", "llm_pass", is_flag=True,
              help="Optional LLM semantic pass on tool descriptions (BYO ANTHROPIC_API_KEY; heuristic; sends tool names+descriptions only).")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "html", "sarif"]), default="terminal")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Write output to a file.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]),
              help="Exit non-zero if findings at/above this severity exist (CI gate).")
@click.option("--baseline", is_flag=True, help="Record/update the rug-pull baseline during this scan.")
@click.option("--baseline-path", type=click.Path(path_type=Path), help="Custom baseline file location.")
@click.option("--summary-only", is_flag=True, help="Posture and verdict only, no per-finding detail.")
def scan(configs, manifests, rules_dirs, openai_files, langchain_files, live, policy_file,
         llm_pass, fmt, output, fail_on, baseline, baseline_path, summary_only) -> None:
    """Scan MCP client configs on this machine (or given via --config)."""
    inst = build_installation(list(configs) or None, list(manifests) or None,
                              auto_discover=not (configs or openai_files or langchain_files))
    for f in openai_files:
        from blastscope.adapters.openai_tools import parse_openai_tools_file
        inst.servers.append(parse_openai_tools_file(f))
    for f in langchain_files:
        from blastscope.adapters.langchain_tools import parse_langchain_export
        inst.servers.append(parse_langchain_export(f))
    if not inst.servers:
        console.print("[yellow]No MCP servers found.[/yellow] "
                      "Point me at a config with --config <path>.")
        sys.exit(0)

    findings, assessment = _run_scan(inst, rules_dirs, live,
                                     update_baseline=baseline, baseline_path=baseline_path)

    if policy_file:
        from blastscope.policy import load_policy, evaluate_policy
        from blastscope.scoring import assess as _assess
        violations = evaluate_policy(inst, load_policy(policy_file), scan_findings=findings)
        findings = sorted(findings + violations,
                          key=lambda x: (-x.severity.rank, x.server, x.rule_id))
        assessment = _assess(findings)

    if llm_pass:
        from blastscope.llm_pass import run_llm_pass
        from blastscope.scoring import assess as _assess
        try:
            heuristic = run_llm_pass(inst)
            if heuristic:
                findings = sorted(findings + heuristic,
                                  key=lambda x: (-x.severity.rank, x.server, x.rule_id))
                assessment = _assess(findings)
            console.print(f"[dim]LLM pass: {len(heuristic)} heuristic finding(s)[/dim]")
        except RuntimeError as e:
            console.print(f"[yellow]LLM pass skipped:[/yellow] {e}")

    if fmt == "sarif":
        from blastscope.reporters import sarif_out
        _emit(sarif_out.render(inst, findings, assessment), output)
    elif fmt == "json":
        payload = json_out.render(inst, findings, assessment)
        _emit(payload, output)
    elif fmt == "html":
        payload = html_out.render(inst, findings, assessment)
        out = output or Path("blastscope-report.html")
        out.write_text(payload, encoding="utf-8")
        console.print(f"HTML report written to [bold]{out}[/bold]")
    else:
        terminal.render(inst, findings, assessment, detail=not summary_only)
        if output:
            output.write_text(json_out.render(inst, findings, assessment), encoding="utf-8")
            console.print(f"[dim]JSON copy written to {output}[/dim]")

    if fail_on and any(f.severity.rank >= Severity(fail_on).rank for f in findings):
        sys.exit(1)


@main.command()
@click.argument("target")
@click.option("--rules-dir", "rules_dirs", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal")
@click.option("-o", "--output", type=click.Path(path_type=Path))
@click.option("--no-live", is_flag=True, help="Assess the declared config only; do not execute the server.")
def inspect(target, rules_dirs, fmt, output, no_live) -> None:
    """Assess a single server BEFORE you add it to a client.

    TARGET can be a package spec (npx:@vendor/pkg, uvx:pkg), a URL, or a path to
    a config/manifest JSON. This is the pre-install check — run it before pasting
    anything into your client config.
    """
    inst = Installation(clients_found=["inspect"])
    p = Path(target)
    if p.is_file():
        from blastscope.adapters.mcp_static import parse_manifest_file
        try:
            inst.servers = parse_config_file(p, client="inspect")
        except Exception:
            inst.servers = []
        if not inst.servers:
            inst.servers = [parse_manifest_file(p)]
    elif target.startswith(("npx:", "uvx:")):
        runner, _, pkg = target.partition(":")
        inst.servers = [ServerConfig(name=pkg, command=runner, args=[pkg], source_client="inspect")]
    elif target.startswith(("http://", "https://")):
        transport = "sse"
        inst.servers = [ServerConfig(name=target, transport=transport, url=target, source_client="inspect")]
    else:
        console.print(f"[red]Could not interpret target:[/red] {target}")
        console.print("Use npx:<pkg>, uvx:<pkg>, an https URL, or a path to a config/manifest.")
        sys.exit(2)

    live = not no_live and bool(inst.servers and inst.servers[0].command)
    findings, assessment = _run_scan(inst, rules_dirs, live,
                                     update_baseline=False, baseline_path=None)

    if fmt == "json":
        _emit(json_out.render(inst, findings, assessment), output)
    elif fmt == "html":
        out = output or Path("blastscope-inspect.html")
        out.write_text(html_out.render(inst, findings, assessment), encoding="utf-8")
        console.print(f"HTML report written to [bold]{out}[/bold]")
    else:
        terminal.render(inst, findings, assessment, detail=True)


@main.command()
@click.option("--config", "configs", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--baseline-path", type=click.Path(path_type=Path))
def watch(configs, baseline_path) -> None:
    """One-shot drift check against the recorded baseline (for cron/CI scheduling).

    Records a baseline on first run, reports rug-pull drift on subsequent runs.
    Wrap in your scheduler of choice to run continuously.
    """
    inst = build_installation(list(configs) or None, auto_discover=not configs)
    if not inst.servers:
        console.print("[yellow]No MCP servers found.[/yellow]")
        sys.exit(0)
    from blastscope.baseline import check_and_update
    drift = check_and_update(inst, path=baseline_path, update=True)
    drift = [f for f in drift if f.risk_class == "R5"]
    if not drift:
        console.print("[green]No definition drift since baseline.[/green]")
        return
    for f in drift:
        console.print(f"[red]{f.severity.value.upper()}[/red] {f.title} — {f.server} ({f.location})")
    sys.exit(1)


@main.command()
@click.option("--rules-dir", "rules_dirs", multiple=True, type=click.Path(exists=True, path_type=Path))
def rules(rules_dirs) -> None:
    """List loaded detection rules."""
    from rich.table import Table
    t = Table(title=f"BlastScope rule packs (v{__version__})")
    for col in ("ID", "Class", "Severity", "Title"):
        t.add_column(col)
    for r in load_rules(list(rules_dirs) or None):
        t.add_row(r.id, r.risk_class, r.severity.value, r.title)
    console.print(t)
    console.print("[dim]Composition rules (R3/R12) and rug-pull rules (R5) are engine-driven, "
                  "not YAML, and always active.[/dim]")


def _emit(payload: str, output: Path | None) -> None:
    if output:
        output.write_text(payload, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        click.echo(payload)




@main.command()
@click.option("--config", "configs", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--manifest", "manifests", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--openai-tools", "openai_files", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--langchain-export", "langchain_files", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--live", is_flag=True, help="Enumerate real tools via handshake before exporting.")
@click.option("-o", "--output", type=click.Path(path_type=Path))
def export(configs, manifests, openai_files, langchain_files, live, output) -> None:
    """Export an AI-BOM: the full capability surface of your installation.

    A machine-readable inventory of every server, tool, and classified capability
    — governance evidence for audits, DDQs, and change review. Diff two exports
    to see exactly what an installation gained between approvals.
    """
    from blastscope.aibom import render as render_aibom
    inst = build_installation(list(configs) or None, list(manifests) or None,
                              auto_discover=not (configs or openai_files or langchain_files))
    for f in openai_files:
        from blastscope.adapters.openai_tools import parse_openai_tools_file
        inst.servers.append(parse_openai_tools_file(f))
    for f in langchain_files:
        from blastscope.adapters.langchain_tools import parse_langchain_export
        inst.servers.append(parse_langchain_export(f))
    if not inst.servers:
        console.print("[yellow]No MCP servers found.[/yellow]")
        sys.exit(0)
    if live:
        from blastscope.adapters.mcp_live import enrich_installation
        enrich_installation(inst, consent=_consent_prompt)
    _emit(render_aibom(inst), output)


if __name__ == "__main__":
    main()
