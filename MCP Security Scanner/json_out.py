"""BlastScope CLI."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from blastscope import __version__
from blastscope.adapters.mcp_static import build_installation
from blastscope.engine import load_rules, scan_installation
from blastscope.models import Severity
from blastscope.reporters import json_out, terminal
from blastscope.scoring import assess

console = Console()


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
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Write output to a file.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]),
              help="Exit non-zero if findings at/above this severity exist (CI gate).")
@click.option("--summary-only", is_flag=True, help="Grade and verdict only, no per-finding detail.")
def scan(configs, manifests, rules_dirs, fmt, output, fail_on, summary_only) -> None:
    """Scan MCP client configs on this machine (or given via --config)."""
    inst = build_installation(list(configs) or None, list(manifests) or None,
                              auto_discover=not configs)
    if not inst.servers:
        console.print("[yellow]No MCP servers found.[/yellow] "
                      "Point me at a config with --config <path>.")
        sys.exit(0)

    rules = load_rules(list(rules_dirs) or None)
    findings = scan_installation(inst, rules)
    assessment = assess(findings)

    if fmt == "json":
        payload = json_out.render(inst, findings, assessment)
        if output:
            output.write_text(payload, encoding="utf-8")
            console.print(f"Wrote {output}")
        else:
            click.echo(payload)
    else:
        terminal.render(inst, findings, assessment, detail=not summary_only)
        if output:
            output.write_text(json_out.render(inst, findings, assessment), encoding="utf-8")
            console.print(f"[dim]JSON copy written to {output}[/dim]")

    if fail_on:
        threshold = Severity(fail_on).rank
        if any(f.severity.rank >= threshold for f in findings):
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


if __name__ == "__main__":
    main()
