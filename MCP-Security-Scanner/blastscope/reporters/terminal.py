"""Human-facing terminal output."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from blastscope import __version__
from blastscope.models import Finding, Installation, Severity
from blastscope.scoring import Assessment

SEV_STYLE = {
    Severity.CRITICAL: ("⛔", "bold white on red"),
    Severity.HIGH: ("🔴", "bold red"),
    Severity.MEDIUM: ("🟠", "yellow"),
    Severity.LOW: ("🟡", "dim yellow"),
    Severity.INFO: ("ℹ️ ", "dim"),
}

POSTURE_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH RISK": "bold red",
    "MEDIUM RISK": "yellow",
    "LOW RISK": "dim yellow",
    "CLEAN": "bold green",
}


def render(inst: Installation, findings: list[Finding], assessment: Assessment,
           detail: bool = True, console: Console | None = None) -> None:
    c = console or Console()

    c.print()
    c.print(f"[bold]BlastScope[/bold] v{__version__} — Installation Assessment")
    c.print("─" * 58)
    clients = ", ".join(inst.clients_found) or "none"
    tools = sum(len(s.tools) for s in inst.servers)
    c.print(f"Clients scanned : {clients}")
    c.print(f"Servers found   : {len(inst.servers)}"
            + (f"      Tools declared: {tools}" if tools else ""))
    c.print()

    style = POSTURE_STYLE[assessment.posture]
    if assessment.total:
        subtitle = f"{assessment.total} finding{'s' if assessment.total != 1 else ''}"
    else:
        subtitle = None
    c.print(Panel(Text(f"  {assessment.posture}  ", style=style),
                  expand=False, subtitle=subtitle))
    c.print()

    if detail and findings:
        for f in findings:
            icon, style = SEV_STYLE[f.severity]
            c.print(f"{icon} [{style}]{f.severity.value.upper()}[/] "
                    f"[bold]{f.title}[/bold]   [dim]({f.rule_id})[/dim]")
            c.print(f"   Server   : {f.server}  →  {f.location}")
            c.print(f"   Evidence : {f.evidence}")
            if f.explanation:
                c.print(f"   Why      : {f.explanation.strip()}")
            if f.remediation:
                c.print(f"   [green]Fix[/green]      : {f.remediation.strip()}")
            if f.mappings:
                maps = " · ".join(f"{k}: {v}" for k, v in f.mappings.items())
                c.print(f"   [dim]{maps}[/dim]")
            c.print()

    t = Table.grid(padding=(0, 2))
    t.add_row(*(f"[{SEV_STYLE[s][1]}]{assessment.counts[s.value]} {s.value}[/]"
                for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)))
    c.print(t)
    c.print()
    c.print(Panel(f"[bold]Verdict:[/bold] {assessment.verdict}", expand=False))
    c.print()
