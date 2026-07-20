"""HTML report — the shareable artifact for stakeholders who don't live in a terminal.

Two audiences, one document: a plain-language executive summary at the top
(what can this installation do, what's the realistic attack, top fixes) followed
by the full technical findings. Self-contained, no external assets, offline.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from blastscope import __version__
from blastscope.models import Finding, Installation, Severity
from blastscope.scoring import Assessment

_SEV_COLOR = {
    "critical": "#b3261e",
    "high": "#c94f4f",
    "medium": "#c77700",
    "low": "#7a7a2e",
    "info": "#5a6472",
}


def _esc(s: str) -> str:
    return html.escape(str(s))


def _exec_summary(inst: Installation, findings: list[Finding], a: Assessment) -> str:
    trifecta = next((f for f in findings if f.rule_id == "BS-R3-001"), None)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]

    if trifecta:
        headline = ("This installation contains a complete data-exfiltration chain. "
                    "A single prompt injection could read private data and send it to "
                    "an attacker. Treat as critical.")
    elif crit:
        headline = ("This installation has critical security exposure that should be "
                    "remediated before it handles sensitive data.")
    elif high:
        headline = ("This installation has high-impact findings that materially increase "
                    "risk. Remediation is recommended before broader use.")
    elif findings:
        headline = ("This installation has hygiene issues but no critical or high-impact "
                    "exposure was detected.")
    else:
        headline = ("No known risk patterns were detected. This is not a guarantee of "
                    "safety — see scope and limitations.")

    top_fixes = []
    seen = set()
    for f in findings:
        if f.severity.rank >= Severity.HIGH.rank and f.remediation not in seen:
            top_fixes.append((f.title, f.remediation))
            seen.add(f.remediation)
        if len(top_fixes) >= 3:
            break

    fixes_html = "".join(
        f"<li><strong>{_esc(t)}.</strong> {_esc(r.strip())}</li>" for t, r in top_fixes
    ) or "<li>No high-priority remediations required.</li>"

    return f"""
    <section class="exec">
      <h2>Executive summary</h2>
      <p class="headline">{_esc(headline)}</p>
      <div class="metricline">
        <span class="posture" style="background:{_SEV_COLOR.get(a.highest_severity,'#5a6472')}">
          {_esc(a.posture)}</span>
        <span>{len(inst.servers)} servers, {sum(len(s.tools) for s in inst.servers)} tools assessed</span>
        <span>{a.counts['critical']} critical &middot; {a.counts['high']} high &middot;
              {a.counts['medium']} medium &middot; {a.counts['low']} low</span>
      </div>
      <h3>Top priorities</h3>
      <ol class="fixes">{fixes_html}</ol>
    </section>
    """


def _finding_card(f: Finding) -> str:
    color = _SEV_COLOR.get(f.severity.value, "#5a6472")
    maps = " &middot; ".join(f"{_esc(k)}: {_esc(v)}" for k, v in (f.mappings or {}).items())
    return f"""
    <article class="finding">
      <div class="fhead">
        <span class="sev" style="background:{color}">{_esc(f.severity.value.upper())}</span>
        <span class="ftitle">{_esc(f.title)}</span>
        <span class="rid">{_esc(f.rule_id)}</span>
      </div>
      <div class="fbody">
        <div class="frow"><span class="k">Server</span><span>{_esc(f.server)} &rarr; {_esc(f.location)}</span></div>
        <div class="frow"><span class="k">Evidence</span><span class="mono">{_esc(f.evidence)}</span></div>
        <div class="frow"><span class="k">Why</span><span>{_esc(f.explanation.strip())}</span></div>
        <div class="frow"><span class="k">Fix</span><span>{_esc(f.remediation.strip())}</span></div>
        {f'<div class="frow"><span class="k">Frameworks</span><span class="maps">{maps}</span></div>' if maps else ''}
      </div>
    </article>
    """


def render(inst: Installation, findings: list[Finding], assessment: Assessment) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = "\n".join(_finding_card(f) for f in findings) or \
        "<p class='none'>No findings.</p>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BlastScope report</title>
<style>
  :root {{ --ink:#1a1a1a; --muted:#5a6472; --line:#e2e2e2; --bg:#fafafa; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         color:var(--ink); background:var(--bg); margin:0; line-height:1.55; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:40px 24px 80px; }}
  header.top {{ border-bottom:2px solid var(--ink); padding-bottom:16px; margin-bottom:28px; }}
  header.top h1 {{ margin:0; font-size:26px; letter-spacing:.5px; }}
  header.top .sub {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  h2 {{ font-size:19px; margin:34px 0 12px; }}
  h3 {{ font-size:15px; margin:22px 0 8px; color:var(--muted); text-transform:uppercase;
        letter-spacing:.5px; }}
  .exec {{ background:#fff; border:1px solid var(--line); border-radius:12px; padding:24px; }}
  .headline {{ font-size:17px; font-weight:500; margin:8px 0 18px; }}
  .metricline {{ display:flex; flex-wrap:wrap; gap:14px; align-items:center; font-size:13px;
                 color:var(--muted); margin-bottom:8px; }}
  .posture {{ color:#fff; padding:4px 12px; border-radius:20px; font-weight:600; font-size:12px;
              letter-spacing:.5px; }}
  ol.fixes li {{ margin:6px 0; }}
  .finding {{ background:#fff; border:1px solid var(--line); border-radius:10px;
              margin:14px 0; overflow:hidden; }}
  .fhead {{ display:flex; align-items:center; gap:12px; padding:12px 16px;
            border-bottom:1px solid var(--line); }}
  .sev {{ color:#fff; font-size:11px; font-weight:600; padding:3px 9px; border-radius:4px;
          letter-spacing:.5px; }}
  .ftitle {{ font-weight:500; flex:1; }}
  .rid {{ color:var(--muted); font-size:12px; font-family:ui-monospace,monospace; }}
  .fbody {{ padding:8px 16px 14px; }}
  .frow {{ display:grid; grid-template-columns:96px 1fr; gap:12px; padding:5px 0;
           font-size:14px; border-top:1px solid #f2f2f2; }}
  .frow:first-child {{ border-top:none; }}
  .frow .k {{ color:var(--muted); font-size:12px; text-transform:uppercase;
              letter-spacing:.4px; padding-top:2px; }}
  .mono, .maps {{ font-family:ui-monospace,monospace; font-size:12.5px; word-break:break-word; }}
  .maps {{ color:var(--muted); }}
  footer {{ margin-top:40px; padding-top:16px; border-top:1px solid var(--line);
            color:var(--muted); font-size:12px; }}
  .none {{ color:var(--muted); }}
</style></head>
<body><div class="wrap">
  <header class="top">
    <h1>BlastScope</h1>
    <div class="sub">MCP &amp; agentic AI installation assessment &middot; v{__version__} &middot; {ts}</div>
  </header>
  {_exec_summary(inst, findings, assessment)}
  <h2>Findings ({len(findings)})</h2>
  {cards}
  <footer>
    Generated locally by BlastScope v{__version__}. This report reflects known risk
    patterns in tool definitions and configuration; it assesses capability surface,
    not server source code. A clean result means no known patterns were detected,
    not a guarantee of safety.
  </footer>
</div></body></html>"""
