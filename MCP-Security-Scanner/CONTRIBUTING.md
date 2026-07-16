# Contributing to BlastScope

The fastest way to contribute is a **new detection rule** — no engine code required.

## Adding a rule

Rules are YAML in `blastscope/rules/`. Add one to an existing risk-class pack or
create a new pack. Minimum fields:

```yaml
rules:
  - id: BS-R7-999            # BS-<risk class>-<number>, must be unique
    risk_class: R7
    severity: high           # critical | high | medium | low | info
    title: Short human title
    applies_to: env_value    # see field selectors in engine.py
    detector: regex          # regex | builtin
    pattern: 'your-regex'    # for detector: regex
    redact: true             # redact the match in output (use for secrets)
    explanation: Why this matters, in plain English.
    remediation: What the user should do about it.
    mappings:                # REQUIRED — every rule maps to a framework
      owasp_llm10: "LLM02 Sensitive Information Disclosure"
      mitre_atlas: "AML.T0052"
      nist_ai_rmf: "GOVERN"
```

## The two-sided test rule

Every rule must (1) fire on a matching case in `examples/vulnerable_config.json`
and (2) NOT fire on `examples/clean_config.json`. Add fixtures to both if needed.
A rule that only proves it can detect, without proving it won't over-detect, will
not be merged. Run `pytest` before opening a PR.

## Principles

- Deterministic first. No network calls in the default path.
- Explainable. Every finding cites evidence, a fix, and a framework mapping.
- Never leak secrets into output — set `redact: true`.
