# R4 — Over-permissioning
rules:
  - id: BS-R4-001
    risk_class: R4
    severity: high
    title: Filesystem access at or near root
    applies_to: arg
    detector: builtin
    builtin: broad_fs_path
    explanation: >
      A server granted '/' or a full home directory can read SSH keys, cloud
      credentials, browser profiles and every document you own. Scope grants to
      the narrowest directory the use case needs.
    remediation: Replace the path argument with a specific project directory (e.g. ~/Documents/notes).
    mappings: {owasp_llm10: "LLM06 Excessive Agency", mitre_atlas: "AML.T0055", nist_ai_rmf: "GOVERN"}

  - id: BS-R4-002
    risk_class: R4
    severity: medium
    title: Shell-wrapped server command
    applies_to: any_text
    detector: regex
    pattern: '(?:^|\s)(bash|sh|zsh|cmd(\.exe)?|powershell)\s+(-c|/c)\s'
    explanation: >
      Launching a server through a shell wrapper enables argument injection and
      makes the real executable ambiguous to review and to allow-listing.
    remediation: Invoke the server binary directly with explicit args; remove the shell layer.
    mappings: {owasp_llm10: "LLM06 Excessive Agency", mitre_atlas: "AML.T0053", nist_ai_rmf: "GOVERN"}

  - id: BS-R4-003
    risk_class: R4
    severity: high
    title: Tool schema accepts arbitrary URLs or hosts
    applies_to: tool_description
    detector: regex
    pattern: 'any\s+(url|host|endpoint|address)|arbitrary\s+(url|host|endpoint)|posts?\s+(data|content|payload)?\s*to\s+(a|any|the\s+specified)\s+url'
    explanation: >
      Tools that accept caller-controlled URLs are network-egress primitives. In
      combination with data-access tools they complete an exfiltration path.
    remediation: Constrain the tool with a URL allow-list, or isolate it from data-reading servers.
    mappings: {owasp_llm10: "LLM06 Excessive Agency", mitre_atlas: "AML.T0056", nist_ai_rmf: "MANAGE"}
