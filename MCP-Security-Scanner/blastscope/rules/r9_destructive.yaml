# R9 — Destructive actions without friction
rules:
  - id: BS-R9-001
    risk_class: R9
    severity: high
    title: Irreversible destructive tool exposed
    applies_to: tool_name
    detector: regex
    pattern: '^(delete|drop|truncate|destroy|purge|wipe|remove)[-_]?(all|db|database|table|records?|files?|user|account)?s?$|^rm[-_]|force[-_]?delete'
    explanation: >
      This tool performs an irreversible operation. If any injected content
      reaches the model, this tool is one call away from permanent data loss.
    remediation: >
      Remove it from agent-accessible tools, gate it behind human confirmation,
      or replace it with a soft-delete equivalent.
    mappings: {owasp_llm10: "LLM06 Excessive Agency", mitre_atlas: "AML.T0055", nist_ai_rmf: "MANAGE"}

  - id: BS-R9-002
    risk_class: R9
    severity: medium
    title: Destructive capability described without confirmation semantics
    applies_to: tool_description
    detector: regex
    pattern: '\b(permanently|irreversibly|cannot\s+be\s+undone|without\s+confirmation)\b.{0,60}\b(delete|remove|erase|drop|overwrite)|\b(delete|drop|erase)s?\b.{0,60}\b(permanently|immediately|all\s+(data|records|files))\b'
    explanation: >
      The tool self-describes irreversible behaviour but the definition carries no
      destructiveHint annotation or confirmation requirement the client could act on.
    remediation: Ask the maintainer to add MCP tool annotations (destructiveHint) or gate usage behind approval.
    mappings: {owasp_llm10: "LLM06 Excessive Agency", mitre_atlas: "AML.T0055", nist_ai_rmf: "MANAGE"}

  - id: BS-R9-003
    risk_class: R9
    severity: medium
    title: Financial/outbound-communication tool exposed to the agent
    applies_to: tool_name
    detector: regex
    pattern: '^(send[-_]?(email|mail|message|payment|funds|money)|pay|transfer[-_]?(funds|money)|charge[-_]?card|post[-_]?(tweet|public))'
    explanation: >
      Sending money or messages is irreversible in the real world even when the
      software operation succeeds. These tools deserve human-in-the-loop gates.
    remediation: Require explicit per-call confirmation in the client, or remove the tool from the default set.
    mappings: {owasp_llm10: "LLM06 Excessive Agency", mitre_atlas: "AML.T0055", nist_ai_rmf: "MANAGE"}
