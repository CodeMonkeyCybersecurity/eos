# Architecture Decision Records (ADR)

ADRs capture why we make architectural choices so contributors can extend Eos without re-litigating past decisions. Each record follows the "solve once, systematize" philosophy: document the context, decide, encode, and move on.

## How to use
- Copy [ADR-0001 Template](ADR-0001-template.md) and increment the number (ADR-0003, ADR-0004...).
- Keep the required sections: Context, Decision, Consequences, Status, Date.
- Link code, issues, or docs that informed the decision.
- Mark Status as Proposed/Accepted/Deprecated/Superseded and update the Date when status changes.
- Prefer concise text; add appendices or links for long analysis.

## Index
- [ADR-0002 SSH Hardening by Host Role](ADR-0002-ssh-hardening-by-host-role.md) — draft hardening by infrastructure role.
- [ADR-0001 Template](ADR-0001-template.md) — copy for new decisions.

## Principles to reflect
- Human Technology: human-centric, evidence-based, sustainable innovation.
- Decisions should be reversible where possible; note risk and blast radius.
- Align with EOS command and service boundaries to keep responsibilities clear.
