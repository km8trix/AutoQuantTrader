# Audit-only snapshot instructions

This is an isolated security-audit source snapshot, not the ongoing development
checkout. Read README.md and AUDIT_SCOPE.json for scope and verification limits.
Use source and synthetic fixture definitions to investigate security findings.
Do not assume omitted local evidence or runtime data is available.

Preserve HALTED startup and false trading authority. Do not access credentials,
providers, real accounts, orders, funds, private runtime/history, or production.
Do not activate services, deploy, publish fixes, or merge. Existing retained-history,
diagnostic, fixture-budget and runtime holds are not released by this audit.
Record findings with exact source locations, preconditions, impact and suggested
remediation. Do not treat an unavailable runtime check as a pass.
