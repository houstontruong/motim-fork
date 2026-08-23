# AG_PROMPT.md — Motim Account-Read Reconciliation: Final Confidentiality Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task

Remediate the four findings from a fresh independent Codex audit of the existing **offline-only** account-read reconciliation layer. Read `SPEC.md`, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, `motim-account-read-audit-fix.md`, the report, and the current tests before changing code. Preserve all prior fixes through `31132ea`; do not weaken the no-auth-input boundary.

The audit reproduced these defects:

1. A route key containing URL query credentials is accepted at reconciliation ingest and can be emitted verbatim in an `unsupported_schema` issue. Reject credential-bearing URL/userinfo/query material before adapters can echo it; errors must be redacted and must produce zero facts.
2. `Redactor.redact_url()` leaves URL userinfo credentials visible, including URLs without query strings. Sanitization must handle userinfo robustly as well as sensitive query fields.
3. `Redactor.redact_data_structure()` only traverses dict/list, leaving sensitive values inside supported non-list containers unchanged. Make direct structural redaction safely recursive across relevant mapping/tuple/set-like input without breaking deterministic or JSON-safe output expectations.
4. `Redactor.redact_body_bytes()` can preserve plaintext form-shaped auth fields when content type is unknown. Apply a fail-closed treatment that masks sensitive key/value material without corrupting legitimate benign content unnecessarily.

Choose the smallest robust approach satisfying the offline account-read contract. Add focused direct and end-to-end regressions for each finding, including nested variants and zero-fact/redacted-error behavior. Preserve strict no-network/no-replay/no-real-credentials guarantees. Never capture traffic, sign in, make an HTTP/WebSocket request, open a socket, reintroduce replay/export of credential-bearing data, or create a real-capture runbook.

If you see a better approach than this brief describes, say so and explain why before changing direction.

Work through the roadmap checkpoints in order. Commit only after verified checkpoints using conventional commits.

## Git Setup (MANDATORY)

- Work on branch `main`.
- Commit locally with a descriptive conventional-commit message.
- Push with `git push origin main`. If credentials prevent this, record the exact blocker in the report; OpenClaw will verify and push.

## Expected output files

- Updated `motim-account-read-audit-fix.md` documenting these four findings, changed files, exact verification commands with actual output/exit codes, and remaining gaps.
- Updated regression tests/fixtures covering every listed reproduction.
- Updated `motim-account-read-report.md` with the new verification evidence.

## Completion

When all outputs are written, run this in PowerShell to notify OpenClaw:

```powershell
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-codex-fixes-7"
  status = "complete"
  project_dir = "C:\Users\houst\PycharmProjects\motim-fork"
  required = @("motim-account-read-audit-fix.md", "motim-account-read-report.md")
  optional = @()
  message = "All artifacts written"
  ts = Get-Date -Format "yyyy-MM-dd HH:mm EDT"
} | ConvertTo-Json -Compress

Invoke-WebRequest -Method POST -Uri "https://ntfy.sh/$topic" -Headers @{"Content-Type"="application/json";"Title"="AG job complete";"Tags"="white_check_mark"} -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 15 -UseBasicParsing
```

Include what changed, verification output, and any remaining errors in the report.
