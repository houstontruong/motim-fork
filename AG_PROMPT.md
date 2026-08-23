# AG_PROMPT.md — Motim Account-Read Reconciliation: Final Codex Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`
(If the folder does not exist, clone it first: `git clone https://github.com/houstontruong/motim-fork.git`)

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task
Remediate the one remaining Codex audit finding in the existing **offline-only** account-read reconciliation layer. Read `SPEC.md`, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, the prior remediation report, and the current tests before changing code.

Round 4 is already implemented in `6352d88`; do not regress it. The fresh audit reproduced this remaining defect:

1. Nested authentication material is still fail-open for `nonce`: a syntactically valid `GET` record with `response.body.metadata.nonce` returns `ok` with a fact. The recursive boundary must reject `nonce` (including normalized variants) with a redacted structured `invalid_input` result and zero facts.

Choose the smallest robust implementation that satisfies the contract. Add direct API, JSONL, and CLI regressions for nested `nonce` fields, including redaction and zero-fact assertions; preserve the strict no-network/no-replay/no-real-credentials guarantee. This task must never capture traffic, sign in, make an HTTP/WebSocket request, open a socket, reintroduce replay/export of credential-bearing data, or provide a real-capture runbook.

If you see a better approach than this brief describes, say so and explain why before changing direction.

Work through the roadmap checkpoints in order. Commit only after a verified checkpoint, using conventional commits. If you see a better approach than the brief describes, say so and explain why before changing direction.

## Git Setup (MANDATORY)
- Work on branch `main`.
- Commit locally with descriptive conventional-commit messages.
- Push when you can: `git push origin main` (use your configured GitHub credentials). If push fails for credential reasons, leave commits local and say so in the report file — OpenClaw will pull and push.

## EXPECTED OUTPUT FILES (write into this project dir)
- `motim-account-read-audit-fix.md` — the two audit findings, changed files, exact verification commands with actual output/exit codes, and any remaining gaps
- Updated reconciliation tests/fixtures proving both requirements
- Updated `motim-account-read-report.md` with the new verification evidence

## Completion

When ALL output files are written, run this in PowerShell to notify OpenClaw:

```
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-codex-fixes-5"
  status = "complete"
  project_dir = "C:\Users\houst\PycharmProjects\motim-fork"
  required = @("motim-account-read-audit-fix.md", "motim-account-read-report.md")
  optional = @("tests/", "motim/")
  message = "All artifacts written"
  ts = Get-Date -Format "yyyy-MM-dd HH:mm EDT"
} | ConvertTo-Json -Compress

Invoke-WebRequest -Method POST -Uri "https://ntfy.sh/$topic" -Headers @{"Content-Type"="application/json";"Title"="AG job complete";"Tags"="white_check_mark"} -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 15 -UseBasicParsing
```

Include in the report: what you did, files created/modified, key findings, and any errors encountered.
