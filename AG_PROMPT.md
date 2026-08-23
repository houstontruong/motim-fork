# AG_PROMPT.md — Motim Account-Read Reconciliation: Redaction Consistency Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`
(If the folder does not exist, clone it first: `git clone https://github.com/houstontruong/motim-fork.git`)

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task
Remediate the one remaining Codex audit finding in the existing **offline-only** account-read reconciliation layer and its defense-in-depth redaction path. Read `SPEC.md`, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, the prior remediation report, and the current tests before changing code.

Rounds 4–5 are already implemented through `e4bfb14`; do not regress them. The fresh audit reproduced this remaining defect:

1. `motim/redact.py` does not normalize separators consistently with the reconciliation validator. Synthetic keys `n_o_n_c_e` and `n-o-n-c-e` are rejected at reconciliation ingest, but can remain unredacted when `redact_header_value`, `redact_query_string`, or `redact_data_structure` is invoked independently. Apply a shared lowercase + hyphen/underscore-normalized sensitive-name match across those redaction paths.

Choose the smallest robust implementation that satisfies the contract. Add regression tests covering split-nonce variants in nested data structures, header redaction, and query redaction, and retain the existing reconciliation zero-fact proof. Preserve the strict no-network/no-replay/no-real-credentials guarantee. This task must never capture traffic, sign in, make an HTTP/WebSocket request, open a socket, reintroduce replay/export of credential-bearing data, or provide a real-capture runbook.

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
  job = "motim-account-read-codex-fixes-6"
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
