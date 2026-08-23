# AG_PROMPT.md — Motim Account-Read Reconciliation: Round 11 Bounded-Decoding Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task

Remediate the remaining findings from the independent Codex audit of exact commit `08ae77bedf9a78d1c710db20d8fc9d5f5231e689`. The project remains strictly **offline-only**. Read the current source, relevant tests, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, `motim-account-read-audit-fix.md`, and `motim-account-read-report.md` before changing code.

1. **HIGH — malformed percent sequences bypass auth/redaction:** `_has_percent_encoding()` only recognizes valid `%XX` triples. Inputs such as `api%GG_key: TOPSECRET`, `api%G0_key`, `api%0G_key`, or `api%` can bypass `contains_auth_elements()` and standalone `Redactor.redact_data_structure()`. Treat **any remaining percent character** in a sensitive-name/route parsing context as unresolved and suspicious after bounded decoding: reject at ingestion with `invalid_input`, zero facts, no secret output; classify the name as sensitive in redaction. Add direct/API/JSONL/CLI regressions for all malformed forms.
2. **MEDIUM — quadratic decoding CPU cost:** the input-length-derived decode bound makes repeated `%25` sequences quadratic. Replace it with a small constant decode-depth cap and fail closed if any percent character remains after that cap; also enforce modest maximum route and field/key string lengths before decode. The limits must be documented and tested so ordinary routes remain accepted. Add hostile-size regressions that prove bounded/structured failure without seconds-long processing.

Use the smallest robust solution. Apply the exact same fail-closed treatment to validator, redactor, and adapter route-derived issue messages. Preserve all prior fixes and strict no-network/no-replay/no-real-credentials constraints. Do not capture traffic, sign in, make HTTP/WebSocket requests, open a socket, mutate an account, or create a real-capture runbook.

If you see a better approach than this brief describes, say so and explain why before changing direction.

Commit only after verified checkpoints using a conventional commit, then push to `origin main`.

## Expected output files

- Updated `motim-account-read-audit-fix.md` documenting both findings, changed files, exact verification commands with actual output/exit codes, and remaining gaps.
- Updated regression tests covering every listed reproduction.
- Updated `motim-account-read-report.md` with the new verification evidence.

## Completion

When all outputs are written, run this in PowerShell to notify OpenClaw:

```powershell
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-codex-fixes-11"
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
