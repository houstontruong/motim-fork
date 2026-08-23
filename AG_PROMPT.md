# AG_PROMPT.md — Motim Account-Read Reconciliation: Round 9 Confidentiality Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task

Remediate the two findings from the independent Codex audit of exact commit `46ff8d643fc6d4a17509fc65826c0a9a2ff487a4` in the existing **offline-only** account-read reconciliation layer. Read the current source, relevant tests, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, `motim-account-read-audit-fix.md`, and `motim-account-read-report.md` before changing code. Preserve all prior fixes; do not weaken the no-auth-input boundary.

The audit reproduced these defects:

1. **Fully percent-encoded structural delimiters can leak (HIGH):** a route such as `unsupported%3Fapi%5Fkey%3DTOPSECRET` or `unsupported%23token%3DTOPSECRET` is decoded only for pattern checks, not before query/fragment parsing. It can pass validation and reach an unsupported-route issue whose literal-delimiter stripping leaves the encoded secret intact. Iteratively decode the complete route before auth parsing and sanitize any reflected route from that decoded representation. Prefer failing closed on encoded structural delimiters (`?`, `#`, `=`, `&`, `;`, `@`). Add direct API, JSONL, CLI, Bybit, and Lighter regressions proving `invalid_input`, zero facts, and no canary in output.
2. **BOM-less UTF-16/NUL-bearing body data can leak (HIGH):** with a missing or generic content type, BOM-less UTF-16LE/BE or NUL-bearing binary can decode as UTF-8 and bypass the generic text sanitizer, so a `password: TOPSECRET` body may be persisted. Before the UTF-8 fallback, detect binary/NUL characteristics. Safely decode BOM-less UTF-16 only with strict heuristics or fail closed to the existing binary-redaction placeholder. Add direct redactor and persistence-path tests for BOM-less UTF-16LE and UTF-16BE with absent and generic content types, including unique canaries.

Choose the smallest robust approach satisfying the offline account-read contract. Preserve strict no-network/no-replay/no-real-credentials guarantees. Never capture traffic, sign in, make an HTTP/WebSocket request, open a socket, reintroduce replay/export of credential-bearing data, or create a real-capture runbook.

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
  job = "motim-account-read-codex-fixes-9"
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
