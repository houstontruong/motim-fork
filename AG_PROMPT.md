# AG_PROMPT.md — Motim Account-Read Reconciliation: Round 10 Deep-Encoding Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task

Remediate the remaining HIGH finding from the independent Codex audit of exact commit `cb21423d1a043108f454c5296ae2f6a9da2a13a8`. The project remains strictly **offline-only**. Read the current source, tests, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, `motim-account-read-audit-fix.md`, and `motim-account-read-report.md` before changing code.

**Finding — deep percent-encoding bypass (HIGH):** `motim/reconcile/validator.py` decodes only five rounds; the Bybit and Lighter adapter issue sanitizers use the same limit. A route whose structural delimiters are encoded six times, such as a six-layer encoding of `unsupported?api_key=TOPSECRET_DEPTH6`, passes `_is_auth_string()` and produces an unsupported-route issue reflecting the secret.

Implement the smallest robust fix:

- Decode to a real safe fixed point with a bound derived from input length, **or** fail closed when valid percent-encoding remains after a safe bounded decode limit.
- Apply the same safe behavior to validation and every adapter route-derived message. Never reflect the original encoded route if decoding cannot complete safely.
- Add API, JSONL, CLI, Bybit, and Lighter regressions at more than five encoding layers. They must prove `invalid_input`, zero facts, redacted/no-secret output, and CLI exit code 4.
- Preserve all prior fixes and strict no-network/no-replay/no-real-credentials constraints. Do not capture traffic, sign in, make HTTP/WebSocket requests, open a socket, mutate an account, or create a real-capture runbook.

If you see a better approach than this brief describes, say so and explain why before changing direction.

Commit only after verified checkpoints using a conventional commit, then push to `origin main`.

## Expected output files

- Updated `motim-account-read-audit-fix.md` documenting this finding, changed files, exact verification commands with actual output/exit codes, and remaining gaps.
- Updated regression tests covering every listed reproduction.
- Updated `motim-account-read-report.md` with the new verification evidence.

## Completion

When all outputs are written, run this in PowerShell to notify OpenClaw:

```powershell
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-codex-fixes-10"
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
