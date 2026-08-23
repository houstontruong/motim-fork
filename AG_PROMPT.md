# AG_PROMPT.md — Motim Account-Read Reconciliation: Round 8 Confidentiality Remediation

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task

Remediate the three findings from the fresh independent Codex audit of exact commit `52c882e` in the existing **offline-only** account-read reconciliation layer. Read `SPEC.md`, `ACCOUNT_READ_CONTRACT.md`, `MOTIM_ACCOUNT_READ_AUDIT.md`, `motim-account-read-audit-fix.md`, the report, and the current tests before changing code. Preserve all prior fixes; do not weaken the no-auth-input boundary.

The audit reproduced these defects:

1. **Fail-open unknown/generic bodies (HIGH):** `Redactor.redact_body_bytes()` returns unknown/generic non-UTF-8 bodies unchanged. UTF-16, compressed, or otherwise non-UTF-8 form-like credential material can therefore persist raw values; generic UTF-8 text such as `password: SECRET123` also survives the current form/regex paths. Adopt a safe, fail-closed strategy for unparseable or unsupported encodings/content types while preserving benign, recognized content where feasible. Add direct and persistence-path regressions with unique canaries.
2. **Percent-encoded key bypass (HIGH):** `validator._is_auth_string()` does not URL-decode query field names before sensitivity checks. A percent-encoded key such as `api%5Fkey=...` can pass validation and expose its value through facts. Decode query and fragment components before normalized sensitivity matching, reject the entire input with `invalid_input`, zero facts, and no canary leakage. Cover Bybit and Lighter, direct API, JSONL, and CLI paths.
3. **Fragment reflection (MEDIUM):** Route fragments are not parsed for credentials, and unsupported-route messages can echo `positions#api_key=SECRET123`. Treat fragment parameters as auth material for validation and sanitize every unsupported-route message defensively so no route-derived secret is reflected even if validation changes later.

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
  job = "motim-account-read-codex-fixes-8"
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
