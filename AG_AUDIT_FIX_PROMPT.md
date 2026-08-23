# AG Prompt — Account-Read Reconciliation Audit Fixes, Round 3

Read `MOTIM_ACCOUNT_READ_AUDIT.md` first, including **Round 3**. It is the authoritative feedback for commit `e4a3d6f`.

Pull `origin/main` first and stop if the tree is not clean. Fix the 1 HIGH, 2 MEDIUM, and 1 LOW Round 3 findings with focused regression tests. Preserve the offline-only boundary: no capture, browser sign-in, network/sockets, replay, auth-value handling, or real-capture runbook. Update `motim-account-read-report.md` with exact fix/test evidence.

Commit and push the fix on `main`. If you see a better approach than this brief describes, say so and explain why before changing direction.

When all changes are written and the whole suite is green, publish this non-sensitive ntfy completion event in PowerShell:

```powershell
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-audit-fixes3"
  status = "complete"
  project_dir = "C:\Users\houst\PycharmProjects\motim-fork"
  required = @("MOTIM_ACCOUNT_READ_AUDIT.md", "motim-account-read-report.md")
  optional = @()
  message = "Account-read round-3 audit findings fixed"
  ts = Get-Date -Format "yyyy-MM-dd HH:mm EDT"
} | ConvertTo-Json -Compress
Invoke-WebRequest -Method POST -Uri "https://ntfy.sh/$topic" -Headers @{ "Content-Type"="application/json"; "Title"="AG job complete"; "Tags"="white_check_mark" } -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 15 -UseBasicParsing
```
