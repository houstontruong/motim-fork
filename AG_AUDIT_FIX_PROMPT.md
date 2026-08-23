# AG Prompt — Account-Read Reconciliation Audit Fixes

Read `MOTIM_ACCOUNT_READ_AUDIT.md` first. It is the authoritative feedback for commit `9681bbc`.

Pull `origin/main` first and stop if the tree is not clean. Fix all 2 HIGH, 4 MEDIUM, and 1 LOW finding with focused regression tests. Preserve the offline-only boundary: no capture, browser sign-in, network/sockets, replay, auth-value handling, or real-capture runbook. Update `motim-account-read-report.md` to remove/revise any pre-fix “fully verified” claim and record the exact fix/test evidence.

Commit and push the fix on `main`. If you see a better approach than this brief describes, say so and explain why before changing direction.

When all changes are written and the whole suite is green, publish this non-sensitive ntfy completion event in PowerShell:

```powershell
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-audit-fixes"
  status = "complete"
  project_dir = "C:\Users\houst\PycharmProjects\motim-fork"
  required = @("MOTIM_ACCOUNT_READ_AUDIT.md", "motim-account-read-report.md")
  optional = @()
  message = "Account-read audit findings fixed"
  ts = Get-Date -Format "yyyy-MM-dd HH:mm EDT"
} | ConvertTo-Json -Compress
Invoke-WebRequest -Method POST -Uri "https://ntfy.sh/$topic" -Headers @{ "Content-Type"="application/json"; "Title"="AG job complete"; "Tags"="white_check_mark" } -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 15 -UseBasicParsing
```
