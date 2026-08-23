# AG_PROMPT.md — Motim Account-Read Reconciliation (offline only)

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`
(If the folder does not exist, clone it first: `git clone https://github.com/houstontruong/motim-fork.git`)

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task
Implement the **offline-only** account-read reconciliation layer in `SPEC.md`. Start by writing the validated v1 input/output models and contract tests; then add the isolated Bybit and Lighter synthetic-fixture adapters; then the CLI/API; then verification and docs.

This task must never capture traffic, sign in, make an HTTP/WebSocket request, open a socket, reintroduce replay/export of credential-bearing data, or provide a real-capture runbook. Do not infer real endpoint paths. If code outside this new package looks like it could replay or reconstruct credentials, stop and report it instead of broadening scope.

Work through the roadmap checkpoints in order. Commit only after a verified checkpoint, using conventional commits. If you see a better approach than the brief describes, say so and explain why before changing direction.

## Git Setup (MANDATORY)
- Work on branch `main`.
- Commit locally with descriptive conventional-commit messages.
- Push when you can: `git push origin main` (use your configured GitHub credentials). If push fails for credential reasons, leave commits local and say so in the report file — OpenClaw will pull and push.

## EXPECTED OUTPUT FILES (write into this project dir)
- `ACCOUNT_READ_CONTRACT.md` — exact v1 schemas, taxonomy, exit codes, and redacted fixture/output example
- `motim-account-read-report.md` — changed files, all verification commands with actual output/exit codes, known gaps, and explicit statement that real capture is out of scope
- New reconciliation tests/fixtures as specified in `SPEC.md`

## Completion

When ALL output files are written, run this in PowerShell to notify OpenClaw:

```
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-account-read-reconciliation"
  status = "complete"
  project_dir = "C:\Users\houst\PycharmProjects\motim-fork"
  required = @("ACCOUNT_READ_CONTRACT.md", "motim-account-read-report.md")
  optional = @("tests/", "motim/")
  message = "All artifacts written"
  ts = Get-Date -Format "yyyy-MM-dd HH:mm EDT"
} | ConvertTo-Json -Compress

Invoke-WebRequest -Method POST -Uri "https://ntfy.sh/$topic" -Headers @{"Content-Type"="application/json";"Title"="AG job complete";"Tags"="white_check_mark"} -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 15 -UseBasicParsing
```

Include in the report: what you did, files created/modified, key findings, and any errors encountered.
