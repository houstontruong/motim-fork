# AG_PROMPT.md — Motim Phase B (production-safe fork)

Working directory: `C:\Users\houst\PycharmProjects\motim-fork`
(If the folder does not exist, clone it first: `git clone https://github.com/houstontruong/motim-fork.git`)

Read `./SPEC.md` before coding. Treat it as a brief, not a blueprint.

## Task
Implement the production-safe Motim fork described in SPEC.md:
1. Remove replay/probe capability **at the source** (no code path can re-send a captured request with stored credentials).
2. Redaction-before-persistence (secrets never reach the DB).
3. Egress allowlist by design (deny-by-default) + loopback-only bind.
4. Safe DB/config defaults (0600-equivalent private permissions).
5. Tests proving validation gates G1–G5, plus `SECURITY.md` and `ROADMAP.md`.

Work through the roadmap checkpoints in order. Commit only after a verified checkpoint, using conventional commits. If you see a better approach than the brief describes, say so and explain why before changing direction.

## Git Setup (MANDATORY)
- Work on branch `main`.
- Commit locally with descriptive conventional-commit messages.
- Push when you can: `git push origin main` (use your configured GitHub credentials). If push fails for credential reasons, leave commits local and say so in the report file — OpenClaw will pull and push.

## EXPECTED OUTPUT FILES (write into this project dir)
- `SECURITY.md` — threat model + how each non-negotiable is enforced
- `ROADMAP.md` — what a read-only agent integration (Bybit/Lighter-style account-read reconciliation) would consume
- `motim-phase-b-report.md` — what you did, files created/modified, gate results (G1–G5), any errors

## Completion

When ALL output files are written, run this in PowerShell to notify OpenClaw:

```
$topic = "ag-openclaw-b4zaCyNakC3zMJ566TYCa0ifoXdprXhwu9gm5UjdiJs"
$payload = @{
  schema = "ag.ntfy.v1"
  job = "motim-phase-b"
  status = "complete"
  project_dir = "C:\Users\houst\PycharmProjects\motim-fork"
  required = @("SECURITY.md", "ROADMAP.md", "motim-phase-b-report.md")
  optional = @("tests/")
  message = "All artifacts written"
  ts = Get-Date -Format "yyyy-MM-dd HH:mm EDT"
} | ConvertTo-Json -Compress

Invoke-WebRequest -Method POST -Uri "https://ntfy.sh/$topic" -Headers @{"Content-Type"="application/json";"Title"="AG job complete";"Tags"="white_check_mark"} -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 15 -UseBasicParsing
```

Include in the report: what you did, files created/modified, key findings, and any errors encountered.