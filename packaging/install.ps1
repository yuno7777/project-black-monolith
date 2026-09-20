$ErrorActionPreference = "Stop"
foreach ($command in @("python", "node", "npm", "psql")) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "$command is required and must be on PATH"
  }
}
if (-not (Test-Path .venv)) { python -m venv .venv }
& .venv\Scripts\python.exe -m pip install --require-hashes -r vector-anchor\requirements.lock -r trace-audit\requirements.lock
npm ci --prefix dashboard
npm run build --prefix dashboard
if (-not (Test-Path .env)) { & .venv\Scripts\python.exe scripts\generate_secrets.py }
Write-Host "Installed. Configure DATABASE_ADMIN_URL and DATABASE_URL in .env, then run:"
Write-Host ".venv\Scripts\python.exe scripts\run_local_demo.py --skip-build"
