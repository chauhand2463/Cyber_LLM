$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Start Backend
Write-Host "Initializing Cybernetic Backend Core..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ScriptDir'; & '.\.venv\Scripts\python.exe' -m uvicorn api.app:app --reload --port 8000"

# Start Frontend
Write-Host "Launching Mission Control Interface..." -ForegroundColor Magenta
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$ScriptDir\frontend'; npm run dev"

Write-Host "MISSION CONTROL ONLINE" -ForegroundColor Green
Write-Host "Access Dashboard at: http://localhost:3000" -ForegroundColor White
