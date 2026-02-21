$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
$RunAgentsScript = Join-Path $ScriptDir "run_agents.py"

if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment not found at $VenvPython. Please run 'pip install -r requirements.txt' inside a created virtual environment first."
    exit 1
}

# Pass all arguments to the python script
& $VenvPython $RunAgentsScript @args
if ($LASTEXITCODE -ne 0) {
    Write-Error "Agent execution failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
