$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath ".\.venv\Scripts\python.exe")) {
    py -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

if (-not $env:VAULT_AGENT_ID) {
    $env:VAULT_AGENT_ID = "agent-demo-001"
}

& .\.venv\Scripts\python.exe -m uvicorn server:app --reload --host 127.0.0.1 --port 8001
