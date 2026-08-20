# Installation and run guide

## Requirements

- Python 3.11+
- Windows, macOS, or Linux
- A current compiler toolchain only if `liboqs-python` must build locally

## Recommended setup

Create and activate a virtual environment, then install the pinned ranges:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On macOS/Linux, activate with `source .venv/bin/activate`.

Start the application from this folder:

```powershell
$env:VAULT_AGENT_ID = "agent-demo-001"
uvicorn server:app --reload --host 127.0.0.1 --port 8001
```

Open `http://127.0.0.1:8001`.

## Backend selection

AgentShield tries `liboqs` first and the `cryptography` ML-KEM implementation second. Select explicitly when troubleshooting:

```powershell
$env:PQS_BACKEND = "cryptography"
uvicorn server:app --reload --port 8001
```

Valid values are `auto`, `liboqs`, and `cryptography`. A vault created with one backend must continue using that backend because key serialization is backend-specific.

## Resetting a demo vault

Stop the server and move these runtime files to a backup folder: `vault_public.pem`, `vault_private.pem`, `key_meta.json`, `secrets.json`, `agents.json`, `policies.json`, and `audit_log.json`. Start the server again to create a fresh vault. Keep all seven files together if you need to restore it.

## Common issues

- **PowerShell blocks activation:** run `Set-ExecutionPolicy -Scope Process Bypass`, then activate the environment again.
- **No ML-KEM backend:** upgrade pip and reinstall requirements. On machines where `liboqs` cannot build, set `PQS_BACKEND=cryptography`.
- **Port already in use:** choose another port, for example `--port 8002`, and open that address.
- **Old dashboard after editing:** perform a hard refresh. The homepage is served with no-cache headers in development.
- **Incomplete key material:** restore all vault files from the same backup or move the incomplete set aside and start a fresh demo vault.
