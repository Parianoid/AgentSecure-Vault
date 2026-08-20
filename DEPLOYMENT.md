# Public Demo Deployment

The simplest judge-accessible deployment is a Render web service connected to this GitHub repository.

## One-click Blueprint deployment

1. Push this repository to GitHub.
2. Sign in to Render and choose **New → Blueprint**.
3. Connect the `agentshield-vault` repository.
4. Approve the settings read from `render.yaml`.
5. Wait for the health check at `/health` to pass.
6. Open the generated `onrender.com` URL and perform the synthetic demo flow.

## Manual service settings

If you create a Web Service instead of a Blueprint, use:

```text
Language: Python
Build command: pip install -r requirements-render.txt
Start command: uvicorn server:app --host 0.0.0.0 --port $PORT
Health check path: /health
```

Environment variables:

```text
PQS_BACKEND=cryptography
VAULT_AGENT_ID=agent-demo-001
LOG_LEVEL=INFO
```

`requirements-render.txt` deliberately uses the standardized `cryptography` ML-KEM implementation and omits the native `liboqs-python` wrapper. This reduces deployment failures without replacing or simulating the ML-KEM-768 cryptographic path.

## Free-instance behavior

- The service can sleep after inactivity and may take roughly a minute to wake.
- Local files are temporary and reset after restarts, redeploys, or sleep cycles.
- Open the URL shortly before judging.
- Treat resets as a clean demo workspace.
- Never enter real credentials.

For durable production state, migrate metadata to a transactional database and move private-key operations to a managed KMS or HSM.

