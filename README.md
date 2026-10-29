# Cloud User Authentication System Using Python — Hardened Demo & Free Hosting

This is an academic prototype featuring a FastAPI backend, browser dashboard, Argon2 password hashing, signed JWT access tokens, refresh-token rotation/revocation, TOTP MFA, RBAC, account lockout, rate limiting, database audit logs, and a Moto simulation of selected AWS services.

**Not a production identity provider.** Use only demo accounts and data. The simulated AWS services are not a live AWS deployment. For public hosting, use HTTPS provided by the host, a managed PostgreSQL database, private environment variables, a unique admin password, and MFA for the admin account.

## Run locally on Windows

1. Install Python 3.11+.
2. Extract the project ZIP.
3. Double-click `start_windows.bat`.
4. The script creates `.venv`, installs dependencies, copies `.env.example` to `.env` if needed, and prompts you to create a private administrator if one does not exist.
5. Open http://127.0.0.1:8000. Keep the terminal running.

The local administrator password is entered in the terminal and is not echoed. The dashboard contains no pre-filled administrator or auditor credentials. To demonstrate RBAC, register a normal user in the UI; only an administrator created through the local CLI or private deployment configuration can have the admin role.

macOS/Linux:

```bash
chmod +x start_mac_linux.sh
./start_mac_linux.sh
```

## Local commands

```bash
# Create the first admin if none exists; does not reset existing credentials
python -m app.create_admin

# Run tests
python -m pytest -q

# Start server manually
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

API docs: http://127.0.0.1:8000/docs
Health: http://127.0.0.1:8000/health

## Free public hosting option: Render + Supabase

This project includes `render.yaml` for a Render free web service. Use Supabase Free as the PostgreSQL database rather than Render's free Postgres for anything that must last beyond a short demo. Current free plans have limits and can pause/sleep; check the provider dashboards before the presentation.

1. Create a GitHub repository from this project and push the source. **Do not commit `.env`, generated keys, database files, or secrets.**
2. Create a Supabase project. Copy the PostgreSQL **Session Pooler** connection string from Supabase's Connect panel. Use a URL like `postgresql+psycopg://...` (URL-encode special characters in the password). Keep the string private.
3. In Render, create a Blueprint from the GitHub repository using `render.yaml`, or create a Python Web Service manually with:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`
4. In Render's private Environment settings, set these values:
   - `APP_ENV` = `production`
   - `CLOUD_SIMULATION` = `true` (Moto simulation only; not live AWS)
   - `DATABASE_URL` = your Supabase PostgreSQL connection string, converted to `postgresql+psycopg://...`
   - `AUTH_JWT_SECRET` = a unique random string of at least 32 characters
   - `AUTH_ENCRYPTION_KEY` = a Fernet key generated with the command below
   - `BOOTSTRAP_ADMIN_EMAIL` = your own admin email
   - `BOOTSTRAP_ADMIN_PASSWORD` = a unique strong password known only to you
   - `AWS_DEFAULT_REGION` = `us-east-1`
5. Generate the key values locally (do not put them in Git or send them in chat):

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Use the first output for `AUTH_JWT_SECRET`, and the second for `AUTH_ENCRYPTION_KEY`.
6. Deploy. When the service starts for the first time, it creates the single administrator from the private environment variables. It never resets the existing admin's password on later starts and refuses to silently promote a regular account.
7. Open the public HTTPS URL. Sign in using your admin email/password, immediately enable TOTP MFA with your authenticator app, then log out and test login with the code.
8. Test from a private/incognito browser: create a normal account and confirm it cannot access `/admin/users` (`403`). Keep the admin credentials private and do not send them to your teacher.

### Free-hosting caveats

- Render free web services sleep after 15 minutes without inbound traffic and can take about a minute to wake. Local filesystem data is ephemeral, so this configuration requires the external PostgreSQL database and stable `AUTH_JWT_SECRET`/`AUTH_ENCRYPTION_KEY` environment variables.
- Supabase Free can pause projects after a week of low activity. Open the dashboard and check project status before your demo.
- Moto creates simulated AWS resources in the running process. They are re-created after a restart. The persistent audit database is authoritative; the simulated CloudWatch/S3 side effects are only demonstration exports and may reset after a restart.
- The app uses a process-local rate limiter; keep one application instance for this demo.
- A free public URL is suitable for a classroom demonstration, not production identities or sensitive data.

## Security design notes

- No admin/auditor password is embedded in HTML/JavaScript or shipped as a default.
- Public registration always assigns role `user`; there is no public role-selection input.
- Admin creation is local-terminal-only (`python -m app.create_admin`) or one-time bootstrap via private host environment variables.
- A hosted deployment fails startup if production secrets, database URL or bootstrap credentials are missing.
- Admin credentials must be unique, private and protected with MFA after first login.
- Passwords use Argon2; refresh tokens are stored as hashes; JWT access tokens expire after 15 minutes.
- `AUTH_ENCRYPTION_KEY` remains stable across host restarts so encrypted MFA secrets remain decryptable. The Moto KMS resource is tested separately as a simulated cloud-integration demonstration; it is not the persistent key store for hosted MFA records.
- Real AWS Secrets Manager/KMS/CloudWatch/S3 integration, production-grade centralized rate limiting, access-token denylisting, recovery codes, backups and a formal security review remain future work.
