# Cloud User Authentication System Using Python

A final-year cybersecurity project demonstrating a Python authentication API, browser dashboard, and selected cloud-security concepts. The application uses FastAPI, SQLAlchemy, PostgreSQL (hosted) or SQLite (local), Argon2 password hashing, JWT access tokens, refresh-token rotation/revocation, TOTP multi-factor authentication (MFA), role-based access control (RBAC), temporary account lockout, rate limiting, audit logging, password recovery by email, and simulated AWS services through Moto.

> **Project status:** Academic prototype, not a production identity provider. Use demo accounts and non-sensitive data only. The current AWS KMS, Secrets Manager, IAM, CloudWatch Logs, and S3 integrations are simulated with Moto; they are not live AWS resources.

## Features

- User registration with password-policy validation and Argon2 password hashing.
- Login, short-lived signed JWT access tokens, and refresh-token rotation/revocation.
- TOTP MFA compatible with authenticator applications.
- Role-based access control for `user`, `admin`, and `auditor` roles.
- Temporary account lockout and endpoint rate limiting.
- Audit events stored in the application database, with simulated cloud exports.
- Forgot Password flow using Resend's HTTPS Email API.
- Password-reset links that expire after 20 minutes, can be used once, and are stored in the database as token hashes.
- Browser UI for registration, login, profile access, MFA, administrative views, audit events, and password reset.
- Pytest automated tests, Dockerfile, and GitHub Actions CI workflow.

## Architecture

- **FastAPI / Uvicorn:** HTTP API and application server.
- **SQLAlchemy:** ORM and database access.
- **SQLite:** local demonstration database.
- **PostgreSQL via Supabase:** persistent hosted database.
- **Argon2:** password hashing and password verification.
- **JWT:** signed access tokens.
- **PyOTP:** TOTP MFA generation and verification.
- **Resend:** password-reset emails sent over HTTPS (not SMTP).
- **Moto / Boto3:** simulated AWS integrations for the academic demo.
- **Pytest / HTTPX:** automated tests.

## Run locally on Windows

1. Install Python 3.11 or newer.
2. Extract the project ZIP.
3. Double-click `start_windows.bat`. The script creates `.venv`, installs dependencies, prepares `.env` from `.env.example` if needed, and prompts for an administrator if none exists.
4. Open <http://127.0.0.1:8000>. Keep the terminal running.

The local administrator password is entered in the terminal and is not echoed. The dashboard does not contain pre-filled administrator or auditor credentials. Public registration creates a regular `user` account; it cannot assign the administrator role.

### macOS / Linux

```bash
chmod +x start_mac_linux.sh
./start_mac_linux.sh
```

### Local commands

```bash
# Create an administrator only if one does not already exist.
# This does not reset an existing administrator password.
python -m app.create_admin

# Run the automated tests
python -m pytest -q

# Start the server manually
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- Dashboard: <http://127.0.0.1:8000>
- Health check: <http://127.0.0.1:8000/health>
- API docs: <http://127.0.0.1:8000/docs>

## Public hosting: Render + Supabase

The current public deployment uses Render for the FastAPI web service and Supabase PostgreSQL for persistent data. The free plans have limits and may sleep or pause due to inactivity; check both provider dashboards before a presentation.

1. Keep the GitHub repository private unless/until a security review has checked the entire Git history for secrets.
2. Create a Supabase project. From **Connect**, copy the PostgreSQL **Session Pooler** URI. Use the URI supplied by Supabase and URL-encode any special characters in the database password. The application expects a SQLAlchemy-compatible URL such as `postgresql+psycopg://...`; follow the project configuration and README instructions if the copied URI uses `postgresql://...`.
3. In Render, create a Blueprint from this repository using `render.yaml`, or create a Python Web Service with:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`
4. Add configuration in Render's **Environment** settings. Never put production values in source code or GitHub.

| Variable | Purpose / expected value |
|---|---|
| `APP_ENV` | `production` |
| `CLOUD_SIMULATION` | `true` for the Moto-based cloud demonstration |
| `AWS_DEFAULT_REGION` | `us-east-1` for the simulated AWS resources unless your project configuration requires otherwise |
| `DATABASE_URL` | Private Supabase PostgreSQL connection URI; use the SQLAlchemy-compatible format required by the application |
| `AUTH_JWT_SECRET` | Unique random secret used to sign JWTs |
| `AUTH_ENCRYPTION_KEY` | Stable Fernet key used to encrypt sensitive values such as stored MFA secrets |
| `BOOTSTRAP_ADMIN_EMAIL` | Your administrator email address |
| `BOOTSTRAP_ADMIN_PASSWORD` | Your unique, strong administrator password |
| `RESEND_API_KEY` | Private Resend sending API key |
| `RESEND_FROM_EMAIL` | Sender identity on a verified Resend domain, e.g. `CloudAuth <no-reply@notify.securebiz.co.in>` |
| `PUBLIC_BASE_URL` | Public HTTPS URL, e.g. `https://cloudauth-demo.onrender.com` |

Generate `AUTH_JWT_SECRET` locally (do not commit or share the output):

```powershell
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

Generate `AUTH_ENCRYPTION_KEY` with a Python environment where `cryptography` is installed:

```powershell
py -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep the encryption key stable across restarts and redeployments. Changing it can make existing encrypted MFA secrets unreadable. The app creates the initial administrator from the private bootstrap environment variables during first startup; it does not reset the password of an existing administrator on subsequent starts.

After deployment, open the Render-provided HTTPS URL. Sign in as the administrator, immediately enable TOTP MFA, then sign out and verify that login requires the authenticator code. In a separate private/incognito browser, register an ordinary user and confirm that the user cannot access administrator-only endpoints (for example, `/admin/users` should return `403`). Do not give your administrator credentials to your teacher or embed them in the public UI.

## Password recovery and Resend email setup

The **Forgot password?** flow sends a short-lived reset link by email through the Resend HTTPS API. Render's free web services block outbound SMTP ports, so this project calls the Resend API at `https://api.resend.com/emails` over HTTPS rather than using SMTP.

### 1. Verify a domain you control

1. Create or sign in to a Resend account at <https://resend.com/>.
2. Open **Domains** and add a domain/subdomain you own or are explicitly authorized to use. This deployment uses `notify.securebiz.co.in` as the sending subdomain.
3. Resend will show the DNS records required for domain verification and sending. Add the exact records shown in your Resend dashboard to the DNS provider that manages the domain's active nameservers. Do not copy a DKIM TXT value from another account or project; use the full value generated for your own domain.
4. For this setup, the Cloudflare zone is `securebiz.co.in`. Resend displayed these sending records for the selected region:

   | Type | Name (relative to `securebiz.co.in`) | Target / value |
   |---|---|---|
   | CNAME | `send.notify` | `send.forge.rmta.net` |
   | CNAME | `rsend.notify` | `rsend-apne1.forge.rmta.net` |
   | TXT | `resend._domainkey.notify` | The full DKIM public-key value shown by Resend; copy it exactly from your own dashboard |

   **Important:** These targets are specific to the records Resend displayed for this project/region. If your Resend dashboard shows different values, use the current dashboard values. DNS providers may append the zone name automatically; avoid entering the full domain twice. Set the CNAMEs to **DNS only** if using Cloudflare, not proxied. Leave TTL on Auto unless your provider requires otherwise.
5. Return to Resend and wait until the domain status is **Verified**. DNS verification can take time. For password resets, only sending is required; inbound-email/receiving setup is not required.

Only send from a domain you own or are authorized to use. Do not use an institutional domain without permission from its administrator.

### 2. Create a Resend API key

1. In Resend, open **API Keys** and create a key for CloudAuth.
2. Choose **Sending access**. If the dashboard supports restricting the key to a domain, restrict it to `notify.securebiz.co.in`.
3. Copy the key when Resend displays it. Store it privately; do not paste it into GitHub, `README.md`, source files, or chat.

### 3. Configure Render environment variables

In Render, open the `cloudauth-demo` service → **Environment**. Add or update the following values:

- `RESEND_API_KEY`: the private Resend API key created above.
- `RESEND_FROM_EMAIL`: `CloudAuth <no-reply@notify.securebiz.co.in>` (must match your verified domain).
- `PUBLIC_BASE_URL`: `https://cloudauth-demo.onrender.com` (must be the live public URL, without a trailing slash requirement).

Save the environment changes and wait for Render to redeploy. In the Resend account associated with the API key, the sending domain must be verified and the key must have permission to send.

### 4. Test the password-reset flow

1. Open the live CloudAuth page and click **Forgot password?**.
2. Submit the email address of an existing, active CloudAuth account. The public endpoint deliberately returns the same generic response for registered and unregistered addresses so it does not reveal account existence.
3. Check the recipient's Inbox, Spam/Junk and Promotions folders. In Resend, check **Emails** for message delivery status and **Logs** for the `POST /emails` API request/status.
4. Open the reset link. It expires after 20 minutes and can be used only once. Enter a new password and submit it.
5. On successful reset, the page displays a success message and redirects to the login form. Sign in with the new password; if MFA is enabled, a valid authenticator code is still required. The old password should fail.

### 5. Troubleshooting Resend delivery

- **No email appears:** Confirm the email belongs to an existing, active CloudAuth account. The generic API response is intentional and does not prove an email was sent.
- **Resend reports an authorization error:** Confirm `RESEND_API_KEY` is current, active, has Sending access, and belongs to the same Resend account/domain. Confirm `RESEND_FROM_EMAIL` matches the verified domain.
- **Domain not verified:** Check the Resend domain page and make sure the DNS records exactly match the current records Resend generated. Check the DNS provider managing the active nameservers and ensure Cloudflare CNAMEs are DNS only.
- **Render logs say email delivery failed:** Check Render logs at the time of the request, plus Resend **Logs** and **Emails**. The production endpoint responds generically to avoid email/account enumeration.
- **HTTP 403 with a non-JSON response and no Resend log entry:** The response may be generated by an intermediary/edge layer before reaching Resend. A Cloudflare `1010` response means a browser-signature block. Do not repeatedly create API keys or change DNS records. Capture the HTTP status, response content type, Cloudflare Ray ID and timestamp (without credentials or reset tokens) and contact Resend Support if needed.
- **Direct API test succeeds but hosted app fails:** Compare the hosted environment variables, sender, API endpoint, request headers, and the most recent deployed commit. Do not print or log the API key, recipient reset URL, or token.

The public API does not return a raw reset token. In local development only, a reset URL may be returned to facilitate testing when email is not configured. Reset links are stored in the database as SHA-256 token hashes; a new reset request invalidates previous unused links. After a successful reset, refresh-token sessions are revoked and temporary failed-login/lockout state is cleared. MFA remains enabled.

## Tests

Run the automated suite from the project root with the project's virtual environment activated:

```powershell
python -m pytest -q
```

A successful run should report all tests as passed. Test count may change as features are added. Automated tests check defined behavior; they do not prove the application is free of all security vulnerabilities.

## Free-hosting caveats

- Render free web services sleep after 15 minutes without inbound traffic and may take about a minute to wake. The public URL remains the same, but the first request after sleep may be slow.
- Render's local filesystem is ephemeral. Use the external PostgreSQL database for persistent application data and keep `AUTH_JWT_SECRET` and `AUTH_ENCRYPTION_KEY` stable.
- Supabase Free has limits and free projects can pause after a period of inactivity. Check its dashboard before a presentation.
- Moto's simulated AWS resources are recreated after a process restart. The database audit records are the persistent application records; simulated CloudWatch/S3 exports are demonstration side effects.
- The app's rate limiter is process-local; keep one application instance for this demo.
- A free public URL is suitable for a classroom demonstration, not for real users' sensitive identity data or production authentication workloads.

## Security notes and limitations

- Never commit `.env`, generated keys, database files, API keys, database connection strings, administrator passwords, MFA secrets, password-reset links, or reset tokens.
- The `.env.example` file is only a template; keep real values in local untracked `.env` files or the hosting provider's private environment settings.
- No administrator/auditor password is embedded in HTML/JavaScript or shipped as a default.
- Public registration always assigns role `user`; there is no public role-selection input.
- Hosted administrator creation is bootstrapped from private environment variables only once. Changing the bootstrap password later does not automatically reset an already-existing admin's password.
- Passwords use Argon2; refresh tokens and reset tokens are stored as hashes; access tokens expire after 15 minutes.
- `AUTH_ENCRYPTION_KEY` must remain stable to decrypt existing MFA secrets.
- Current AWS Secrets Manager/KMS/CloudWatch/S3 integration is simulated with Moto. Live AWS deployment, production-grade centralized rate limiting, access-token denylisting, MFA recovery codes, backups, alerting, and a formal security review are future work.

## Updating the GitHub repository

After editing this file in your local project folder:

```powershell
git add README.md
git diff --cached --check
git commit -m "Document Resend password reset setup"
git push origin main
```

Render can deploy the latest commit automatically when automatic deploys are enabled. Check the Render Events/Logs page to confirm the deployment succeeds.
