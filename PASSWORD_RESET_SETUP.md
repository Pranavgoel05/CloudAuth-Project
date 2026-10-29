# CloudAuth Forgot Password — Setup and Test

The feature adds a password-recovery link to the login screen and two API routes:

- `POST /auth/password/forgot` — request a reset link.
- `POST /auth/password/reset` — set a new password using a valid reset token.

## Security behavior

- Reset tokens are generated randomly, stored only as SHA-256 hashes, expire in 20 minutes, and are single-use.
- A new request invalidates previous active reset links for the account.
- The forgot-password endpoint uses a generic response so it does not reveal whether an email address is registered.
- After a successful reset, active refresh tokens are revoked and temporary login lockout is cleared. Existing access JWTs can remain valid until their short expiry (15 minutes).
- MFA is not disabled by a password reset.
- In local development only, when `APP_ENV` is not `production` and no email API key is set, the endpoint returns a reset URL for manual testing. This link is never returned in production.

## Local test

1. Start the application with `APP_ENV=development`.
2. Register an account and click **Forgot password?**.
3. Submit the account email. For an existing account, the UI displays a local-only development reset link.
4. Open the link, enter and confirm a new strong password, and submit.
5. Log in using the new password. The old password and reset link should no longer work.

## Hosted setup on Render

Render's free web services block outbound SMTP ports, so the hosted feature uses Resend's HTTPS API.

1. Create a Resend account at https://resend.com/ and create an API key with sending permission.
2. For delivery to arbitrary users, add and verify a sender domain in Resend. Resend will show the exact DNS records to add at the DNS provider for your domain. Do not guess the DNS records.
3. Set these variables under Render → `cloudauth-demo` → Environment:
   - `RESEND_API_KEY`: the private Resend API key.
   - `RESEND_FROM_EMAIL`: a sender on your verified domain, e.g. `CloudAuth <noreply@your-verified-domain>`.
   - `PUBLIC_BASE_URL`: `https://cloudauth-demo.onrender.com`.
4. Save and redeploy. Do not put these values in GitHub or this document.
5. Visit the public login page, click **Forgot password?**, request a reset for an existing account and check that account's inbox (including Spam). The public response is intentionally generic.
6. If no email arrives, check Render logs for the generic password-reset delivery warning and inspect the email provider's dashboard logs. Never paste API keys or reset tokens into support chats.

If `APP_ENV=production` and `RESEND_API_KEY` is missing, the endpoint returns HTTP 503 for all addresses rather than creating a reset token that cannot be delivered.
