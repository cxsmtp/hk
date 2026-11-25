# Sign-in and passwords

How people sign in to Hawk AI, and what happens when someone forgets their password. Ported from CxMissionZero's
`docs/sign-in.md` (MZ-01.00.78, MZ-01.01.11) with its numbers and wording; where Hawk differs, this page says so.

## Passwords

- At least 12 characters, not repetitive (5 different characters at least), at most 72 bytes (Hawk hashes with
  bcrypt, which reads only the first 72 bytes; CxMissionZero uses scrypt and allows 256). The same rule everywhere:
  registration, the first administrator, changing one's password and a reset link.
- **Five wrong passwords in a row lock the account for 15 minutes.** While it is locked, only someone who types the
  right password learns it (423, "Too many failed attempts: try again after …"); anyone else gets the same
  "Wrong email or password." as for any wrong password or unknown address. Wrong two-step codes count too.
- **At most 30 sign-in attempts in 10 minutes from one network address** (password, two-step code, single sign-on
  return, the Executive MCP connector's forms). The address is the connection's: behind the front proxy
  (`deploy/Caddyfile`), Caddy sets `X-Forwarded-For` itself and uvicorn takes it from there, so a header sent by the
  browser changes nothing.
- A disabled account is told so (403) only after the right password.

## Idle sign-ins (`SESSION_IDLE_MINUTES`, 480)

CxMissionZero keeps a server-side session that ends after 8 hours without use. Hawk's console holds a 30-minute access
token and a refresh token that is replaced at every refresh. A refresh token that was not used for
`SESSION_IDLE_MINUTES` (default 480 = 8 hours) is refused, so the person signs in again. Because each refresh issues a
new refresh token, its age is the time since the sign-in was last used. An access token already issued keeps working
until its own 30 minutes are over.

**Signed out everywhere.** A password reset (and changing one's own password) revokes every refresh token of the
account and records the moment (`users.signed_out_at`): access tokens issued before it are refused at once.

## Forgot your password?

"Forgot your password?" under **Sign In** sends a one-time link to the account's own email address. It shows only when
it can work: an owner or admin allows it (Settings → Sign-in), the email server is set up and tested, and the server's
own https address is set (`PUBLIC_URL`, which `deploy/compose.yaml` passes as `WEB_ORIGIN`).

| | |
| --- | --- |
| **Nothing to learn from asking** | The answer is word for word the same whether or not the address has an account, it takes at least a quarter of a second either way, and the email goes out after the answer. |
| **Only to the account's own address** | The link goes to the account's email, never to one given in the request. Accounts with no password of their own (added by single sign-on) and disabled accounts never get one. |
| **Only to this server** | The link points at `WEB_ORIGIN`, never at the address a request arrived on. It must be https (unless it is this computer). |
| **A secret no one else holds** | 256 random bits after `#` (`/login/reset#reset=…`): browsers never send that part to a server or in a `Referer`, and the page takes it out of the address bar at once. Only its SHA-256 is kept, in Redis with a 30-minute time to live (see *Where it is kept*). |
| **Once, for 30 minutes** | A link works once. Asking again replaces the earlier link; changing the password any other way ends it too. |
| **Limited** | At most 3 links an hour to one person, a minute apart, and at most 10 requests (and 10 links that do not work) a quarter of an hour from one network address. |
| **Strong, and new** | The new password follows the same rules and may not be the current one. |
| **Everyone out** | Saving it signs the account out everywhere, clears a lock after wrong passwords, and an email confirms the change with when and from where. |
| **Recorded** | Each link sent (or not sent, and why), and each password reset, is in the audit log, never the link itself. |

**Who may use it** (Settings → Sign-in): **Everyone with a password** (the default), **Everyone except those who
manage people** (owners and admins of any tenant), or **Nobody**. An owner or admin who may not reset by email gets a
temporary password on the server: `python -m app.cli.reset_admin <email>`.

### The email server (`SMTP_*`)

Hawk had no way to send email before this. It now sends with the variables CxMissionZero uses, under the same names:

| Variable | Meaning | Default |
| --- | --- | --- |
| `SMTP_HOST` | Mail server name | (none: no email) |
| `SMTP_PORT` | Port | `587` |
| `SMTP_SECURE` | `true`: TLS from the first byte (port 465). `false`: STARTTLS, required before any login is sent | `false` |
| `SMTP_USER`, `SMTP_PASS` | Login (left out: no login, for an internal relay) | |
| `SMTP_FROM` | From address | `SMTP_USER` when it is an address |
| `SMTP_FROM_NAME` | Sender name | `Hawk AI` |

The mail server's certificate is always checked. Nothing is sent until an owner or admin presses **Send a test email to
me** (Settings → Sign-in) and it arrives: the fingerprint of exactly these settings is kept, so changing any of them
asks for a new test (CxMissionZero's "tested" rule).

## Two-step sign-in

After the password, a six-digit code from an authenticator app (Microsoft Authenticator, Google Authenticator, or any
other that makes time-based codes). It covers signing in with an email and password, in the console and on the
Executive MCP connector's forms; it is not asked for after single sign-on.

**Turning it on, for yourself.** Settings → Two-step sign-in → **Turn on two-step sign-in**: scan the QR code (made in
the page; nothing is fetched), enter the code, keep the ten recovery codes. **New recovery codes** and **Turn off** ask
for a current code from the app: a recovery code is not enough.

**Required for everyone.** Settings → Sign-in → **Require two-step sign-in for everyone who signs in with a password**.
A person without it sets it up at their next password sign-in, before they get in; nobody can turn their own off.

**Lost the phone?** Sign in with a recovery code. No codes left: an owner or admin uses **Reset two-step** on Settings →
Sign-in (for people whose role is not above theirs). **The only administrator lost it:** start the API once with
`RESET_TWO_STEP=<their email>`; the log says `Two-step sign-in was reset for …` and the audit log records it. Left in
the environment it does nothing more, until the API has started without it. Or `python -m app.cli.reset_admin <email>`
sets a temporary password and takes two-step sign-in off in one go.

| | |
| --- | --- |
| **A standard anyone can check** | TOTP (RFC 6238): HMAC-SHA1, six digits, 30 seconds; the code before and after are accepted too. Python's own `hmac`. |
| **No tokens before the code** | A correct password gives only a ticket: 256 random bits, kept as a hash, for one person, five minutes. |
| **A code works once** | The step of the last code used is kept; that code and any older one are refused. |
| **Wrong codes are limited** | Five wrong codes end the ticket, and they count as wrong passwords do. |
| **Recovery codes are not kept** | Only their SHA-256 is. A used one is removed. |
| **The key** | The server must work out the code, so the key cannot be a hash: it is kept with the person, encrypted with the connector secrets key. |

## Single sign-on (OpenID Connect)

Hawk already had OIDC sign-in; it now follows CxMissionZero's rules. The identity providers stay in Hawk's
configuration; who may sign in through them is set on Settings → Single sign-on.

| CxMissionZero | Hawk |
| --- | --- |
| On/off (People & roles → Sign-in) | `COMPANY_SSO_ENABLED` |
| Issuer, client id, button label | `OIDC_PROVIDERS_JSON` (`issuer`, `client_id`, `display_name`; one per workspace) |
| Client secret | `OIDC_PROVIDER_SECRETS_JSON` (encrypted) |
| Redirect `<server>/api/session/oidc/callback` | `OIDC_CALLBACK_URL` (`…/auth/oidc/callback`), then the console at `OIDC_FRONTEND_URL` |
| Round trip kept 10 minutes | `OIDC_STATE_TTL_SECONDS`, default now 600 (was 300) |
| Who may sign in, role, email domains, verified email, passwords for Admins only | Settings → Single sign-on (stored in `sign_in_policy`) |
| Links by (issuer, sub) in `iam.json` | `users.sso_issuer`, `users.sso_subject`; `OIDC_BINDINGS_JSON` (no longer required) still links the subjects it lists |

- The authorization code flow with PKCE (S256), `state` and `nonce`, kept in Redis, used once, tied to the browser by
  an HttpOnly, SameSite=Lax cookie.
- The ID token is verified with RS256, PS256 or ES256 only (RSA keys of 2048 bits or more), then its issuer, audience
  and authorized party, expiry, issue time, not-before and nonce, with a minute of clock difference. Hawk keeps its own
  extra rule: the token's `amr` must include `mfa`.
- The email must be marked verified by the provider, unless an owner or admin turns that off; never for an owner or
  admin who is not linked yet.
- **Who may sign in**: people already in Hawk AI (the default), or everyone in the allowed email domains, added at their
  first sign-on with the role chosen (viewer, operator or auditor; never owner or admin) in the provider's workspace.
- **Only Admins may still sign in with a password**: with single sign-on on, everyone else's correct password gets
  "Signing in with a password is turned off for this account. Use single sign-on."
- When it does not work, the sign-in page says why in one sentence (`/login#sso=<code>`); the detail is in the audit
  log (`auth.sso.refused`) and in the API log on a line starting `! [single sign-on]`.

## Where it is kept

Hawk runs several API processes, so what CxMissionZero keeps in its process memory is kept in Redis (`REDIS_URL`),
each with its time to live: two-step tickets, keys waiting for their first code, reset links' hashes, the Executive MCP
connector's authorization codes and the sign-in limits. `SIGN_IN_STORE=memory` keeps them in one process instead (unit
tests, a single local process). If Redis cannot be reached, steps that need a ticket or a link are refused ("Sign-in is
unavailable for a moment"); the limit per address is then not counted, but the lock after five wrong passwords (in the
database) still holds.

## Executive MCP connector (OAuth)

`/mcp/executive/register` keeps each client and its exact redirect URIs (https, or http to localhost). `/authorize`
sends a code only to one of those URIs and requires PKCE with S256; the code is random, kept five minutes, works once,
and only for the client and redirect URI it was issued to. Its email-and-password forms (and the device form) have the
same lock, limit, "passwords for Admins only" and two-step code as the console.

## Roles

The auditor reads and never changes anything: it ranks above the operator for reading (`min_role="auditor"` routes),
but on routes that need at least an operator it may only read (GET, HEAD, OPTIONS). Routes that name it explicitly keep
doing so.
