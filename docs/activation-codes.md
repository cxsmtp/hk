# Activation codes

Hawk AI is licensed with activation codes from the maintainer, the same way as CxMissionZero:

| What | Code | What it does |
| --- | --- | --- |
| **The product** | a product activation code | Keeps Hawk AI working past its end date (below), until the date the code gives. |
| **Several tenants** | a tenants activation code naming the organisation, how many tenants and, optionally, how many active users in each | Allows that many tenants; with a users cap, each tenant takes up to that many active users. |

Without a tenants code Hawk AI serves **one tenant**, with no cap on its users. Everything else works without a code, until the product licence's end date.

## The product licence: Hawk AI stops after 31 January 2027

Hawk AI works until the **end of 31 January 2027, UTC**. This is a licence on purpose: it is how Hawk AI is licensed. After that it stops until the **product activation code** from the maintainer is entered. There is **one product code for everyone** who uses Hawk AI: it is not tied to a server or an organisation, so the same key, given to everyone, works on every installation. The code says until when Hawk AI works; a new one, issued when the licensing changes, extends it again.

- **Before the end.** From 2 January 2027 (30 days before), owners and admins see a banner at the top of every page with the date and the days left, and **Settings → Activation codes** shows **Hawk AI · Active · Until the end of 31 Jan 2027 (UTC)**. A product code applied there moves the date at once.
- **After the end.** Every page shows **The product has been deactivated. Please reach out to Bhawani Singh.**, with **Enter an activation code**. Nobody can sign in; every other request to the API is refused (`503` with `{"error": "The product has been deactivated. Please reach out to Bhawani Singh.", "deactivated": true}`). Scheduled and background work (the Celery tasks: monitoring checks, discovery scans, snapshots, approval timeouts and the rest) stops: each task logs once that Hawk AI has been deactivated and returns, without retrying. The health checks (`/health`, `/health/live`, `/health/ready`, `/health/schema`) still answer, so the containers are not restarted over and over.
- **Nothing is deleted.** Settings, people, tenants, history and evidence stay in the database. Once a code is entered, everything works again as it was, with no restart.
- **Entering the code after the end.** Paste it on the deactivation page and select **Activate** (it posts to `/licence/activate`): anyone who reaches the server can, since only a code the maintainer signed is accepted (10 tries a minute from one address). Every code applied or refused there is in the audit log (actions `licence.activation_code.applied` and `licence.activation_code.refused`, by *deactivation page* and the address).
- **The code itself is what counts.** An accepted code is kept as the signed code in the database (the one row of `activation_state`) and checked again every time it is read: its date, what it unlocks and for how many tenants and users are read from the code, never from what is kept beside it. A date changed by hand there, an entry whose code was edited or signed by another key, or an entry with no code, counts for nothing.
- **An older code does not undo a newer one.** Codes are not tied to one server, so a code issued before the one in force for the same thing is refused. On the deactivation page, which anyone can reach, a product code is taken only if it runs longer than the one in force. Signed in, an owner or admin can still enter a newer code that ends sooner.
- **Setting the clock back does not help.** The licence goes by the latest time any Hawk AI process has seen, kept in the database (at most hourly); a code whose date has already passed on that clock is refused.

## For owners and admins: applying a code

1. Open **Settings → Activation codes** (in the account menu, under Administration). Owners and admins of a tenant can open it.
2. Paste the code you were sent, then select **Apply the code**.

What the code unlocks is switched on at once. The page then shows it, for which organisation and until when, and warns 30 days before the code expires; it lists the last 10 codes entered. Before the first tenants code it says **No add-ons are unlocked yet**.

With a tenants code in force, creating a tenant beyond its count is refused, and so is adding (or activating) a user in a tenant that already has as many active users as the code allows; the message names **Settings → Activation codes**. Tenants and users already there are never removed or disabled, also when there are more than a new code allows, or when the code expires (Hawk AI then serves one tenant again for new tenants, with no cap on users).

Codes are checked on the server against the maintainer's public key, which is built into Hawk AI. Nothing is sent anywhere. Every code applied, or refused, is recorded in the audit log (actions `activation.code.applied` and `activation.code.refused`) with who entered it.

## For the maintainer: issuing codes

Codes are signed with an Ed25519 key, using `tools/licensing/activation.py` (Python 3 with the `cryptography` package). It reads the same private key file as CxMissionZero's `scripts/activation.mjs`, so the existing `issuer-key.pem` works unchanged.

- **The private key stays with you.** Keep it outside the repository and the containers, and back it up.
- **Only the public key is built in,** as `ISSUER_KEYS` in `apps/api/app/services/activation_service.py`.
- **A new key pair** (only to replace the key): `python3 tools/licensing/activation.py keygen issuer-key.pem`. It refuses to overwrite an existing file and prints the public key to put in `ISSUER_KEYS`.

| To | Command |
| --- | --- |
| Allow several tenants | `python3 tools/licensing/activation.py issue issuer-key.pem "Acme Corp" 5` |
| Allow several tenants, each with up to 50 active users | `python3 tools/licensing/activation.py issue issuer-key.pem "Acme Corp" 5 --max-users 50` |
| Keep Hawk AI working until the end of a day (UTC) | `python3 tools/licensing/activation.py product issuer-key.pem 2027-12-31` |
| Keep Hawk AI working for some months | `python3 tools/licensing/activation.py product issuer-key.pem 12` |
| See what a code contains | `python3 tools/licensing/activation.py show HK1.…` |

- **Validity:** a tenants code lasts 12 months. Add a number of months after the tenant count to change that.
- **Format:** a code is `HK1.<payload>.<signature>`. The payload names the organisation, what the code unlocks and when it expires. Anyone can read it with `show`, but only your key can sign one. The signature covers the `HK1` prefix, so a CxMissionZero code (`MZ1`) never works in Hawk AI, nor a Hawk AI code in CxMissionZero.
