# HTTPS and hosting

Everything people send to Hawk AI is sensitive: sign-ins, the AI systems and findings it records, and the policies it enforces. Serve it over HTTPS only. Then nobody on the network can read it or change it on the way.

Hawk AI serves HTTPS by default (`HTTPS=on` in `deploy/compose.yaml`): with your certificate when you give one, otherwise with a self-signed one it makes (way C). An install never serves plain http by accident. `HTTPS=off` turns it off: for your own machine, or behind a load balancer that does HTTPS.

The behaviour, the defaults and the wording are those of CxMissionZero's HTTPS (its own docs/https-and-hosting.md); [How Hawk does it](#how-hawk-does-it-the-one-deviation) says what differs and why.

**No certificate from your organisation? One setting does it all.** With a DNS name pointing at the server and ports 80 and 443 open to the internet, set in `deploy/.env`:

```
BIND_ADDRESS=0.0.0.0
PORT=443
HTTP_REDIRECT_PORT=80
HAWK_HOST=hawk.company.com
LETSENCRYPT_DOMAIN=hawk.company.com
LETSENCRYPT_EMAIL=appsec@company.com
```

then run `sudo deploy/install.sh` again. Hawk AI gets a free certificate from Let's Encrypt (under a minute), switches to HTTPS only, and renews the certificate by itself 30 days before it expires. Setting `LETSENCRYPT_DOMAIN` means you accept the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/). The same is one button under Settings → HTTPS → **Free certificate from Let's Encrypt**. Details: [way B](#b-free-certificate-from-lets-encrypt-public-name).

**The easiest way with your organisation's certificate: Settings → HTTPS** (owners and admins). On the running server, with no new command:
1. upload the certificate (or create a request for IT there), checked like a browser would;
2. turn on HTTPS next to http (**HTTP and HTTPS**);
3. test it: open the https address;
4. switch to HTTPS only, from the page open over HTTPS;
5. add HSTS.

Replacing a certificate works the same way, and the previous one can be put back in one click.

| Way | Use it when | You need |
| --- | --- | --- |
| **A. Your company's certificate** | It runs inside the company network or VPN (the usual case) | A certificate for its name from your company CA or IT: `server.crt` and `server.key`, or one `.pfx` and its password |
| **B. Free certificate from Let's Encrypt**, got and renewed by Hawk AI itself | It has a public name that the internet can reach, and no certificate comes from your organisation | A DNS name (e.g. `hawk.company.com`) pointing at the host, with ports 80 and 443 open to it |
| **C. Self-signed**, made by Hawk AI (the default) | Trying it out, or a closed lab | Nothing. Browsers warn until the certificate is trusted |

## A. Your company's certificate

1. Ask IT for a server certificate for the name people will use, e.g. `hawk.company.com`. The name must be in the certificate's *Subject Alternative Name*. Ask for the full chain (server and intermediate certificates in one file), or for a `.pfx`.
2. Put the files in the data folder's `certs` folder (`/var/lib/hawk-ai/certs`, mounted read-only at `/certs` in the API), owned by uid 1000:

```
sudo cp server.crt server.key /var/lib/hawk-ai/certs/ && sudo chown 1000:1000 /var/lib/hawk-ai/certs/* && sudo chmod 0600 /var/lib/hawk-ai/certs/server.key
```

3. In `deploy/.env`:

```
TLS_CERT_FILE=/certs/server.crt
TLS_KEY_FILE=/certs/server.key
HAWK_HOST=hawk.company.com
BIND_ADDRESS=0.0.0.0
PORT=443
HTTP_REDIRECT_PORT=80
```

and run `sudo deploy/install.sh` again.

**With a `.pfx` instead:** `TLS_PFX_FILE=/certs/server.pfx` and `TLS_PFX_PASSPHRASE=…` in place of the two lines. An encrypted key: `TLS_KEY_PASSPHRASE=…`.

**What happens:**
- **HTTPS on 443.** Only TLS 1.2 and 1.3 are accepted.
- **http redirects.** Plain `http://` on port 80 (`HTTP_REDIRECT_PORT`) is redirected to `https://` (308). Plain http sent to the HTTPS port is redirected too.
- **Checked at start.** The API's log shows the certificate's name and expiry date. A certificate and key that don't match, or a wrong `.pfx` password, stop the start with the reason, and the proxy serves nothing. A wrong certificate never results in plain http.
- **Renewals need no restart.** Replace the files in the folder. Hawk AI picks them up within 5 minutes (it looks every 5 seconds). A broken new file is not used: the previous certificate stays in use and the log says why.

## B. Free certificate from Let's Encrypt (public name)

**Best choice when you will not get a certificate from your organisation.** Set the options at the top of this page.

What happens:
- At start, Hawk AI first checks that `http://hawk.company.com/` reaches it, so a wrong DNS entry or a closed port 80 is reported without using up Let's Encrypt's limits. Then it asks Let's Encrypt, answers its check on port 80, and puts the certificate to use without a restart.
- It switches to HTTPS only. Plain http redirects to https, except Let's Encrypt's own checks, which stay answered for renewals.
- It renews 30 days before expiry, by itself (it looks twice a day); each certificate and each failure is in the audit log.
- Restarting or updating keeps the certificate (it is in the data volume) and does not ask again.

| Option | Meaning |
| --- | --- |
| `LETSENCRYPT_DOMAIN` | The name(s), comma-separated. Setting it means you accept the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/). |
| `LETSENCRYPT_EMAIL` | Optional: where Let's Encrypt sends expiry warnings. |
| `LETSENCRYPT_STAGING=1` | Try Let's Encrypt's staging service first (browsers do not trust its certificates). |
| `LETSENCRYPT_SKIP_CHECK=1` | Skip the self-check, when the server cannot reach its own public name although the internet can. |
| `ACME_DIRECTORY_URL` | Another ACME certificate authority's directory instead of Let's Encrypt. |

From the page instead: Settings → HTTPS → **Free certificate from Let's Encrypt**: enter the name, tick the agreement, **Get the certificate**. It turns HTTPS on next to http; switch to HTTPS only there.

## C. Self-signed (trying it out)

What Hawk AI does when no certificate is given; `TLS_HOSTNAMES=hawk.company.com` in `deploy/.env` adds names. Open `https://localhost:3000`. The browser warns once, because nobody vouches for the certificate.
- **The certificate.** Hawk AI makes it at the first start (ECDSA P-256) and keeps it in the API's data volume (`/data/tls/self-signed.crt`) for about 13 months (397 days). It covers `localhost`, `127.0.0.1`, `HAWK_HOST`, the host of `PUBLIC_URL` and the names in `TLS_HOSTNAMES`. It is remade when the names change or it has fewer than 30 days left.
- **No HSTS.** With a self-signed certificate Hawk AI never sends HSTS, so a browser is never locked out of a site it can't verify. The log warns at every start that it is self-signed.
- **To stop the warning on your machines,** import that `.crt` as trusted (`docker compose -f deploy/compose.yaml cp api:/data/tls/self-signed.crt .`). In practice it's simpler to switch to way A or B.

## Settings → HTTPS

Owners and admins only, under **Settings → HTTPS** (`/settings/https`). Every change is written to the audit log.

- **How the server is reached:** **HTTP only**, **HTTP and HTTPS**, **HTTPS only**.
  - **HTTPS only** can be chosen only from the page opened over HTTPS: that proves HTTPS works from your browser before http goes away. With a self-signed certificate it asks you to confirm.
  - Back to **HTTP only** from HTTPS only asks you to confirm, and is refused while HSTS is on (turn HSTS off first).
- **Hardening** (saved as you change it): the lowest TLS version (TLS 1.2, or TLS 1.3 only), and HSTS. HSTS is refused until HTTPS only is on with a certificate browsers trust (never with a self-signed one). Start with **a day** (86,400 s), then a week, half a year, **a year** (31,536,000 s), with **Include subdomains** once every subdomain has HTTPS. A certificate given to the deployment (way A) starts with HSTS on for a year with subdomains, as CxMissionZero does.
- **Certificate in use:** who it is for, its names, issuer, expiry (flagged 30 days ahead) and where it came from, with every warning.
- **Upload your certificate:** PEM files in any order and with any names (certificate, chain or bundle, key), DER `.cer` / `.crt`, or one `.pfx` / `.p12` with its password. **Check it** checks without changing anything; **Check and put to use** puts it into use at once. Checked the way a browser would: it is served on a private loopback port and connected to, so the key belonging to the certificate, the chain (a missing intermediate is spotted), the names people use, the dates, the key's strength (RSA under 2048 bits refused) and its purpose (a web server certificate) are all reported first. With HTTPS only on, a certificate with warnings asks you to confirm.
- **Put the previous one back:** the certificate replaced last, in one click (the two swap).
- **No certificate yet?** **Create a request** (CSR) for IT: a new RSA 2048 key is made and kept on the server (0600), and `hawk-ai.csr` downloads. Upload just the certificate IT sends back: it pairs with the key by itself. Or **Make a self-signed one for these names**.
- **Free certificate from Let's Encrypt:** names, an email for expiry notices, the agreement, staging; **Renew now** and **Stop renewing** once it has one. Its last attempt (or why it failed) is shown.

**Locked out?** For example, nobody's browser accepts the certificate, or HSTS was turned on with a bad certificate. On the server, run:

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.https both
```

Within 5 seconds http works again next to HTTPS (on `HTTP_REDIRECT_PORT`), HSTS is off, and no restart is needed. Then fix the certificate on the page. `python -m app.cli.https` alone says what is set; `http` and `https` are the other choices. Every change, from the page or this command, is in the audit log.

## Settings

| Option (`deploy/.env`) | Default | What for |
| --- | --- | --- |
| `HTTPS` | `on` | How it starts: `on` HTTPS only (your certificate, else self-signed; plain http redirects), `off` plain http, `both` side by side. Once changed under **Settings → HTTPS**, the page's choice wins, across restarts and updates. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | — | PEM certificate (with its chain) and key, under `/certs` (the data folder's `certs`). |
| `TLS_KEY_PASSPHRASE` | — | If the key is encrypted. |
| `TLS_PFX_FILE`, `TLS_PFX_PASSPHRASE` | — | A `.pfx` / `.p12`, instead of the two PEM files. |
| `TLS_HOSTNAMES` | — | Extra names for the self-signed certificate (comma-separated). |
| `PORT` | 3000 | The HTTPS port people use (the proxy's 8443). Also where the redirect from http points. |
| `HTTP_REDIRECT_PORT` | 80 | Plain http: redirected to https while HTTPS only; Hawk AI itself while http is on next to HTTPS; Let's Encrypt's checks (they need 80). Set another port if 80 is taken on the machine. |
| `TRUST_PROXY` | nobody (Hawk serves HTTPS itself); `loopback` with `HTTPS=off` | Whose `X-Forwarded-*` headers to believe: `off`, `on`, an address, a CIDR (comma-separated for several), `loopback`, `linklocal` or `uniquelocal` (every private address). Set it to your load balancer's address when one sits in front. A number of hops is not supported. |
| `LETSENCRYPT_DOMAIN`, `LETSENCRYPT_EMAIL`, `LETSENCRYPT_STAGING`, `LETSENCRYPT_SKIP_CHECK`, `ACME_DIRECTORY_URL` | — | [Way B](#b-free-certificate-from-lets-encrypt-public-name). |

**Why not trust the whole private network by default.** On a company network most people's computers have private addresses too. If every private address were trusted, anyone could send `X-Forwarded-For` and appear as any address in the audit log. So by default nobody is believed when Hawk AI serves HTTPS itself. Name your load balancer's address, or its network (a CIDR such as `10.89.0.0/24`), and use `uniquelocal` only if no one else can reach Hawk AI directly from that network.

## How Hawk does it (the one deviation)

CxMissionZero is one process that serves HTTPS itself. Hawk AI is several containers behind one front proxy (Caddy), which keeps terminating TLS. So:

- **The API owns the HTTPS state** (`apps/api/app/services/https_manager.py`, `tls_service.py`, `acme_service.py`): the choices in `/data/https.json` (0600, a last good copy kept as `.bak`), the certificates and keys in `/data/tls` (keys 0600: `uploaded/`, `previous/`, `self-signed.*`, `request.key`, `acme/` account keys), the Let's Encrypt state in `/data/acme.json`. Nothing is in the database or the repository.
- **The API drives the proxy by writing its whole configuration** (`apps/api/app/services/https_proxy.py`): a Caddyfile and the certificate in use with its key, into the `hawk-proxy-config` volume (read-only in the proxy). Each file is written whole, flushed and renamed into place; a new certificate gets a new file name. The proxy runs `caddy run --watch`, so it reloads within about a second, keeping open connections. Caddy's admin API stays off: nothing on the network can reconfigure it. The proxy starts only once the API has written its configuration, and a certificate that cannot be used makes the API write a configuration that serves nothing (its health check fails with the reason) before it stops: never plain http.
- **Two ports instead of one.** CxMissionZero answers `http://` and `https://` on the same port (the first byte of each connection decides). Caddy cannot serve plain http on its TLS port: there it only answers with a 308 redirect to https (its `http_redirect` listener wrapper). So "http next to HTTPS" (`both`, and the way back in) is on the second port, `HTTP_REDIRECT_PORT` (CxMissionZero's name for its own extra http port), published by default on 80.
- **Let's Encrypt** is CxMissionZero's own ACME client, ported (`acme_service.py`), not Caddy's: the self-check, the button, the audit entries and the status on the page work as in CxMissionZero. The proxy hands `/.well-known/acme-challenge/` to the API in every mode.
- **`TRUST_PROXY`** is applied at the proxy (Caddy's `trusted_proxies`): it decides which `X-Forwarded-*` reach the API, which hears only from the proxy.

## Hosting it safely: checklist

- [ ] **Keep it internal if you can.** If everyone who uses Hawk AI is on the company network or VPN, don't expose it to the internet at all.
- [ ] **If it must face the internet,** allow only your company's address ranges at the firewall where possible. Expose only 443, plus 80 for redirects and Let's Encrypt.
- [ ] **HTTPS only,** with a certificate from IT (way A) or Let's Encrypt (way B), then HSTS.
- [ ] **Back up** the database and the data folder (deploy/README.md), and the `hawk-data` volume: it holds the HTTPS choices, the certificates and their keys.
- [ ] **Keep it current:** `git pull`, then `sudo deploy/install.sh`. Settings, certificates and data are kept.
