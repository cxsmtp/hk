import type { GuideTopic } from "../types";

/** app/services/https_manager.py, app/services/acme_service.py, app/cli/https.py, deploy/.env.example, Settings → HTTPS. */
export const https: GuideTopic = {
  slug: "https",
  title: "HTTPS and certificates",
  summary: "The self-signed certificate Hawk AI starts with, your own certificate or a request (CSR) for IT, a free one from Let's Encrypt, the three modes, and the way back in when HTTPS locks you out.",
  sections: [
    {
      id: "default",
      title: "What you start with",
      blocks: [
        {
          kind: "p",
          text: "Hawk AI starts in HTTPS only (`HTTPS=on`) with a self-signed certificate it makes itself: every browser warns about it. Extra names for it go in `TLS_HOSTNAMES` (comma-separated). It serves HTTPS on `PORT` and plain http on `HTTP_REDIRECT_PORT`, which redirects to HTTPS.",
        },
        {
          kind: "p",
          text: "A certificate is chosen in this order: one put in place on [Settings → HTTPS](/settings/https) (uploaded, or returned by IT for a request made there, or from Let's Encrypt); one named in `deploy/.env`; otherwise the self-signed one. Every certificate is checked before use, the way a browser would: a wrong key, a missing intermediate, a name it does not cover or an expired date is reported before anyone meets it.",
        },
      ],
    },
    {
      id: "modes",
      title: "The three modes",
      who: "Owners and admins",
      blocks: [
        {
          kind: "table",
          head: ["Mode", "What it does"],
          rows: [
            ["**HTTP only**", "Plain http only: a test machine, or behind another proxy that does HTTPS."],
            ["**HTTP and HTTPS**", "Both side by side: try HTTPS while http keeps working."],
            ["**HTTPS only**", "HTTPS only: http answers with a redirect to HTTPS."],
          ],
        },
        {
          kind: "list",
          items: [
            "Switch on [Settings → HTTPS](/settings/https), with no restart. To switch to HTTPS only, open the page over its https address and switch there: that proves HTTPS works from your browser first.",
            "Once changed on the page, the page's choice wins over `HTTPS` in `deploy/.env`.",
            "Hardening on the same page: the lowest TLS version (TLSv1.2 or TLSv1.3) and HSTS (browsers then refuse plain http to this name). Turn HSTS on only with HTTPS only and a certificate browsers trust.",
          ],
        },
      ],
    },
    {
      id: "own-certificate",
      title: "Your own certificate",
      who: "Owners and admins",
      blocks: [
        {
          kind: "steps",
          items: [
            "On [Settings → HTTPS](/settings/https), under **Upload your certificate**, choose the files: PEM (certificate, chain and key, in any files) or one .pfx, and the key's or .pfx's passphrase if it has one.",
            "**Check it** shows whom it is for, until when, and any problem. **Check and put to use** swaps it in, with no restart.",
            "The certificate it replaced is kept: **Put the previous one back** returns to it.",
          ],
        },
        {
          kind: "p",
          text: "Or give the files to the server: put them in the `certs` folder of `HAWK_DATA_DIR` and name them in `deploy/.env`, then run `sudo deploy/install.sh` again. Renewed files are picked up within 5 minutes, with no restart.",
        },
        {
          kind: "table",
          head: ["Setting", "Example", "What it is"],
          rows: [
            ["`TLS_CERT_FILE`", "`/certs/server.crt`", "The certificate with its chain."],
            ["`TLS_KEY_FILE`", "`/certs/server.key`", "Its private key (`TLS_KEY_PASSPHRASE` if it has one)."],
            ["`TLS_PFX_FILE`", "`/certs/server.pfx`", "Or one .pfx file (`TLS_PFX_PASSPHRASE`)."],
          ],
        },
      ],
    },
    {
      id: "csr",
      title: "No certificate yet: a request for IT",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "On [Settings → HTTPS](/settings/https), open **No certificate yet? Ask IT with a request (CSR), or use a self-signed one**, give the names it is for and the organisation, and **Create a request**. **Download the request** and send it to IT; upload the certificate they return as above. The same place makes a self-signed certificate for those names.",
        },
      ],
    },
    {
      id: "lets-encrypt",
      title: "A free certificate from Let's Encrypt",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "For a public name that the internet reaches on port 80 (Let's Encrypt checks the name there). The server needs `BIND_ADDRESS=0.0.0.0`, and usually `PORT=443`, with `HTTP_REDIRECT_PORT=80` open to the internet.",
        },
        {
          kind: "steps",
          items: [
            "On [Settings → HTTPS](/settings/https), under **Free certificate from Let's Encrypt**, give the names and an email for expiry notices, and accept the Let's Encrypt Subscriber Agreement. **Staging** gets a test certificate browsers do not trust.",
            "**Get the certificate**: Hawk AI first tries the address itself, so a wrong DNS entry or a closed port 80 is found before asking.",
            "It renews by itself 30 days before it expires. **Renew now** and **Stop renewing** are on the same page.",
          ],
        },
        {
          kind: "p",
          text: "Or set `LETSENCRYPT_DOMAIN` and `LETSENCRYPT_EMAIL` in `deploy/.env` (setting them means you accept the Subscriber Agreement).",
        },
      ],
    },
    {
      id: "locked-out",
      title: "Locked out by HTTPS",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "A certificate no browser accepts, or HSTS, and Settings → HTTPS cannot be reached? On the server, put plain http back next to HTTPS:",
        },
        {
          kind: "code",
          lines: ["docker compose -f deploy/compose.yaml exec api python -m app.cli.https both"],
        },
        {
          kind: "list",
          items: [
            "A running server switches within 5 seconds, with no restart. HSTS is turned off with it. It is recorded in the audit log.",
            "Then open Hawk AI over http (`http://HAWK_HOST`, on `HTTP_REDIRECT_PORT`), open Settings → HTTPS and fix the certificate there.",
            "`python -m app.cli.https` alone shows the mode in use; `http` and `https` are the other choices.",
            "A browser that already saw HSTS for this name may keep refusing plain http for a while: use another browser or the https address.",
          ],
        },
      ],
    },
  ],
};
