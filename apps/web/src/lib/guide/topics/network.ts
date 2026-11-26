import type { GuideTopic } from "../types";

/** app/services/network_proxy.py, app/services/trust_store.py, Settings → Network & proxy, deploy/.env.example. */
export const network: GuideTopic = {
  slug: "network",
  title: "Network, proxy and trusted certificates",
  summary: "Reaching the internet through a company proxy, what your network team needs to allow, trusting a company root certificate, and a load balancer in front.",
  sections: [
    {
      id: "proxy",
      title: "A company web proxy",
      who: "Owners and admins",
      blocks: [
        {
          kind: "steps",
          items: [
            "Open [Settings → Network & proxy](/settings/network). Leave the proxy empty to connect directly; otherwise give its address and, if it asks for one, a user name and password.",
            "Check it: the check opens the same connection step by step and says where it stopped (the proxy, the tunnel, the certificate or the service's answer).",
            "Save, then restart the services on the server: the change takes effect when api, worker and beat start again.",
          ],
        },
        { kind: "code", lines: ["docker compose -f deploy/compose.yaml restart api worker beat"] },
        {
          kind: "list",
          items: [
            "Only basic sign-in to the proxy: Windows sign-in (NTLM, Kerberos) and SOCKS are not supported. Ask for this server to be allowed by its address, or for a user name and password.",
            "Email always goes directly to the mail server.",
            "The services of Hawk AI itself (api, web, worker, beat, proxy, postgres, redis) and this machine are always reached directly.",
            "The alternative to the page: `HTTPS_PROXY` and `NO_PROXY` in `deploy/.env` (then `sudo deploy/install.sh`). The page's setting wins.",
          ],
        },
      ],
    },
    {
      id: "allow-list",
      title: "What your network team needs to allow",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "The same page lists the addresses Hawk AI calls, worked out from this server's settings and the connectors set up. Send it to your network team before you install, or when a connection is blocked. Everything Hawk AI sends out is encrypted (HTTPS).",
        },
      ],
    },
    {
      id: "trusted-certificates",
      title: "Trusted certificates",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "Hawk AI trusts the public certificate authorities for its own connections (connectors, single sign-on, email). Two reasons a server may still be \"not trusted\":",
        },
        {
          kind: "list",
          items: [
            "The server left out an intermediate certificate. Hawk AI fetches it from the address the certificate names, and keeps it only if it leads to a root already trusted. Nothing to do; it is recorded in the audit log.",
            "A company proxy inspects HTTPS and signs with its own root. Hawk AI finds that root and shows it on [Settings → Network & proxy](/settings/network): an Owner or Admin trusts it with **Trust and connect**, or uploads it. It is never trusted without that.",
          ],
        },
        {
          kind: "p",
          text: "To get the company certificates from a Windows computer on your network, the page gives a command to paste into the command prompt; it saves `company-certificates.pem` on the desktop to upload. Trusted certificates are used at once, with no restart.",
        },
      ],
    },
    {
      id: "load-balancer",
      title: "A load balancer in front",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Behind another proxy or load balancer, set `TRUST_PROXY` in `deploy/.env` to its address or range (or `uniquelocal`, `on` or `off`) so Hawk AI believes the client address it passes on, and `PUBLIC_URL` to the address people use. Set **HTTP only** on Settings → HTTPS if the load balancer does HTTPS itself.",
        },
      ],
    },
  ],
};
