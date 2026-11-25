# Network and proxy

How Hawk AI reaches the services its connectors use, and what your network team needs to allow. Everything it sends is encrypted (HTTPS, TLS 1.2 or later). Ported from CxMissionZero's docs/network.md; the page is **Settings → Network & proxy** (`/settings/network`), for owners and admins, and applies to the whole installation.

## Directly, or through your company's proxy

By default Hawk AI connects directly. When your network lets outgoing web traffic out only through a proxy, set it on the page:

| Field | Meaning |
| --- | --- |
| **Proxy server** | The proxy, as `host:port`, for example `proxy.acme.local:8080` (`http://` is assumed; `https://` works too). A SOCKS proxy is not supported. |
| **User name, if the proxy asks for one** / **Password** | For a proxy that asks for a user name and password (basic authentication). The password is kept on the server (`network.json` in the data folder, readable by the server only) and never shown again; leave it blank to keep the saved one. |
| **Hosts that skip the proxy** | Names or addresses reached directly, separated by commas: `.acme.local` (the domain and everything under it), `smtp.acme.local`, `10.0.0.5`. This machine and the other containers of the stack are always reached directly. |
| **Service address to check** | Filled in from the connectors set up. Before that, type the address of a service a connector will read, for example `graph.microsoft.com`. |

**Check the connection** tries the way to the service with what is typed, before anything is saved, and says where it stops:

| Step | ✓ | ✕, and what to do |
| --- | --- | --- |
| **Proxy** | The proxy answered | The address or port is wrong, or the proxy is not reachable from the server: check them with your network team |
| **Connection** | The proxy opened a connection to the service | **407**: the proxy wants a sign-in (a user name and password, or allow the server by its IP address). **403**: the proxy does not allow the host (ask for it on port 443) |
| **Certificate** | The service's certificate is trusted | Usually a proxy that inspects HTTPS: the page shows the certificate it presents; select **Trust and connect** (below), or ask for an exception from inspection |
| **Service** | The service answered | — |

With the proxy empty, the same check tries the direct connection.

**Save** checks again and saves the proxy only if it lets the service through (a proxy that cannot be reached, or refuses the service, is not saved: it would only stop what works). **Stop using the proxy** goes back to direct connections. Both are in the audit log.

### When a change takes effect

CxMissionZero restarts itself after a change. Hawk AI runs as several containers (api, worker, beat), each of which reads the proxy when it starts, so a saved or removed proxy is used from their next start:

```
docker compose -f deploy/compose.yaml restart api worker beat
```

People stay signed in. Until then the page says the proxy is saved and not yet in use. Trusted certificates (below) need no restart.

### With environment variables instead

The usual `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` variables work too, set on the api, worker and beat containers. A proxy saved under Settings takes precedence over them.

Windows-integrated sign-in to the proxy (NTLM / Kerberos) is not supported: a server process cannot use it. Ask for the server to be allowed by its IP address, or for a user name and password for it.

**Through the proxy:** every connector, single sign-on, Let's Encrypt (everything the server reaches over HTTPS). **Directly:** the email server, which speaks SMTP rather than web traffic, and the hosts that skip the proxy.

## A proxy that inspects HTTPS

A company proxy that inspects HTTPS signs every site with its own root certificate, which Hawk AI does not trust. When the check stops at **Certificate**, the page shows the certificate presented (its name, the product such as Zscaler or Netskope, and its fingerprint):

- **Trust and connect** trusts that root, after looking it up again on the server (only what was shown can be trusted), and keeps it only if the service is then trusted. It applies at once, to every connector, single sign-on and email, with no restart.
- **Upload a certificate…** takes your company's root (.pem, .crt or .cer). Uploaded where a connection failed, only the certificates that complete that connection are kept, so a whole exported Windows store can be given as it is (the page has the one-line command that exports it).
- A server that left out its intermediate certificate is completed from the address its certificate names (its "CA Issuers" link), only when a public root vouches for it; that is audited and asks nothing.

The list, with who added each certificate and when, is under **Trusted certificates** on the same page; **Remove** takes one out. Issuer links are never followed to a link-local or cloud metadata address, nor to the server itself.

Python reads only the server's own certificate of what a server presents; the rest of the chain comes from its "CA Issuers" links or from an upload.

## What your network team needs to allow

The page lists every connection the server makes or takes, worked out from its own settings: the services of the connectors set up, the email server, the identity provider, Let's Encrypt when it is used, and the port people's browsers use, then every service a connector can call ("Only if you connect it"). **Copy for your network team** and **Download (.txt)** give it as text for a ticket or an email.

## Outbound addresses

Every address Hawk AI calls out to is https (plain http only to this machine, for a test double), never carries a user name or password, and is never a link-local or cloud metadata address (169.254.169.254, metadata.google.internal, 100.100.100.200, 168.63.129.16, fd00:ec2::254 and the like): `app/services/outbound_url.py`. The connectors' credentialed calls also keep their allowlist per connector and, when direct, pin the connection to the public address the name resolved to (`app/services/outbound_destination_policy.py`); through a proxy, the proxy resolves the name.
