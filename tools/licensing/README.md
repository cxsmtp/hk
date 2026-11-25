# Licensing tools

`activation.py` makes Hawk AI activation codes (see [docs/activation-codes.md](../../docs/activation-codes.md)). It is
for the maintainer, on their own machine, and needs Python 3 with the `cryptography` package.

```sh
python3 tools/licensing/activation.py keygen <private-key-file>
python3 tools/licensing/activation.py issue <private-key-file> "<organisation>" <max-tenants> [months=12] [--max-users N]
python3 tools/licensing/activation.py product <private-key-file> <YYYY-MM-DD | months> ["<label>"]
python3 tools/licensing/activation.py show <code>
```

- `keygen` writes a new Ed25519 private key (PKCS#8 PEM, mode 0600) and prints the public key, base64 SPKI DER, for
  `ISSUER_KEYS` in `apps/api/app/services/activation_service.py`. It never overwrites a file. The owner's existing key
  (`issuer-key.pem`, made by CxMissionZero's `scripts/activation.mjs keygen`) is already the one built in.
- `issue` prints a tenants code: up to `<max-tenants>` tenants (at least 1) and, with `--max-users`, up to N active
  users in each tenant, for 12 months unless another number of months is given.
- `product` prints the product code for everyone: Hawk AI works until the end of that day (UTC, which must be in the
  future) or for that many months. The label (default "Everyone") is what Settings → Activation codes shows.
- `show` prints what a code says, without checking its signature.

The code goes to standard output; what it is for goes to standard error. Keep the private key out of every
repository and container.
