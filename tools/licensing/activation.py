#!/usr/bin/env python3
"""Activation codes for Hawk AI (docs/activation-codes.md). For the maintainer, on their own machine.

Ported from CxMissionZero's scripts/activation.mjs; it reads the same Ed25519 private key file.

  python3 tools/licensing/activation.py keygen <private-key-file>
      Makes the Ed25519 key pair once. Keep the private key file safe and out of any repository; the printed
      public key goes into ISSUER_KEYS in apps/api/app/services/activation_service.py.

  python3 tools/licensing/activation.py issue <private-key-file> "<organisation>" <max-tenants> [months=12] [--max-users N]
      Prints a tenants activation code for one organisation: up to <max-tenants> tenants and, with --max-users,
      up to N active users in each tenant.

  python3 tools/licensing/activation.py product <private-key-file> <YYYY-MM-DD | months> ["<label>"]
      Prints the product activation code: one key for everyone who uses Hawk AI (it is not tied to a server or an
      organisation). With it, Hawk AI works until the end of that day (UTC), or for that many months, past its
      built-in end (31 January 2027). Entered on the deactivation page, or under Settings → Activation codes before
      then. The label (default "Everyone") is what the Activation codes page shows it was issued for.

  python3 tools/licensing/activation.py show <code>
      What a code says (without checking its signature).

Needs only the Python standard library and the cryptography package.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

PREFIX = "HK1"

USAGE = (
    "Usage:\n"
    "  keygen <private-key-file>\n"
    '  issue <private-key-file> "<organisation>" <max-tenants> [months] [--max-users N]\n'
    '  product <private-key-file> <YYYY-MM-DD | months> ["<label>"]\n'
    "  show <code>"
)


def usage() -> None:
    print(USAGE, file=sys.stderr)
    sys.exit(2)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def iso(moment: datetime) -> str:
    """As JavaScript's toISOString: UTC, with milliseconds."""
    moment = moment.astimezone(timezone.utc)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


def number(text: str) -> float:
    """JavaScript's Number(): NaN when it is not a number."""
    try:
        return float(str(text).strip()) if str(text).strip() else 0.0
    except ValueError:
        return math.nan


def add_months(moment: datetime, months: int) -> datetime:
    """As JavaScript's setUTCMonth(month + months): a day past the end of the month runs into the next."""
    total = moment.month - 1 + months
    first = moment.replace(year=moment.year + total // 12, month=total % 12 + 1, day=1)
    return first + timedelta(days=moment.day - 1)


def public_key_text(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode("ascii")


def load_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as handle:
        key = load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print(f"{path} is not an Ed25519 private key.", file=sys.stderr)
        sys.exit(1)
    return key


def make_code(key: Ed25519PrivateKey, payload: dict, months: str | float, until: datetime | None = None) -> tuple[str, dict]:
    """Sign a payload (expiry filled in: ``months`` from now, or ``until`` when given) into an HK1 code."""
    issued = datetime.now(timezone.utc)
    if until is not None:
        expires = until
    else:
        count = number(months)
        count = 12 if not count or math.isnan(count) else count
        expires = add_months(issued, int(max(1, count)))
    full = {"v": 1, "id": secrets.token_hex(6), "issued": iso(issued), "expires": iso(expires), **payload}
    head = f"{PREFIX}.{b64url(json.dumps(full, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))}"
    return f"{head}.{b64url(key.sign(head.encode('utf-8')))}", full


def read_code(code: str) -> dict | None:
    parts = str(code or "").strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)).decode("utf-8", errors="replace"))
    except (ValueError, binascii.Error):
        return None


def keygen(args: list[str]) -> None:
    if not args:
        usage()
    path = args[0]
    if os.path.exists(path):
        print(f"{path} already exists; not overwriting it.", file=sys.stderr)
        sys.exit(1)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    print(f"Private key written to {path} (keep it safe; never commit it).")
    print("Public key, for ISSUER_KEYS in apps/api/app/services/activation_service.py:")
    print(public_key_text(key))


def issue(args: list[str]) -> None:
    max_users = None
    rest: list[str] = []
    index = 0
    while index < len(args):
        if args[index] == "--max-users":
            if index + 1 >= len(args):
                usage()
            max_users = number(args[index + 1])
            if math.isnan(max_users) or not max_users.is_integer() or max_users < 1:
                usage()
            index += 2
            continue
        rest.append(args[index])
        index += 1
    if len(rest) < 3:
        usage()
    path, org, maximum = rest[0], rest[1], rest[2]
    months = rest[3] if len(rest) > 3 else "12"
    max_tenants = number(maximum)
    if not path or not org.strip() or math.isnan(max_tenants) or not max_tenants.is_integer() or max_tenants < 1:
        usage()
    key = load_key(path)
    payload = {"org": org.strip(), "scope": "tenants", "maxTenants": int(max_tenants)}
    if max_users is not None:
        payload["maxUsers"] = int(max_users)
    code, full = make_code(key, payload, months)
    print(code)
    users = f", up to {int(max_users)} active users in each" if max_users is not None else ""
    print(
        f"For {full['org']}: up to {int(max_tenants)} tenants{users}, until {full['expires'][:10]} (public key {public_key_text(key)[-12:]}).",
        file=sys.stderr,
    )


def product(args: list[str]) -> None:
    if len(args) < 2:
        usage()
    path, when = args[0], args[1]
    org = args[2] if len(args) > 2 else "Everyone"
    if not path or not when or not org.strip():
        usage()
    # A date: until the end of that day, UTC. A number: that many months from now.
    day = None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", when):
        try:
            day = datetime.fromisoformat(f"{when}T00:00:00+00:00") + timedelta(days=1)
        except ValueError:
            day = None
        if day is None or not day > datetime.now(timezone.utc):
            print(f"{when} is not a day in the future.", file=sys.stderr)
            sys.exit(1)
    elif not number(when) >= 1:
        usage()
    key = load_key(path)
    code, full = make_code(key, {"org": org.strip(), "scope": "product", "action": "activate"}, when, day)
    print(code)
    print(
        f"The product activation code (for {full['org']}): Hawk AI works until {full['expires'][:16].replace('T', ' ')} UTC, wherever it is entered.",
        file=sys.stderr,
    )


def show(args: list[str]) -> None:
    payload = read_code(args[0] if args else "")
    if payload is None:
        print("Not an activation code.", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main(argv: list[str]) -> None:
    if not argv:
        usage()
    command, args = argv[0], argv[1:]
    commands = {"keygen": keygen, "issue": issue, "product": product, "show": show}
    if command not in commands:
        usage()
    commands[command](args)


if __name__ == "__main__":
    main(sys.argv[1:])
