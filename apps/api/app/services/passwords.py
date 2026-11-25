"""Generated passwords and the password rule, ported from CxMissionZero's src/iam.js (generatePassword,
passwordProblem)."""

from __future__ import annotations

import secrets

#: Letters and digits that cannot be mistaken for one another (no I, O, l, o, 0 or 1): CxMissionZero's alphabet.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
MIN_PASSWORD_LENGTH = 12
#: CxMissionZero allows 256 characters (scrypt). Hawk hashes with bcrypt, which reads only the first 72 bytes, so a
#: longer password is refused rather than silently shortened.
MAX_PASSWORD_LENGTH = 72


def generate_password() -> str:
    """4 groups of 5 characters from the unambiguous alphabet, e.g. ``Hq7Tz-mWb3K-p9XcR-a4NfE``."""

    chars = "".join(secrets.choice(ALPHABET) for _ in range(20))
    return "-".join(chars[i : i + 5] for i in range(0, 20, 5))


def password_problem(password: str) -> str:
    """What is wrong with a password someone chose, or "" if nothing."""

    text = str(password or "")
    if len(text) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if len(text.encode("utf-8")) > MAX_PASSWORD_LENGTH:
        return "That password is too long."
    if len(set(text)) < 5:
        return "That password is too repetitive."
    return ""
