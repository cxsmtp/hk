#!/bin/sh
set -eu

usage() {
    printf '%s\n' "usage: $0 --vendor NAME --product NAME --version VERSION --test-scenario TEXT --result pass --build-evidence PATH --evidence-out PATH" >&2
}

required() {
    label=$1
    value=$2
    if [ -z "$value" ]; then
        printf '%s\n' "error: $label is required" >&2
        usage
        exit 2
    fi
}

VENDOR=""
PRODUCT=""
PRODUCT_VERSION=""
TEST_SCENARIO=""
RESULT=""
BUILD_EVIDENCE=""
EVIDENCE_OUT=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --vendor) VENDOR=${2:-}; shift 2 ;;
        --product) PRODUCT=${2:-}; shift 2 ;;
        --version) PRODUCT_VERSION=${2:-}; shift 2 ;;
        --test-scenario) TEST_SCENARIO=${2:-}; shift 2 ;;
        --result) RESULT=${2:-}; shift 2 ;;
        --build-evidence) BUILD_EVIDENCE=${2:-}; shift 2 ;;
        --evidence-out) EVIDENCE_OUT=${2:-}; shift 2 ;;
        *) printf '%s\n' "error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

required "--vendor" "$VENDOR"
required "--product" "$PRODUCT"
required "--version" "$PRODUCT_VERSION"
required "--test-scenario" "$TEST_SCENARIO"
required "--result" "$RESULT"
required "--build-evidence" "$BUILD_EVIDENCE"
required "--evidence-out" "$EVIDENCE_OUT"

if [ "$RESULT" != "pass" ]; then
    printf '%s\n' "error: coexistence evidence requires an explicit pass result" >&2
    exit 2
fi
[ -f "$BUILD_EVIDENCE" ] || { printf '%s\n' "error: --build-evidence must reference an existing file" >&2; exit 2; }
[ ! -e "$EVIDENCE_OUT" ] || { printf '%s\n' "error: evidence output already exists" >&2; exit 2; }

python3 - "$VENDOR" "$PRODUCT" "$PRODUCT_VERSION" "$TEST_SCENARIO" "$RESULT" "$BUILD_EVIDENCE" "$EVIDENCE_OUT" <<'PY'
import hashlib
import json
import os
import sys
import tempfile
from datetime import UTC, datetime

vendor, product, product_version, scenario, result, build_path, output = sys.argv[1:]


def bounded(label: str, value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise SystemExit(f"error: {label} must be a non-empty bounded single-line value")
    return value


vendor = bounded("vendor", vendor, 255)
product = bounded("product", product, 255)
product_version = bounded("version", product_version, 64)
scenario = bounded("test scenario", scenario, 512)
if result != "pass":
    raise SystemExit("error: coexistence evidence requires an explicit pass result")
if os.path.getsize(build_path) > 4096:
    raise SystemExit("error: build evidence exceeds 4096 bytes")
with open(build_path, encoding="utf-8") as stream:
    build = json.load(stream)

if set(build) != {"schema", "version", "artifact", "entitlement", "signature", "verified_at"}:
    raise SystemExit("error: build evidence has missing or unknown fields")
if build.get("schema") != "hawk.bank-macos-build-evidence" or build.get("version") != 1:
    raise SystemExit("error: unsupported build evidence")
artifact = build.get("artifact")
signature = build.get("signature")
entitlement = build.get("entitlement")
if not isinstance(artifact, dict) or set(artifact) != {"name", "sha256", "binary_version"}:
    raise SystemExit("error: build evidence lacks bounded binary version evidence")
if not isinstance(signature, dict) or set(signature) != {
    "status", "identity_type", "publisher", "team_id", "hardened_runtime"
}:
    raise SystemExit("error: build evidence lacks signed publisher evidence")
if not isinstance(entitlement, dict) or set(entitlement) != {
    "status", "source", "network_extension_type"
}:
    raise SystemExit("error: build evidence lacks signed entitlement evidence")

name = bounded("Hawk binary name", artifact.get("name"), 255)
digest = artifact.get("sha256")
if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
    raise SystemExit("error: build evidence lacks a lowercase binary SHA-256")
publisher = bounded("signed publisher", signature.get("publisher"), 255)
team_identifier = bounded("signed team identifier", signature.get("team_id"), 32)
if (
    signature.get("status") != "verified"
    or signature.get("identity_type") != "developer-id-application"
    or signature.get("hardened_runtime") is not True
    or not publisher.startswith("Developer ID Application:")
):
    raise SystemExit("error: build evidence lacks verified signed publisher evidence")
binary_version = bounded("Hawk binary version", artifact.get("binary_version"), 64)
if (
    entitlement.get("status") != "verified"
    or entitlement.get("source") != "apple-codesign"
    or entitlement.get("network_extension_type") != "transparent-proxy"
):
    raise SystemExit("error: build evidence lacks verified signed entitlement evidence")

canonical_build = json.dumps(
    build,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
).encode("utf-8")
recorded_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
evidence = {
    "schema": "hawk.edr-coexistence-evidence",
    "version": 1,
    "status": "recorded",
    "vendor": vendor,
    "product": product,
    "product_version": product_version,
    "test_scenario": scenario,
    "result": "pass",
    "certification_claimed": False,
    "hawk_binary": {
        "name": name,
        "sha256": digest,
        "signed_publisher": publisher,
        "team_identifier": team_identifier,
        "binary_version": binary_version,
        "signature_verified": True,
        "hardened_runtime": True,
    },
    "build_evidence_sha256": hashlib.sha256(canonical_build).hexdigest(),
    "recorded_at": recorded_at,
}
payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
if len(payload.encode("utf-8")) > 4096:
    raise SystemExit("error: EDR coexistence evidence exceeds 4096 bytes")

directory = os.path.dirname(os.path.abspath(output))
if not os.path.isdir(directory):
    raise SystemExit("error: evidence output directory does not exist")
fd, temporary = tempfile.mkstemp(prefix=".hawk-edr-evidence.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    if os.path.getsize(temporary) > 4096:
        raise SystemExit("error: written EDR evidence exceeds 4096 bytes")
    with open(temporary, encoding="utf-8") as stream:
        checked = json.load(stream)
    if checked != evidence or checked.get("status") != "recorded":
        raise SystemExit("error: EDR evidence self-validation failed")
    if checked.get("certification_claimed") is not False:
        raise SystemExit("error: local EDR validation cannot claim certification")
    os.replace(temporary, output)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY

printf '%s\n' "$EVIDENCE_OUT"
