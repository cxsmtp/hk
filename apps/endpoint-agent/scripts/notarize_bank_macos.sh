#!/bin/sh
set -eu
ARTIFACT=""; STAPLE_TARGET=""; BUILD_EVIDENCE=""; KEYCHAIN_PROFILE=""; EVIDENCE_OUT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --artifact) ARTIFACT=${2:-}; shift 2;;
        --staple-target) STAPLE_TARGET=${2:-}; shift 2;;
        --build-evidence) BUILD_EVIDENCE=${2:-}; shift 2;;
        --keychain-profile) KEYCHAIN_PROFILE=${2:-}; shift 2;;
        --evidence-out) EVIDENCE_OUT=${2:-}; shift 2;;
        *) printf '%s\n' "error: unknown notarization argument: $1" >&2; exit 2;;
    esac
done
for value in "$ARTIFACT" "$STAPLE_TARGET" "$BUILD_EVIDENCE" "$KEYCHAIN_PROFILE" "$EVIDENCE_OUT"; do
    [ -n "$value" ] || { printf '%s\n' 'error: required notarization input is missing' >&2; exit 2; }
done
case "$ARTIFACT" in *.pkg) ;; *) exit 2;; esac
[ "$(uname -s)" = "Darwin" ] || exit 2
[ -f "$ARTIFACT" ] && [ -f "$BUILD_EVIDENCE" ] && [ ! -e "$EVIDENCE_OUT" ] || exit 2
[ "$(realpath "$ARTIFACT")" = "$(realpath "$STAPLE_TARGET")" ] || {
    printf '%s\n' 'error: staple target must be the exact submitted .pkg' >&2; exit 2;
}

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hawk-bank-notary.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
python3 - "$BUILD_EVIDENCE" "$ARTIFACT" "$TEMP_DIR/binding.json" <<'PY'
import hashlib, json, pathlib, sys
build = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if build.get("schema") != "hawk.bank-macos-build-evidence" or build.get("version") != 2:
    raise SystemExit("error: unsupported build evidence")
components = build.get("components")
if not isinstance(components, list) or len(components) != 4:
    raise SystemExit("error: component evidence is incomplete")
if not isinstance(build.get("component_set_digest"), str) or len(build["component_set_digest"]) != 64:
    raise SystemExit("error: component-set digest is missing")
team = build.get("signature", {}).get("team_id")
if not isinstance(team, str) or len(team) != 10:
    raise SystemExit("error: build Team ID is invalid")
def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
binding = {
    "team_id": team,
    "build_evidence_sha256": digest(build),
    "component_evidence_sha256": digest(components),
    "submitted_package_sha256": hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest(),
}
pathlib.Path(sys.argv[3]).write_text(json.dumps(binding, sort_keys=True), encoding="utf-8")
PY

pkgutil --check-signature "$ARTIFACT" >"$TEMP_DIR/pkg-signature.txt"
python3 - "$TEMP_DIR/pkg-signature.txt" "$TEMP_DIR/binding.json" <<'PY'
import json, pathlib, sys
details = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
team = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))["team_id"]
if "Developer ID Installer" not in details or team not in details:
    raise SystemExit("error: package installer signature Team ID mismatch")
PY
pkgutil --expand "$ARTIFACT" "$TEMP_DIR/expanded"
python3 - "$TEMP_DIR/expanded" <<'PY'
import pathlib, sys
if any(path.name == "Scripts" for path in pathlib.Path(sys.argv[1]).rglob("Scripts")):
    raise SystemExit("error: installer scripts are forbidden")
PY
pkgutil --payload-files "$ARTIFACT" >"$TEMP_DIR/payload-files.txt"
python3 - "$TEMP_DIR/payload-files.txt" <<'PY'
import pathlib, sys
paths = [line.strip().removeprefix("./") for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
if not paths or any(path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts for path in paths):
    raise SystemExit("error: unsafe package payload")
if any("endpoint-floor-policy.bin" in path or "ai.hawk.endpoint.host.plist" in path for path in paths):
    raise SystemExit("error: package embeds policy or managed config")
allowed = (
    "Applications/Hawk Endpoint.app", "Library/Application Support/Hawk/EndpointAgent/runtime",
    "Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity",
    "Library/Application Support/Hawk/EndpointAgent/managed-defaults.json",
    "Library/LaunchAgents/ai.hawk.endpoint-agent.plist",
)
parents = {str(parent) for path in allowed for parent in pathlib.PurePosixPath(path).parents}
if any(not any(path == root or path.startswith(root + "/") for root in allowed)
       and path not in parents for path in paths):
    raise SystemExit("error: unexpected package payload")
PY

xcrun notarytool submit "$ARTIFACT" --keychain-profile "$KEYCHAIN_PROFILE" \
    --wait --output-format json >"$TEMP_DIR/notary-response.json"
python3 - "$TEMP_DIR/notary-response.json" <<'PY'
import json, pathlib, sys
response = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if response.get("status") != "Accepted" or not isinstance(response.get("id"), str) or not response["id"]:
    raise SystemExit("error: Apple did not accept the exact package")
PY
xcrun stapler staple "$ARTIFACT"
xcrun stapler validate "$ARTIFACT"
pkgutil --check-signature "$ARTIFACT" >/dev/null

python3 - "$EVIDENCE_OUT" "$ARTIFACT" "$TEMP_DIR/binding.json" "$TEMP_DIR/notary-response.json" <<'PY'
import datetime, hashlib, json, os, pathlib, sys, tempfile
output = pathlib.Path(sys.argv[1])
package = pathlib.Path(sys.argv[2])
binding = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
response = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
evidence = {
    "schema": "hawk.bank-macos-notarization-evidence", "version": 2,
    **binding,
    "stapled_package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
    "status": "accepted", "submission_id": response["id"],
    "staple_status": "valid",
    "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
}
encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("ascii")
if len(encoded) > 8192:
    raise SystemExit("error: notary evidence is oversized")
with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".hawk-notary-", delete=False) as temporary:
    temporary.write(encoded + b"\n")
    temporary.flush()
    os.fsync(temporary.fileno())
    temporary_name = temporary.name
os.replace(temporary_name, output)
print(output)
PY
