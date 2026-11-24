#!/bin/sh
set -eu

PROJECT=""; SCHEME=""; ARCHIVE_PATH=""; APP_PATH=""; SIGNING_IDENTITY=""
TEAM_ID=""; EVIDENCE_OUT=""; HOST_PROFILE=""; ENDPOINT_PROFILE=""
FILTER_PROFILE=""; ROUTING_PROFILE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --project) PROJECT=${2:-}; shift 2;;
        --scheme) SCHEME=${2:-}; shift 2;;
        --archive-path) ARCHIVE_PATH=${2:-}; shift 2;;
        --app) APP_PATH=${2:-}; shift 2;;
        --signing-identity) SIGNING_IDENTITY=${2:-}; shift 2;;
        --team-id) TEAM_ID=${2:-}; shift 2;;
        --host-profile) HOST_PROFILE=${2:-}; shift 2;;
        --endpoint-profile) ENDPOINT_PROFILE=${2:-}; shift 2;;
        --filter-profile) FILTER_PROFILE=${2:-}; shift 2;;
        --routing-profile) ROUTING_PROFILE=${2:-}; shift 2;;
        --evidence-out) EVIDENCE_OUT=${2:-}; shift 2;;
        *) printf '%s\n' "error: unknown build argument: $1" >&2; exit 2;;
    esac
done
for value in "$PROJECT" "$SCHEME" "$ARCHIVE_PATH" "$APP_PATH" "$TEAM_ID" \
             "$EVIDENCE_OUT" "$HOST_PROFILE" "$ENDPOINT_PROFILE" \
             "$FILTER_PROFILE" "$ROUTING_PROFILE"; do
    [ -n "$value" ] || { printf '%s\n' 'error: required per-target build input is missing' >&2; exit 2; }
done
case "$SIGNING_IDENTITY" in "Developer ID Application: "*) ;; *) exit 2;; esac
[ "$(uname -s)" = "Darwin" ] || exit 2
[ -e "$PROJECT" ] && [ ! -e "$EVIDENCE_OUT" ] || exit 2
for tool in xcodebuild codesign security; do command -v "$tool" >/dev/null 2>&1 || exit 2; done

xcodebuild archive -project "$PROJECT" -scheme "$SCHEME" \
    -configuration Release -archivePath "$ARCHIVE_PATH" \
    CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$SIGNING_IDENTITY" \
    DEVELOPMENT_TEAM="$TEAM_ID" HAWK_APPLE_TEAM_ID="$TEAM_ID" \
    HAWK_HOST_PROVISIONING_PROFILE="$HOST_PROFILE" \
    HAWK_ENDPOINT_SECURITY_PROVISIONING_PROFILE="$ENDPOINT_PROFILE" \
    HAWK_CONTENT_FILTER_PROVISIONING_PROFILE="$FILTER_PROFILE" \
    HAWK_ROUTING_PROVISIONING_PROFILE="$ROUTING_PROFILE" \
    ENABLE_HARDENED_RUNTIME=YES

python3 - "$ARCHIVE_PATH" "$APP_PATH" "$SIGNING_IDENTITY" "$TEAM_ID" \
    "$HOST_PROFILE" "$ENDPOINT_PROFILE" "$FILTER_PROFILE" "$ROUTING_PROFILE" \
    "$EVIDENCE_OUT" <<'PY'
import datetime, hashlib, json, os, pathlib, plistlib, re, subprocess, sys, tempfile

archive, app = map(pathlib.Path, sys.argv[1:3])
publisher, team = sys.argv[3:5]
expected_profiles = dict(zip((
    "ai.hawk.endpoint.host", "ai.hawk.endpoint.endpoint-security",
    "ai.hawk.endpoint.content-filter", "ai.hawk.endpoint.managed-routing",
), sys.argv[5:9]))
output = pathlib.Path(sys.argv[9])
if app.resolve().parent != (archive.resolve() / "Products/Applications"):
    raise SystemExit("error: built app is outside the requested archive")
extension_root = app / "Contents/Library/SystemExtensions"
if not app.is_dir() or not extension_root.is_dir():
    raise SystemExit("error: host or embedded extensions are absent")

def run(args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=20)
    if result.returncode:
        raise SystemExit("error: component verification failed")
    return result.stdout if result.stdout else result.stderr

components = {"ai.hawk.endpoint.host": app}
for extension in extension_root.glob("*.systemextension"):
    try:
        info = plistlib.loads((extension / "Contents/Info.plist").read_bytes())
    except (OSError, ValueError) as exc:
        raise SystemExit("error: extension Info.plist is invalid") from exc
    identifier = info.get("CFBundleIdentifier")
    if identifier not in expected_profiles or identifier in components:
        raise SystemExit("error: unexpected or duplicate extension bundle ID")
    components[identifier] = extension
if set(components) != set(expected_profiles):
    raise SystemExit("error: exact three-extension set is required")

required_entitlements = {
    "ai.hawk.endpoint.host": ("com.apple.developer.system-extension.install", True),
    "ai.hawk.endpoint.endpoint-security": ("com.apple.developer.endpoint-security.client", True),
    "ai.hawk.endpoint.content-filter": ("com.apple.developer.networking.networkextension", "content-filter-provider-systemextension"),
    "ai.hawk.endpoint.managed-routing": ("com.apple.developer.networking.networkextension", "transparent-proxy-provider"),
}
records = []
host_version = None
for identifier, bundle in components.items():
    info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    executable = bundle / "Contents/MacOS" / info.get("CFBundleExecutable", "")
    if info.get("CFBundleIdentifier") != identifier or not executable.is_file():
        raise SystemExit("error: component bundle or executable is invalid")
    version = info.get("CFBundleShortVersionString")
    bundle_version = info.get("CFBundleVersion")
    if not isinstance(version, str) or not version or not isinstance(bundle_version, str) or not bundle_version:
        raise SystemExit("error: component version is invalid")
    if identifier == "ai.hawk.endpoint.host":
        host_version = version
    elif version != host_version:
        raise SystemExit("error: extension version differs from host")
    run(["/usr/bin/codesign", "--verify", "--strict", str(bundle)])
    detail = run(["/usr/bin/codesign", "-dv", "--verbose=4", str(bundle)]).decode("utf-8", errors="replace")
    if (f"Identifier={identifier}" not in detail or f"TeamIdentifier={team}" not in detail or
        f"Authority={publisher}" not in detail or not re.search(r"flags=.*\(runtime\)", detail)):
        raise SystemExit("error: component signature identity or hardened runtime is invalid")
    entitlements = plistlib.loads(run(["/usr/bin/codesign", "-d", "--entitlements", "-", str(bundle)]))
    key, requirement = required_entitlements[identifier]
    actual = entitlements.get(key)
    if ((requirement is True and actual is not True) or
        (requirement is not True and (not isinstance(actual, list) or requirement not in actual))):
        raise SystemExit("error: component entitlement is missing")
    profile_path = bundle / "Contents/embedded.provisionprofile"
    if not profile_path.is_file():
        raise SystemExit("error: component provisioning profile is missing")
    profile = plistlib.loads(run(["/usr/bin/security", "cms", "-D", "-i", str(profile_path)]))
    if team not in profile.get("TeamIdentifier", []) or profile.get("Name") != expected_profiles[identifier]:
        raise SystemExit("error: component provisioning profile identity is invalid")
    records.append({
        "bundle_id": identifier, "version": version, "bundle_version": bundle_version,
        "team_id": team, "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "entitlement": key, "provisioning_profile": profile["Name"],
        "hardened_runtime": True,
    })

digest_records = [{key: row[key] for key in
    ("bundle_id", "version", "bundle_version", "sha256")}
    for row in records]
component_set_digest = hashlib.sha256(
    b"hawk.macos-component-set.v1\0" +
    json.dumps(sorted(digest_records, key=lambda row: row["bundle_id"]),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
).hexdigest()
artifact = {
    "schema": "hawk.bank-macos-build-evidence", "version": 2,
    "artifact": {
        "name": app.name, "sha256": next(row["sha256"] for row in records if row["bundle_id"] == "ai.hawk.endpoint.host"),
        "binary_version": host_version,
    },
    "signature": {"team_id": team, "publisher": publisher, "hardened_runtime": True},
    "components": sorted(records, key=lambda row: row["bundle_id"]),
    "component_set_digest": component_set_digest,
    "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
}
payload = json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
if len(payload) > 16 * 1024:
    raise SystemExit("error: build evidence is oversized")
with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".hawk-build-", delete=False) as temporary:
    temporary.write(payload + b"\n")
    temporary.flush()
    os.fsync(temporary.fileno())
    temporary_name = temporary.name
os.replace(temporary_name, output)
print(output)
PY
