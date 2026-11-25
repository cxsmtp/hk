#!/bin/sh
set -eu

APP=""; RUNTIME=""; IDENTITY_HELPER=""; LAUNCH_AGENT=""; PACKAGE=""
SIGNING_IDENTITY=""; TEAM_ID=""; BUILD_EVIDENCE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --app) APP=${2:-}; shift 2;;
        --runtime) RUNTIME=${2:-}; shift 2;;
        --identity-helper) IDENTITY_HELPER=${2:-}; shift 2;;
        --launch-agent) LAUNCH_AGENT=${2:-}; shift 2;;
        --package) PACKAGE=${2:-}; shift 2;;
        --signing-identity) SIGNING_IDENTITY=${2:-}; shift 2;;
        --team-id) TEAM_ID=${2:-}; shift 2;;
        --build-evidence) BUILD_EVIDENCE=${2:-}; shift 2;;
        *) printf '%s\n' "error: unknown argument: $1" >&2; exit 2;;
    esac
done

for value in "$APP" "$RUNTIME" "$IDENTITY_HELPER" "$LAUNCH_AGENT" "$PACKAGE" "$TEAM_ID" "$BUILD_EVIDENCE"; do
    [ -n "$value" ] || { printf '%s\n' 'error: required package input is missing' >&2; exit 2; }
done
case "$SIGNING_IDENTITY" in "Developer ID Installer: "*) ;; *) exit 2;; esac
[ "$(uname -s)" = "Darwin" ] || exit 2
[ -d "$APP" ] && [ -d "$RUNTIME" ] && [ -f "$IDENTITY_HELPER" ] &&
    [ -f "$LAUNCH_AGENT" ] && [ -f "$BUILD_EVIDENCE" ] && [ ! -e "$PACKAGE" ] || exit 2
for tool in codesign pkgbuild productbuild pkgutil plutil ditto security; do
    command -v "$tool" >/dev/null 2>&1 || exit 2
done

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hawk-managed-pkg.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
python3 - "$APP" "$RUNTIME" "$IDENTITY_HELPER" "$LAUNCH_AGENT" "$BUILD_EVIDENCE" "$TEAM_ID" <<'PY'
import hashlib, json, pathlib, plistlib, re, subprocess, sys
app, runtime, helper, agent, evidence, team = map(pathlib.Path, sys.argv[1:6])
team = sys.argv[6]
build = json.loads(evidence.read_text(encoding="utf-8"))
if build.get("schema") != "hawk.bank-macos-build-evidence" or build.get("signature", {}).get("team_id") != team:
    raise SystemExit("error: build evidence team does not match")
info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
if info.get("CFBundleIdentifier") != "ai.hawk.endpoint.host":
    raise SystemExit("error: host bundle identifier is invalid")
expected_ids = {
    "ai.hawk.endpoint.host", "ai.hawk.endpoint.endpoint-security",
    "ai.hawk.endpoint.content-filter", "ai.hawk.endpoint.managed-routing",
}
records = build.get("components")
if not isinstance(records, list) or len(records) != 4 or {row.get("bundle_id") for row in records} != expected_ids:
    raise SystemExit("error: build evidence component set is invalid")
components = {"ai.hawk.endpoint.host": app}
for extension in (app / "Contents/Library/SystemExtensions").glob("*.systemextension"):
    identity = plistlib.loads((extension / "Contents/Info.plist").read_bytes()).get("CFBundleIdentifier")
    if identity not in expected_ids or identity in components:
        raise SystemExit("error: embedded extension identity is invalid")
    components[identity] = extension
if set(components) != expected_ids:
    raise SystemExit("error: exact embedded extension set is required")
for record in records:
    identifier = record["bundle_id"]
    bundle = components[identifier]
    metadata = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    executable = bundle / "Contents/MacOS" / metadata.get("CFBundleExecutable", "")
    if (not executable.is_file() or
            metadata.get("CFBundleShortVersionString") != record.get("version") or
            metadata.get("CFBundleVersion") != record.get("bundle_version") or
            hashlib.sha256(executable.read_bytes()).hexdigest() != record.get("sha256")):
        raise SystemExit("error: packaged component differs from build evidence")
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(bundle)],
                              capture_output=True, check=False, timeout=20)
    if verified.returncode:
        raise SystemExit("error: packaged component signature does not verify")
    detail = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=4", str(bundle)],
                            capture_output=True, check=False, timeout=20)
    rendered = (detail.stdout + detail.stderr).decode("utf-8", errors="replace")
    if (detail.returncode or f"Identifier={identifier}" not in rendered or
            f"TeamIdentifier={team}" not in rendered or
            not re.search(r"flags=.*\(runtime\)", rendered)):
        raise SystemExit("error: packaged component signature is invalid")
    entitlement_result = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", "-", str(bundle)],
                                        capture_output=True, check=False, timeout=20)
    if entitlement_result.returncode:
        raise SystemExit("error: packaged component entitlement is unreadable")
    entitlements = plistlib.loads(entitlement_result.stdout)
    entitlement = record.get("entitlement")
    required = {
        "ai.hawk.endpoint.host": ("com.apple.developer.system-extension.install", True),
        "ai.hawk.endpoint.endpoint-security": ("com.apple.developer.endpoint-security.client", True),
        "ai.hawk.endpoint.content-filter": ("com.apple.developer.networking.networkextension", "content-filter-provider-systemextension"),
        "ai.hawk.endpoint.managed-routing": ("com.apple.developer.networking.networkextension", "transparent-proxy-provider"),
    }[identifier]
    actual = entitlements.get(required[0])
    if entitlement != required[0] or (required[1] is True and actual is not True) or (
            required[1] is not True and (not isinstance(actual, list) or required[1] not in actual)):
        raise SystemExit("error: packaged component entitlement mismatch")
    profile = bundle / "Contents/embedded.provisionprofile"
    if not profile.is_file():
        raise SystemExit("error: packaged component profile is missing")
    verified_profile = subprocess.run(["/usr/bin/security", "cms", "-D", "-i", str(profile)],
                                      capture_output=True, check=False, timeout=20)
    if verified_profile.returncode or team not in plistlib.loads(verified_profile.stdout).get("TeamIdentifier", []):
        raise SystemExit("error: packaged component profile Team ID is invalid")
launch = plistlib.loads(agent.read_bytes())
if launch.get("EnvironmentVariables", {}).get("HAWK_AGENT_CONFIG") != "/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json":
    raise SystemExit("error: LaunchAgent requires the fixed protected agent config")
args = launch.get("ProgramArguments")
if not isinstance(args, list) or not args or not str(args[0]).startswith(
    "/Library/Application Support/Hawk/EndpointAgent/runtime/") or any(
    "activate-managed-extensions" in str(value) or "apply-managed-policy" in str(value)
    for value in args
):
    raise SystemExit("error: LaunchAgent may not activate the native floor")
for path in (runtime, helper):
    if path.is_symlink():
        raise SystemExit("error: signed runtime paths cannot be symlinks")
PY

for signed in "$APP" "$RUNTIME" "$IDENTITY_HELPER"; do
    codesign --verify --strict "$signed"
    details=$(codesign -dv --verbose=4 "$signed" 2>&1)
    printf '%s\n' "$details" | grep -Fq "TeamIdentifier=$TEAM_ID" || exit 1
    printf '%s\n' "$details" | grep -Eq 'flags=.*\(runtime\)' || exit 1
done

mkdir -p "$TEMP_DIR/stage/Applications" \
    "$TEMP_DIR/stage/Library/Application Support/Hawk/EndpointAgent/bin" \
    "$TEMP_DIR/stage/Library/LaunchAgents"
ditto "$APP" "$TEMP_DIR/stage/Applications/Hawk Endpoint.app"
ditto "$RUNTIME" "$TEMP_DIR/stage/Library/Application Support/Hawk/EndpointAgent/runtime"
ditto "$IDENTITY_HELPER" "$TEMP_DIR/stage/Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity"
install -m 0644 "$LAUNCH_AGENT" "$TEMP_DIR/stage/Library/LaunchAgents/ai.hawk.endpoint-agent.plist"
printf '%s\n' '{"schema":"hawk.macos-managed-defaults","version":1,"mode":"monitor","activation":"explicit-mdm"}' >"$TEMP_DIR/stage/Library/Application Support/Hawk/EndpointAgent/managed-defaults.json"
chmod 0644 "$TEMP_DIR/stage/Library/Application Support/Hawk/EndpointAgent/managed-defaults.json"
pkgbuild --root "$TEMP_DIR/stage" --identifier ai.hawk.endpoint.agent \
    --version "$(plutil -extract CFBundleShortVersionString raw -o - "$APP/Contents/Info.plist")" \
    --ownership recommended "$TEMP_DIR/component.pkg"
productbuild --package "$TEMP_DIR/component.pkg" --sign "$SIGNING_IDENTITY" "$PACKAGE"
pkgutil --check-signature "$PACKAGE"
printf '%s\n' "$PACKAGE"
