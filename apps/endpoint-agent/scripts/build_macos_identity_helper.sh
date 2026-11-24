#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AGENT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE="$AGENT_DIR/native/macos/HawkDeviceIdentity.swift"
BUILD_DIR="$AGENT_DIR/build"
OUTPUT="$BUILD_DIR/hawk-device-identity"
TEMP_OUTPUT="$BUILD_DIR/hawk-device-identity.building"
MODULE_CACHE="$BUILD_DIR/swift-module-cache"

mkdir -p "$BUILD_DIR" "$MODULE_CACHE"
if [ -n "${HAWK_MACOS_SDK:-}" ]; then
  SDK="$HAWK_MACOS_SDK"
elif [ -d "/Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk" ]; then
  SDK="/Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk"
else
  SDK=$(xcrun --show-sdk-path)
fi

CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" \
SWIFT_MODULECACHE_PATH="$MODULE_CACHE" \
xcrun swiftc -sdk "$SDK" -O -framework Security "$SOURCE" -o "$TEMP_OUTPUT"
/usr/bin/codesign --force --sign - --timestamp=none "$TEMP_OUTPUT"
mv "$TEMP_OUTPUT" "$OUTPUT"
chmod 755 "$OUTPUT"

printf '%s\n' "$OUTPUT"
