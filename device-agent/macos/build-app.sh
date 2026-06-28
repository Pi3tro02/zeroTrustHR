#!/usr/bin/env bash
set -euo pipefail

SIGNING_IDENTITY="${1:-}"

if [[ -z "$SIGNING_IDENTITY" ]]; then
  echo "Uso: ./build-app.sh \"Apple Development: name@example.com (TEAMID)\"" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="/tmp/ZeroTrustHRDeviceAgent.app"
MACOS_PATH="$APP_PATH/Contents/MacOS"

rm -rf "$APP_PATH"
mkdir -p "$MACOS_PATH"
cp "$ROOT_DIR/ZeroTrustHRDeviceAgent-Info.plist" "$APP_PATH/Contents/Info.plist"

CLANG_MODULE_CACHE_PATH=/tmp/zerotrusthr-swift-module-cache swiftc \
  "$ROOT_DIR/SecureEnclaveIdentity.swift" \
  "$ROOT_DIR/EnrollmentOutput.swift" \
  "$ROOT_DIR/main.swift" \
  -o "$MACOS_PATH/ZeroTrustHRDeviceAgent"

codesign --force --options runtime \
  --entitlements "$ROOT_DIR/ZeroTrustHRDeviceAgent.entitlements" \
  --sign "$SIGNING_IDENTITY" \
  "$APP_PATH"

codesign --verify --deep --strict --verbose=2 "$APP_PATH"

echo "$APP_PATH"
