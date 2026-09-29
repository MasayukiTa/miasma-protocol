#!/bin/bash
# Build a self-contained, locally signed app for the current Mac architecture.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ]; then
    echo 'This script requires macOS and Xcode Command Line Tools.' >&2
    exit 1
fi
command -v cargo >/dev/null || { echo 'Install Rust (https://rustup.rs) first.' >&2; exit 1; }
xcrun --find clang >/dev/null
cargo build --release --locked -p miasma-desktop -p miasma-cli -p miasma-bridge

APP="${MIASMA_MACOS_OUTPUT:-$PWD/dist}/Miasma.app"
BIN="${CARGO_TARGET_DIR:-$PWD/target}/release"
VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
for name in miasma-desktop miasma miasma-bridge; do
    cp "$BIN/$name" "$APP/Contents/MacOS/$name"
    chmod 755 "$APP/Contents/MacOS/$name"
done
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>miasma-desktop</string>
    <key>CFBundleIdentifier</key><string>org.miasma-protocol.desktop</string>
    <key>CFBundleName</key><string>Miasma</string>
    <key>CFBundleDisplayName</key><string>Miasma</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key><string>Miasma discovers and connects to nearby peers to store and retrieve content.</string>
</dict></plist>
EOF
plutil -lint "$APP/Contents/Info.plist"
# Finder/iCloud metadata on a newly created bundle can prevent code signing.
# Remove only these packaging attributes; preserve other extended attributes.
xattr -rd com.apple.FinderInfo "$APP" 2>/dev/null || true
xattr -rd com.apple.ResourceFork "$APP" 2>/dev/null || true
for name in miasma miasma-bridge; do
    codesign --force --sign - "$APP/Contents/MacOS/$name"
done
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
echo "Built: $APP"
echo "Launch with: open \"$APP\""
