#!/bin/bash
# build-android.sh — Build Miasma Android APK from source
#
# Prerequisites (install once):
#   1. Android SDK with API 34: sdkmanager "platforms;android-34" "build-tools;34.0.0"
#   2. Android NDK:             sdkmanager "ndk;27.0.12077973"
#   3. Rust Android targets:    rustup target add aarch64-linux-android x86_64-linux-android
#   4. cargo-ndk:               cargo install cargo-ndk
#
# Usage:
#   ./scripts/build-android.sh              # Build debug APK
#   ./scripts/build-android.sh --release    # Build release APK
#   ./scripts/build-android.sh --setup      # Install all prerequisites
#
# Environment variables:
#   ANDROID_HOME    — Android SDK root (default: ~/Android/Sdk)
#   ANDROID_NDK_HOME — NDK root (auto-detected from SDK if unset)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILD_TYPE="debug"
SETUP_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --release) BUILD_TYPE="release" ;;
        --setup)   SETUP_ONLY=true ;;
    esac
done

# ── Default paths ────────────────────────────────────────────────────────────
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    # Auto-detect NDK from SDK
    NDK_DIR=$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1 || true)
    if [ -n "$NDK_DIR" ]; then
        export ANDROID_NDK_HOME="$NDK_DIR"
    fi
fi

# ── Setup mode ───────────────────────────────────────────────────────────────
if [ "$SETUP_ONLY" = true ]; then
    echo "=== Setting up Android build prerequisites ==="
    echo ""

    # 1. Android SDK
    if [ ! -f "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
        echo "Install Android command-line tools first:"
        echo "  https://developer.android.com/studio#command-line-tools-only"
        echo "  Extract to: $ANDROID_HOME/cmdline-tools/latest/"
        exit 1
    fi

    SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
    echo "Installing SDK components..."
    yes | "$SDKMANAGER" --licenses 2>/dev/null || true
    "$SDKMANAGER" "platforms;android-34" "build-tools;34.0.0" "platform-tools" "ndk;27.0.12077973"

    # 2. Rust targets
    echo ""
    echo "Installing Rust Android targets..."
    rustup target add aarch64-linux-android x86_64-linux-android

    # 3. cargo-ndk
    echo ""
    echo "Installing cargo-ndk..."
    cargo install cargo-ndk

    echo ""
    echo "=== Setup complete ==="
    exit 0
fi

# ── Verify prerequisites ────────────────────────────────────────────────────
echo "=== Miasma Android Build ==="
echo "  Build type:    $BUILD_TYPE"
echo "  ANDROID_HOME:  $ANDROID_HOME"
echo "  NDK:           ${ANDROID_NDK_HOME:-not set}"
echo ""

ERRORS=0
check() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: $1 not found. $2"
        ERRORS=$((ERRORS + 1))
    fi
}

check "cargo" "Install Rust: https://rustup.rs"
check "cargo-ndk" "Install: cargo install cargo-ndk"
check "java" "Install JDK 17+: apt install openjdk-17-jdk"

if ! rustup target list --installed | grep -q "aarch64-linux-android"; then
    echo "ERROR: Rust target aarch64-linux-android not installed."
    echo "  Run: rustup target add aarch64-linux-android x86_64-linux-android"
    ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "Fix the above errors or run: ./scripts/build-android.sh --setup"
    exit 1
fi

# ── Step 1: Build Rust FFI for Android targets ───────────────────────────────
echo "=== Step 1: Building miasma-ffi for Android ==="

CARGO_NDK_FLAGS=""
if [ "$BUILD_TYPE" = "release" ]; then
    CARGO_NDK_FLAGS="--release"
fi

JNI_LIBS="$PROJECT_DIR/android/app/src/main/jniLibs"
mkdir -p "$JNI_LIBS"

cargo ndk \
    -t arm64-v8a \
    -t x86_64 \
    -o "$JNI_LIBS" \
    build $CARGO_NDK_FLAGS -p miasma-ffi

echo "  JNI libs:"
find "$JNI_LIBS" -name "*.so" -exec echo "    {}" \;

# ── Step 2: Generate UniFFI Kotlin bindings ──────────────────────────────────
echo ""
echo "=== Step 2: Generating UniFFI Kotlin bindings ==="

# Find the compiled library (prefer release if available)
if [ "$BUILD_TYPE" = "release" ]; then
    LIB_PATH="$PROJECT_DIR/target/aarch64-linux-android/release/libmiasma_ffi.so"
else
    LIB_PATH="$PROJECT_DIR/target/aarch64-linux-android/debug/libmiasma_ffi.so"
fi

if [ ! -f "$LIB_PATH" ]; then
    # Fallback: try to find from host target for bindgen
    LIB_PATH=$(find "$PROJECT_DIR/target" -name "libmiasma_ffi.so" -path "*/aarch64*" | head -1)
fi

KOTLIN_OUT="$PROJECT_DIR/android/app/src/main/kotlin/dev/miasma/uniffi"
mkdir -p "$KOTLIN_OUT"

# Generate Kotlin bindings from the compiled library
uniffi-bindgen generate \
    --library "$LIB_PATH" \
    --language kotlin \
    --out-dir "$KOTLIN_OUT"

echo "  Kotlin bindings: $KOTLIN_OUT"
ls -la "$KOTLIN_OUT"/*.kt 2>/dev/null || echo "  (no .kt files generated)"

# ── Step 3: Build Android APK ────────────────────────────────────────────────
echo ""
echo "=== Step 3: Building Android APK ==="

cd "$PROJECT_DIR/android"

GRADLE_TASK="assembleDebug"
APK_DIR="app/build/outputs/apk/debug"
if [ "$BUILD_TYPE" = "release" ]; then
    GRADLE_TASK="assembleRelease"
    APK_DIR="app/build/outputs/apk/release"
fi

# Use system Gradle or wrapper
if [ -f "./gradlew" ]; then
    chmod +x ./gradlew
    ./gradlew "$GRADLE_TASK"
else
    gradle "$GRADLE_TASK"
fi

echo ""
echo "=== Build complete ==="
find "$APK_DIR" -name "*.apk" -exec echo "  APK: {}" \;
find "$APK_DIR" -name "*.apk" -exec ls -lh {} \;
