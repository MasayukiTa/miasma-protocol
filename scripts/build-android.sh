#!/usr/bin/env bash
# Build Miasma for Android / Google Play.
#
# Debug:   ./scripts/build-android.sh
# Release: ./scripts/build-android.sh --release   # signed AAB for Play
# Verify-only release: ./scripts/build-android.sh --release --unsigned-release
# Setup:   ./scripts/build-android.sh --setup
#
# The Android app compiles against API 36 and pins NDK r30. Rust is built for
# arm64-v8a (devices) and x86_64 (emulators). UniFFI bindings are generated from
# the same Android cdylib that is packaged into the app, then the checked-in
# development stub is restored so a build does not dirty the worktree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANDROID_DIR="$PROJECT_DIR/android"

ANDROID_API=36
BUILD_TOOLS_VERSION="36.0.0"
NDK_VERSION="30.0.16248370"
MIN_GRADLE_VERSION="8.13"
BUILD_TYPE="debug"
SETUP_ONLY=false
ALLOW_UNSIGNED_RELEASE=false

for arg in "$@"; do
    case "$arg" in
        --release) BUILD_TYPE="release" ;;
        --setup) SETUP_ONLY=true ;;
        --unsigned-release) ALLOW_UNSIGNED_RELEASE=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"

# Recent Windows JDKs implement NIO Pipe with a temporary Unix-domain socket.
# A long inherited TEMP path can exceed the Windows AF_UNIX path limit and make
# Gradle fail before it even starts ("Unable to establish loopback connection").
# Keep the Java temp root intentionally short on Git Bash/MSYS/Cygwin. Override
# MIASMA_WINDOWS_BUILD_TMP when C: is unavailable.
case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*)
        WINDOWS_BUILD_TMP="${MIASMA_WINDOWS_BUILD_TMP:-C:\miasma-tmp}"
        if command -v cygpath >/dev/null 2>&1; then
            mkdir -p "$(cygpath -u "$WINDOWS_BUILD_TMP")"
        fi
        export TEMP="$WINDOWS_BUILD_TMP"
        export TMP="$WINDOWS_BUILD_TMP"
        ;;
esac

PINNED_NDK="$ANDROID_HOME/ndk/$NDK_VERSION"
if [ -d "$PINNED_NDK" ]; then
    export ANDROID_NDK_HOME="$PINNED_NDK"
elif [ -z "${ANDROID_NDK_HOME:-}" ]; then
    export ANDROID_NDK_HOME="$PINNED_NDK"
fi

SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
if [ ! -x "$SDKMANAGER" ] && [ -x "$SDKMANAGER.bat" ]; then
    SDKMANAGER="$SDKMANAGER.bat"
fi

if [ "$SETUP_ONLY" = true ]; then
    echo "=== Setting up Android build prerequisites ==="
    if [ ! -x "$SDKMANAGER" ] && [[ "$SDKMANAGER" != *.bat ]]; then
        echo "ERROR: Android command-line tools not found under:"
        echo "  $ANDROID_HOME/cmdline-tools/latest/"
        echo "Install Android Studio or the command-line tools first."
        exit 1
    fi

    yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
    "$SDKMANAGER" \
        "platforms;android-$ANDROID_API" \
        "build-tools;$BUILD_TOOLS_VERSION" \
        "platform-tools" \
        "ndk;$NDK_VERSION"

    rustup target add aarch64-linux-android x86_64-linux-android
    if ! command -v cargo-ndk >/dev/null 2>&1; then
        cargo install cargo-ndk
    fi

    echo
    echo "SDK/NDK/Rust targets are ready."
    echo "Gradle $MIN_GRADLE_VERSION+ is also required when the repository has no Gradle wrapper."
    exit 0
fi

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 not found. $2"
}

check_elf_alignment() {
    local so="$1"
    local saw_load=false
    local bad_alignment=false
    local line
    while IFS= read -r line; do
        if [[ "$line" =~ LOAD.*align[[:space:]]+2\*\*([0-9]+) ]]; then
            saw_load=true
            if (( BASH_REMATCH[1] < 14 )); then
                echo "  bad: $so: $line" >&2
                bad_alignment=true
            fi
        fi
    done < <("$OBJDUMP" -p "$so")
    [ "$saw_load" = true ] || fail "Could not read LOAD alignment from $so"
    [ "$bad_alignment" = false ] || fail "$so is not 16 KiB page-size aligned"
}

verify_archive_native_alignment() {
    local archive="$1"
    local unpack
    local found=false
    unpack="$(mktemp -d "${TMPDIR:-/tmp}/miasma-android-native.XXXXXX")"
    (
        cd "$unpack"
        jar xf "$archive"
    )
    while IFS= read -r -d '' so; do
        found=true
        check_elf_alignment "$so"
        echo "  ok: ${so#"$unpack"/}"
    done < <(find "$unpack" -type f -name '*.so' -print0)
    rm -rf "$unpack"
    [ "$found" = true ] || fail "No native libraries found in $archive"
}

need_command cargo "Install Rust from https://rustup.rs"
need_command rustup "Install Rust from https://rustup.rs"
need_command cargo-ndk "Run: cargo install cargo-ndk"
need_command java "Install JDK 17 or newer"
need_command jar "Install a full JDK 17 or newer"

[ -f "$PROJECT_DIR/web/index.html" ] || \
    fail "Canonical web UI is missing: $PROJECT_DIR/web/index.html"
[ -f "$PROJECT_DIR/web/pkg/miasma_wasm_bg.wasm" ] || \
    fail "Web WASM bundle is missing: build web/pkg before the Android package"

[ -d "$ANDROID_HOME/platforms/android-$ANDROID_API" ] || \
    fail "Android platform API $ANDROID_API is missing. Run ./scripts/build-android.sh --setup"
[ -d "$ANDROID_NDK_HOME" ] || \
    fail "NDK r$NDK_VERSION is missing at $ANDROID_NDK_HOME. Run ./scripts/build-android.sh --setup"

if [ -f "$ANDROID_NDK_HOME/source.properties" ]; then
    ACTUAL_NDK="$(sed -n 's/^Pkg.Revision[[:space:]]*=[[:space:]]*//p' "$ANDROID_NDK_HOME/source.properties" | head -1)"
    [ "$ACTUAL_NDK" = "$NDK_VERSION" ] || \
        fail "Expected NDK $NDK_VERSION, found ${ACTUAL_NDK:-unknown} at $ANDROID_NDK_HOME"
fi

for target in aarch64-linux-android x86_64-linux-android; do
    rustup target list --installed | grep -qx "$target" || \
        fail "Rust target $target is missing. Run: rustup target add $target"
done

JAVA_MAJOR="$(java -version 2>&1 | sed -n '1{s/.*version "\([0-9][0-9]*\).*/\1/p}')"
[ -n "$JAVA_MAJOR" ] || fail "Could not determine Java version"
[ "$JAVA_MAJOR" -ge 17 ] || fail "JDK 17+ is required; found Java $JAVA_MAJOR"

if [ -x "$ANDROID_DIR/gradlew" ]; then
    GRADLE=("$ANDROID_DIR/gradlew")
elif [ -f "$ANDROID_DIR/gradlew.bat" ]; then
    GRADLE=("$ANDROID_DIR/gradlew.bat")
elif command -v gradle >/dev/null 2>&1; then
    GRADLE=(gradle)
    GRADLE_VERSION="$(gradle --version | sed -n 's/^Gradle \([0-9][0-9.]*\)$/\1/p' | head -1)"
    if [ -n "$GRADLE_VERSION" ]; then
        LOWEST="$(printf '%s\n%s\n' "$MIN_GRADLE_VERSION" "$GRADLE_VERSION" | sort -V | head -1)"
        [ "$LOWEST" = "$MIN_GRADLE_VERSION" ] || \
            fail "Gradle $MIN_GRADLE_VERSION+ is required by AGP 8.11; found $GRADLE_VERSION"
    fi
else
    fail "Gradle not found and android/gradlew is absent. Install Gradle $MIN_GRADLE_VERSION+ or add the wrapper."
fi

PROFILE="debug"
CARGO_PROFILE_ARGS=()
if [ "$BUILD_TYPE" = "release" ]; then
    PROFILE="release"
    CARGO_PROFILE_ARGS=(--release)

    if [ "$ALLOW_UNSIGNED_RELEASE" = false ]; then
        for name in \
            MIASMA_ANDROID_KEYSTORE \
            MIASMA_ANDROID_STORE_PASSWORD \
            MIASMA_ANDROID_KEY_ALIAS \
            MIASMA_ANDROID_KEY_PASSWORD; do
            [ -n "${!name:-}" ] || fail "$name is required for a signed Play release (or pass --unsigned-release for verification only)"
        done
        [ -f "$MIASMA_ANDROID_KEYSTORE" ] || fail "Keystore not found: $MIASMA_ANDROID_KEYSTORE"
    fi
fi

JNI_LIBS="$ANDROID_DIR/app/src/main/jniLibs"
KOTLIN_ROOT="$ANDROID_DIR/app/src/main/kotlin"
GENERATED_BINDING="$KOTLIN_ROOT/dev/miasma/uniffi/miasma_ffi.kt"
UNIFFI_CONFIG="$PROJECT_DIR/crates/miasma-ffi/uniffi.toml"

STUB_BACKUP="$(mktemp "${TMPDIR:-/tmp}/miasma-ffi-stub.XXXXXX")"
HAD_STUB=false
if [ -f "$GENERATED_BINDING" ]; then
    cp "$GENERATED_BINDING" "$STUB_BACKUP"
    HAD_STUB=true
fi

restore_stub() {
    if [ "$HAD_STUB" = true ]; then
        mkdir -p "$(dirname "$GENERATED_BINDING")"
        cp "$STUB_BACKUP" "$GENERATED_BINDING"
    else
        rm -f "$GENERATED_BINDING"
    fi
    rm -f "$STUB_BACKUP"
}
trap restore_stub EXIT

cd "$PROJECT_DIR"

echo "=== Miasma Android build ==="
echo "  type:        $BUILD_TYPE"
echo "  SDK:         API $ANDROID_API"
echo "  NDK:         $NDK_VERSION"
echo "  Android SDK: $ANDROID_HOME"
echo

echo "[1/5] Building Rust FFI libraries..."
rm -rf "$JNI_LIBS/arm64-v8a" "$JNI_LIBS/x86_64"
mkdir -p "$JNI_LIBS"
cargo ndk \
    -t arm64-v8a \
    -t x86_64 \
    -o "$JNI_LIBS" \
    build "${CARGO_PROFILE_ARGS[@]}" -p miasma-ffi --lib

# cargo-ndk may surface cdylib artifacts from transitive dependencies alongside
# the actual FFI library. They are not DT_NEEDED by libmiasma_ffi.so and only
# bloat the APK/AAB, so package exactly the public JNI library we own.
find "$JNI_LIBS" -mindepth 2 -maxdepth 2 -type f -name '*.so' \
    ! -name 'libmiasma_ffi.so' -delete
for abi in arm64-v8a x86_64; do
    [ -f "$JNI_LIBS/$abi/libmiasma_ffi.so" ] || \
        fail "Missing Rust JNI library for $abi: $JNI_LIBS/$abi/libmiasma_ffi.so"
done

CARGO_OUTPUT_ROOT="${CARGO_TARGET_DIR:-$PROJECT_DIR/target}"
LIB_PATH="$CARGO_OUTPUT_ROOT/aarch64-linux-android/$PROFILE/libmiasma_ffi.so"
[ -f "$LIB_PATH" ] || fail "Expected UniFFI library not found: $LIB_PATH"

echo "[2/5] Checking 16 KiB ELF segment alignment..."
OBJDUMP=""
for candidate in "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump.exe; do
    if [ -x "$candidate" ] || [ -f "$candidate" ]; then
        OBJDUMP="$candidate"
        break
    fi
done
[ -n "$OBJDUMP" ] || fail "llvm-objdump not found in NDK $ANDROID_NDK_HOME"

for so in "$JNI_LIBS"/*/libmiasma_ffi.so; do
    [ -f "$so" ] || continue
    check_elf_alignment "$so"
    echo "  ok: $(basename "$(dirname "$so")")"
done

echo "[3/5] Generating Kotlin UniFFI bindings from the packaged cdylib..."
# Generate to the Kotlin source root. UniFFI appends dev/miasma/uniffi from
# uniffi.toml and overwrites the development stub for the duration of this build.
cargo run --quiet \
    -p miasma-ffi \
    --features bindgen-cli \
    --bin miasma-uniffi-bindgen \
    -- \
    generate \
    --library \
    --metadata-no-deps \
    --language kotlin \
    --config "$UNIFFI_CONFIG" \
    --out-dir "$KOTLIN_ROOT" \
    "$LIB_PATH"

[ -f "$GENERATED_BINDING" ] || fail "UniFFI did not generate $GENERATED_BINDING"
grep -q '^package dev\.miasma\.uniffi$' "$GENERATED_BINDING" || \
    fail "Generated Kotlin binding has the wrong package"
grep -q 'startEmbeddedDaemon' "$GENERATED_BINDING" || \
    fail "Generated bindings are missing startEmbeddedDaemon"

echo "[4/5] Building Android application..."
cd "$ANDROID_DIR"
if [ "$BUILD_TYPE" = "release" ]; then
    "${GRADLE[@]}" --no-daemon bundleRelease
else
    "${GRADLE[@]}" --no-daemon assembleDebug
fi

echo "[5/5] Verifying outputs..."
if [ "$BUILD_TYPE" = "release" ]; then
    OUTPUT="$ANDROID_DIR/app/build/outputs/bundle/release/app-release.aab"
    [ -f "$OUTPUT" ] || fail "Release AAB not found: $OUTPUT"
    echo "  AAB: $OUTPUT"

    if command -v bundletool >/dev/null 2>&1; then
        CONFIG_DUMP="$(bundletool dump config --bundle="$OUTPUT" 2>/dev/null || true)"
        if printf '%s' "$CONFIG_DUMP" | grep -q 'PAGE_ALIGNMENT_16K'; then
            echo "  bundle alignment: PAGE_ALIGNMENT_16K"
        else
            echo "WARNING: bundletool did not report PAGE_ALIGNMENT_16K" >&2
        fi
    else
        echo "  bundletool: not installed; AAB alignment metadata check skipped"
    fi
else
    OUTPUT="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
    [ -f "$OUTPUT" ] || fail "Debug APK not found: $OUTPUT"
    echo "  APK: $OUTPUT"

    ZIPALIGN="$ANDROID_HOME/build-tools/$BUILD_TOOLS_VERSION/zipalign"
    if [ ! -x "$ZIPALIGN" ] && [ -f "$ZIPALIGN.exe" ]; then
        ZIPALIGN="$ZIPALIGN.exe"
    fi
    [ -x "$ZIPALIGN" ] || [ -f "$ZIPALIGN" ] || \
        fail "zipalign not found for build-tools $BUILD_TOOLS_VERSION"
    "$ZIPALIGN" -c -P 16 4 "$OUTPUT" || \
        fail "APK native libraries are not 16 KiB ZIP aligned"
    echo "  APK ZIP alignment: 16 KiB OK"
fi

echo "  verifying every packaged native library (including JNA)..."
verify_archive_native_alignment "$OUTPUT"

ls -lh "$OUTPUT"
echo "=== Android build complete ==="
