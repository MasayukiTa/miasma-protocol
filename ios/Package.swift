// swift-tools-version: 5.9
/// Swift Package for the Miasma iOS app — Phase 2 (Task 13).
///
/// Build flow:
/// 1. Build XCFramework from Rust:
///    ```sh
///    cargo build --target aarch64-apple-ios --release -p miasma-ffi
///    cargo build --target x86_64-apple-ios-simulator --release -p miasma-ffi
///    uniffi-bindgen generate \
///        --library target/aarch64-apple-ios/release/libmiasma_ffi.a \
///        --language swift \
///        --out-dir ios/MiasmaApp/Sources/MiasmaFFI/
///    xcodebuild -create-xcframework \
///        -library target/aarch64-apple-ios/release/libmiasma_ffi.a \
///        -headers ios/MiasmaApp/Sources/MiasmaFFI/miasmaFFI.h \
///        -library target/x86_64-apple-ios-simulator/release/libmiasma_ffi.a \
///        -headers ios/MiasmaApp/Sources/MiasmaFFI/miasmaFFI.h \
///        -output ios/MiasmaFFI.xcframework
///    ```
/// 2. Open ios/MiasmaApp.xcodeproj in Xcode and run on device/simulator.

import PackageDescription

let package = Package(
    name: "MiasmaApp",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "MiasmaFFI", targets: ["MiasmaFFI"]),
        .executable(name: "MiasmaApp", targets: ["MiasmaApp"]),
    ],
    dependencies: [],
    targets: [
        // Auto-generated UniFFI Swift bindings + header.
        // The XCFramework (libmiasma_ffi.a) must be present at this path.
        .target(
            name: "MiasmaFFI",
            path: "MiasmaApp/Sources/MiasmaFFI",
            // Phase 2: link the XCFramework
            // linkerSettings: [.linkedFramework("MiasmaFFI")]
        ),
        .executableTarget(
            name: "MiasmaApp",
            dependencies: ["MiasmaFFI"],
            path: "MiasmaApp/App",
        ),
    ]
)
