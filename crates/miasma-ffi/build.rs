fn main() {
    // Re-run this build script if the FFI source changes.
    println!("cargo:rerun-if-changed=src/lib.rs");
}
