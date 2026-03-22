fn main() {
    // Embed Windows resources: icon, version info, and file description.
    // This makes miasma-desktop.exe show the Miasma icon in Explorer, taskbar,
    // Start Menu shortcuts, and Alt-Tab.
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/miasma.ico");
        res.set("ProductName", "Miasma Protocol");
        res.set("FileDescription", "Miasma Desktop");
        res.set("LegalCopyright", "Miasma Contributors");
        if let Err(e) = res.compile() {
            // Don't fail the build if resource compilation fails (e.g., missing rc.exe).
            // The app will just not have an embedded icon.
            eprintln!("cargo:warning=Failed to compile Windows resources: {e}");
        }
    }
}
