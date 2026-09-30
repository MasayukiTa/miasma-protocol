//! The web client (`web/`), compiled into the daemon so the HTTP bridge can serve it.
//!
//! Serving the client from the bridge's own origin means the launch link printed
//! by `miasma web` is one URL on one port: no second static server, no CORS, and
//! the browser's service worker and `fetch` calls are same-origin.  The files are
//! public code, so they are served without the control token; every `/api/*`
//! route other than `/api/ping` still needs it.
//!
//! Adding a file to `web/` means adding a line here; `every_web_file_is_embedded`
//! fails until you do.

/// One embedded file.
pub struct Asset {
    /// Path relative to `web/`, without a leading slash.
    pub path: &'static str,
    pub content_type: &'static str,
    pub body: &'static [u8],
}

macro_rules! asset {
    ($path:literal, $ct:expr) => {
        Asset {
            path: $path,
            content_type: $ct,
            body: include_bytes!(concat!("../../../../web/", $path)),
        }
    };
}

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

pub static ASSETS: &[Asset] = &[
    asset!("index.html", HTML),
    asset!("css/style.css", CSS),
    asset!("js/app.js", JS),
    asset!("js/bridge.js", JS),
    asset!("js/i18n.js", JS),
    asset!("js/storage.js", JS),
    asset!("manifest.json", "application/manifest+json"),
    asset!("pkg/miasma_wasm.js", JS),
    asset!("pkg/miasma_wasm_bg.wasm", "application/wasm"),
    asset!("sw.js", JS),
];

/// Find the asset for a request path (`/` is the index page).  Anything with a
/// `..` segment or a backslash is refused outright rather than normalised.
pub fn lookup(request_path: &str) -> Option<&'static Asset> {
    let rel = request_path.strip_prefix('/')?;
    let rel = if rel.is_empty() { "index.html" } else { rel };
    if rel.contains("..") || rel.contains('\\') {
        return None;
    }
    ASSETS.iter().find(|a| a.path == rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_the_index_page() {
        assert_eq!(lookup("/").unwrap().path, "index.html");
        assert_eq!(lookup("/js/app.js").unwrap().content_type, JS);
        assert!(lookup("/api/status").is_none());
        assert!(lookup("/../Cargo.toml").is_none());
        assert!(lookup("/js/../index.html").is_none());
        assert!(lookup("index.html").is_none());
    }

    #[test]
    fn every_web_file_is_embedded() {
        // Files under web/ that are not part of the shipped client.
        let skip = ["pkg/.gitignore", "pkg/package.json"];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web");
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if skip.contains(&rel.as_str()) || rel.ends_with(".d.ts") {
                    continue;
                }
                assert!(
                    ASSETS.iter().any(|a| a.path == rel),
                    "web/{rel} is not embedded in daemon/web_assets.rs"
                );
            }
        }
    }

    #[test]
    fn the_service_worker_precache_list_is_all_embedded() {
        let sw = ASSETS.iter().find(|a| a.path == "sw.js").unwrap();
        let sw = std::str::from_utf8(sw.body).unwrap();
        let list = sw
            .split("PRECACHE_ASSETS = [")
            .nth(1)
            .and_then(|s| s.split(']').next())
            .expect("PRECACHE_ASSETS in sw.js");
        for item in list.split(',') {
            let item = item.trim().trim_matches('\'');
            if item.is_empty() {
                continue;
            }
            assert!(
                ASSETS.iter().any(|a| a.path == item),
                "sw.js precaches {item}, which the bridge does not serve"
            );
        }
    }
}
