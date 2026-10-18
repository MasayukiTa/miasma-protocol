//! GitHub Releases: the JSON the public API returns, which release to take, and
//! which asset of it fits this machine.

use semver::Version;
use serde::Deserialize;

use super::config::UpdateChannel;
use super::version::{is_newer, parse_tag, precedence};

/// The repository the program updates from.
pub const REPO: &str = "MasayukiTa/miasma-protocol";

/// Name of the checksum file a release must carry.
pub const SUMS_NAME: &str = "SHA256SUMS.txt";
/// Name of its detached signature.
pub const SIG_NAME: &str = "SHA256SUMS.txt.sig";

/// How many releases one check asks for.
pub const RELEASES_PER_PAGE: u32 = 10;

#[derive(Debug, Clone, Deserialize)]
pub struct GhAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GhRelease {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<GhAsset>,
}

/// The operating system the update is chosen for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Other,
}

impl Os {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

/// The URL of the release list for `repo`, newest first.
pub fn releases_url(repo: &str) -> String {
    format!("https://api.github.com/repos/{repo}/releases?per_page={RELEASES_PER_PAGE}")
}

/// Parse the API answer. A body that is not a JSON array of releases is an
/// error (a rate-limit or error object is not mistaken for "no releases").
pub fn parse_releases(body: &[u8]) -> Result<Vec<GhRelease>, String> {
    serde_json::from_slice::<Vec<GhRelease>>(body).map_err(|e| format!("release list: {e}"))
}

/// The asset of `release` that carries the program for `os`, if any.
///
/// * Windows: the installer-less zip `miasma-<version>-windows-x64.zip`, else
///   the `-easy` variant of it (same programs, different documentation). There
///   is no fallback to anything else: a release without such a zip has no
///   Windows asset.
/// * macOS: `Miasma-macOS.zip` (the application bundle). The `.tar.gz` holds
///   the same binaries, but only the zip is read by the updater, so it is not
///   chosen.
pub fn pick_asset(release: &GhRelease, os: Os) -> Option<&GhAsset> {
    let lower = |a: &GhAsset| a.name.to_ascii_lowercase();
    match os {
        Os::Windows => {
            let is_win = |a: &&GhAsset| {
                let n = lower(a);
                n.starts_with("miasma-") && n.ends_with(".zip") && n.contains("windows-x64")
            };
            release
                .assets
                .iter()
                .filter(is_win)
                .find(|a| !lower(a).ends_with("-easy.zip"))
                .or_else(|| release.assets.iter().filter(is_win).next())
        }
        Os::MacOs => release
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case("Miasma-macOS.zip")),
        Os::Other => None,
    }
}

fn find<'a>(release: &'a GhRelease, names: &[&str]) -> Option<&'a GhAsset> {
    release
        .assets
        .iter()
        .find(|a| names.iter().any(|n| a.name == *n))
}

/// The checksum asset of a release.
pub fn sums_asset(release: &GhRelease) -> Option<&GhAsset> {
    find(release, &[SUMS_NAME, "SHA256SUMS"])
}

/// The signature asset of a release.
pub fn sig_asset(release: &GhRelease) -> Option<&GhAsset> {
    find(release, &[SIG_NAME, "SHA256SUMS.sig"])
}

/// What choosing among the releases came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Nothing newer than the running build (in this channel). `latest` is the
    /// newest version seen, when any release was usable.
    UpToDate { latest: Option<Version> },
    /// A newer release with an asset for this machine and a checksum file.
    Newer { index: usize, version: Version },
    /// The newest newer release has no asset for this machine.
    NoAsset { version: Version },
    /// The newest newer release with an asset has no `SHA256SUMS.txt`, so it
    /// cannot be verified and is refused.
    Unverifiable { version: Version },
}

/// Choose from `releases` for a build of version `current`.
///
/// Drafts and tags that are not semantic versions are ignored; on the stable
/// channel pre-releases are ignored too. Releases are ordered by version, not
/// by date or tag text.
pub fn select_release(
    releases: &[GhRelease],
    channel: UpdateChannel,
    current: &Version,
    os: Os,
) -> Selection {
    let mut usable: Vec<(usize, Version)> = releases
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.draft)
        .filter_map(|(i, r)| parse_tag(&r.tag_name).map(|v| (i, v, r)))
        .filter(|(_, v, r)| channel == UpdateChannel::Beta || (!r.prerelease && v.pre.is_empty()))
        .map(|(i, v, _)| (i, v))
        .collect();
    usable.sort_by(|a, b| precedence(&b.1, &a.1));

    let Some((_, newest)) = usable.first() else {
        return Selection::UpToDate { latest: None };
    };
    if !is_newer(current, newest) {
        return Selection::UpToDate {
            latest: Some(newest.clone()),
        };
    }
    let mut first_newer: Option<Version> = None;
    let mut unverifiable: Option<Version> = None;
    for (i, v) in usable.iter().filter(|(_, v)| is_newer(current, v)) {
        first_newer.get_or_insert_with(|| v.clone());
        let r = &releases[*i];
        if pick_asset(r, os).is_none() {
            continue;
        }
        if sums_asset(r).is_none() {
            unverifiable.get_or_insert_with(|| v.clone());
            continue;
        }
        return Selection::Newer {
            index: *i,
            version: v.clone(),
        };
    }
    if let Some(version) = unverifiable {
        return Selection::Unverifiable { version };
    }
    Selection::NoAsset {
        version: first_newer.unwrap_or_else(|| newest.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(tag: &str, pre: bool, assets: &[&str]) -> GhRelease {
        GhRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease: pre,
            assets: assets
                .iter()
                .map(|n| GhAsset {
                    name: (*n).into(),
                    browser_download_url: format!("https://example.invalid/{n}"),
                    size: 1,
                })
                .collect(),
        }
    }

    const MAC: &[&str] = &["miasma-macos.tar.gz", "Miasma-macOS.zip", "SHA256SUMS.txt"];
    const WIN: &[&str] = &[
        "miasma-0.4.0-windows-x64-easy.zip",
        "miasma-0.4.0-windows-x64.zip",
        "SHA256SUMS.txt",
    ];

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn the_real_release_list_shape_parses() {
        let body = br#"[{"tag_name":"v0.3.2-beta.2","draft":false,"prerelease":true,"extra":1,
            "assets":[{"name":"Miasma-macOS.zip","browser_download_url":"https://x/y","size":5,"id":9}]}]"#;
        let r = parse_releases(body).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].prerelease);
        assert_eq!(r[0].assets[0].size, 5);
    }

    #[test]
    fn an_api_error_object_is_not_a_release_list() {
        assert!(parse_releases(br#"{"message":"API rate limit exceeded"}"#).is_err());
        assert!(parse_releases(b"<html>").is_err());
    }

    #[test]
    fn asset_selection_per_os() {
        let mac = rel("v1.0.0", false, MAC);
        assert_eq!(
            pick_asset(&mac, Os::MacOs).unwrap().name,
            "Miasma-macOS.zip"
        );
        assert!(pick_asset(&mac, Os::Windows).is_none());
        assert!(pick_asset(&mac, Os::Other).is_none());

        let win = rel("v0.4.0", false, WIN);
        assert_eq!(
            pick_asset(&win, Os::Windows).unwrap().name,
            "miasma-0.4.0-windows-x64.zip"
        );
        assert!(pick_asset(&win, Os::MacOs).is_none());

        // Only the easy variant: taken, because the programs are the same.
        let easy_only = rel("v0.4.0", false, &["miasma-0.4.0-windows-x64-easy.zip"]);
        assert_eq!(
            pick_asset(&easy_only, Os::Windows).unwrap().name,
            "miasma-0.4.0-windows-x64-easy.zip"
        );
        // An installer or an unrelated zip is not an installer-less zip.
        let other = rel("v0.4.0", false, &["Miasma.msi", "source.zip", "notes.zip"]);
        assert!(pick_asset(&other, Os::Windows).is_none());
    }

    #[test]
    fn checksum_and_signature_assets_are_found_by_exact_name() {
        let r = rel("v1.0.0", false, &["SHA256SUMS.txt", "SHA256SUMS.txt.sig"]);
        assert_eq!(sums_asset(&r).unwrap().name, "SHA256SUMS.txt");
        assert_eq!(sig_asset(&r).unwrap().name, "SHA256SUMS.txt.sig");
        let none = rel("v1.0.0", false, &["sha256sums.txt.bak"]);
        assert!(sums_asset(&none).is_none());
    }

    #[test]
    fn the_highest_version_wins_not_the_latest_listed() {
        let list = vec![
            rel("v0.3.2-beta.2", true, MAC),
            rel("v0.3.2-beta.11", true, MAC),
            rel("v0.3.2-beta.1", true, MAC),
        ];
        match select_release(&list, UpdateChannel::Beta, &v("0.3.1"), Os::MacOs) {
            Selection::Newer { index, version } => {
                assert_eq!(index, 1);
                assert_eq!(version, v("0.3.2-beta.11"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_running_version_and_older_ones_are_up_to_date() {
        let list = vec![
            rel("v0.3.2-beta.2", true, MAC),
            rel("v0.3.1-beta.1", true, MAC),
        ];
        // 0.3.2 is above 0.3.2-beta.2: no downgrade is ever offered.
        assert_eq!(
            select_release(&list, UpdateChannel::Beta, &v("0.3.2"), Os::MacOs),
            Selection::UpToDate {
                latest: Some(v("0.3.2-beta.2"))
            }
        );
        assert_eq!(
            select_release(&[], UpdateChannel::Beta, &v("0.3.2"), Os::MacOs),
            Selection::UpToDate { latest: None }
        );
    }

    #[test]
    fn the_stable_channel_skips_prereleases_and_drafts() {
        let mut draft = rel("v2.0.0", false, MAC);
        draft.draft = true;
        let list = vec![
            draft,
            rel("v1.1.0-rc.1", true, MAC),
            rel("v1.0.1", false, MAC),
            rel("nightly", false, MAC),
        ];
        match select_release(&list, UpdateChannel::Stable, &v("1.0.0"), Os::MacOs) {
            Selection::Newer { version, .. } => assert_eq!(version, v("1.0.1")),
            other => panic!("{other:?}"),
        }
        match select_release(&list, UpdateChannel::Beta, &v("1.0.0"), Os::MacOs) {
            Selection::Newer { version, .. } => assert_eq!(version, v("1.1.0-rc.1")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_pre_release_flag_on_a_plain_tag_still_counts_as_prerelease_for_stable() {
        let list = vec![rel("v1.0.1", true, MAC)];
        assert_eq!(
            select_release(&list, UpdateChannel::Stable, &v("1.0.0"), Os::MacOs),
            Selection::UpToDate { latest: None }
        );
    }

    #[test]
    fn a_newer_release_without_a_platform_asset_is_reported_as_such() {
        // The shape of the real releases today: macOS files only.
        let list = vec![rel("v0.4.0-beta.1", true, MAC)];
        assert_eq!(
            select_release(&list, UpdateChannel::Beta, &v("0.3.2"), Os::Windows),
            Selection::NoAsset {
                version: v("0.4.0-beta.1")
            }
        );
    }

    #[test]
    fn an_older_release_with_an_asset_is_used_when_the_newest_has_none() {
        let list = vec![
            rel("v0.5.0", false, &["notes.txt"]),
            rel("v0.4.0", false, WIN),
        ];
        match select_release(&list, UpdateChannel::Beta, &v("0.3.0"), Os::Windows) {
            Selection::Newer { index, version } => {
                assert_eq!(index, 1);
                assert_eq!(version, v("0.4.0"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_release_without_checksums_is_unverifiable_not_available() {
        let list = vec![rel("v0.4.0", false, &["miasma-0.4.0-windows-x64.zip"])];
        assert_eq!(
            select_release(&list, UpdateChannel::Beta, &v("0.3.0"), Os::Windows),
            Selection::Unverifiable {
                version: v("0.4.0")
            }
        );
    }
}
