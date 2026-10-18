//! Version handling: release tags, `--version` output, ordering.
//!
//! Ordering is semantic versioning (including the rule that a pre-release
//! sorts below its release: `0.3.2-beta.2 < 0.3.2`), never string equality.
//! Build metadata (`+abc`) is ignored for precedence, as the specification says.

use std::cmp::Ordering;

use semver::{BuildMetadata, Version};

/// A release tag (`v0.3.2-beta.2`, `0.3.2`) as a version. `None` when the tag is
/// not a semantic version (such releases are ignored).
pub fn parse_tag(tag: &str) -> Option<Version> {
    let t = tag.trim();
    let t = t
        .strip_prefix('v')
        .or_else(|| t.strip_prefix('V'))
        .unwrap_or(t);
    Version::parse(t).ok()
}

/// Precedence order of two versions, ignoring build metadata.
pub fn precedence(a: &Version, b: &Version) -> Ordering {
    let strip = |v: &Version| {
        let mut v = v.clone();
        v.build = BuildMetadata::EMPTY;
        v
    };
    strip(a).cmp(&strip(b))
}

/// Whether `candidate` is strictly newer than `current`.
pub fn is_newer(current: &Version, candidate: &Version) -> bool {
    precedence(current, candidate) == Ordering::Less
}

/// A build as `miasma --version` prints it: `miasma 0.3.2 (1a2b3c4d5)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: Version,
    pub build_id: String,
}

/// Parse the output of `miasma --version`. The program name must be `miasma`
/// and the build id is the word in brackets.
pub fn parse_version_output(text: &str) -> Option<BuildInfo> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let mut words = line.split_whitespace();
    if words.next()? != "miasma" {
        return None;
    }
    let version = Version::parse(words.next()?).ok()?;
    let id = words.next()?;
    let id = id.strip_prefix('(')?.strip_suffix(')')?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if words.next().is_some() {
        return None;
    }
    Some(BuildInfo {
        version,
        build_id: id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn tags_parse_with_or_without_the_v() {
        assert_eq!(parse_tag("v0.3.2-beta.2"), Some(v("0.3.2-beta.2")));
        assert_eq!(parse_tag(" 1.0.0 "), Some(v("1.0.0")));
        assert_eq!(parse_tag("nightly"), None);
        assert_eq!(parse_tag("v1.2"), None);
        assert_eq!(parse_tag(""), None);
    }

    #[test]
    fn prerelease_ordering_follows_semver() {
        // The classic chain from the specification.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for w in chain.windows(2) {
            assert!(is_newer(&v(w[0]), &v(w[1])), "{} < {}", w[0], w[1]);
            assert!(!is_newer(&v(w[1]), &v(w[0])), "{} !< {}", w[1], w[0]);
        }
        // beta.11 is newer than beta.2 although "beta.11" < "beta.2" as strings.
        assert!(is_newer(&v("0.3.2-beta.2"), &v("0.3.2-beta.11")));
    }

    #[test]
    fn beta_builds_order_between_themselves_and_below_the_release() {
        // A build that embeds its label (`0.3.2-beta.2`) sees beta.3 as newer,
        // and the plain release as newer still; never the other way round.
        let (b2, b3, rel) = (v("0.3.2-beta.2"), v("0.3.2-beta.3"), v("0.3.2"));
        assert!(precedence(&b2, &b3) == Ordering::Less && precedence(&b3, &rel) == Ordering::Less);
        assert!(is_newer(&b2, &b3) && is_newer(&b3, &rel) && is_newer(&b2, &rel));
        assert!(!is_newer(&b3, &b2) && !is_newer(&rel, &b3) && !is_newer(&b3, &b3));
        // Tags of the real releases parse to exactly these versions.
        assert_eq!(parse_tag("v0.3.2-beta.3"), Some(b3));
    }

    #[test]
    fn a_release_is_newer_than_its_own_prerelease_and_not_the_reverse() {
        assert!(is_newer(&v("0.3.2-beta.2"), &v("0.3.2")));
        assert!(!is_newer(&v("0.3.2"), &v("0.3.2-beta.2")));
        assert!(is_newer(&v("0.3.1"), &v("0.3.2-beta.1")));
    }

    #[test]
    fn equal_versions_and_build_metadata_are_not_newer() {
        assert!(!is_newer(&v("0.3.2"), &v("0.3.2")));
        assert!(!is_newer(&v("0.3.2+aaa"), &v("0.3.2+bbb")));
        assert!(!is_newer(&v("0.3.2+bbb"), &v("0.3.2+aaa")));
        assert_eq!(precedence(&v("1.0.0+x"), &v("1.0.0")), Ordering::Equal);
    }

    #[test]
    fn version_output_is_read_strictly() {
        let b = parse_version_output("miasma 0.3.2 (1a2b3c4d5)\n").unwrap();
        assert_eq!(b.version, v("0.3.2"));
        assert_eq!(b.build_id, "1a2b3c4d5");
        assert!(parse_version_output("miasma 0.3.2-beta.1 (unknown)").is_some());
        assert!(parse_version_output("miasma-desktop 0.3.2 (abc)").is_none());
        assert!(parse_version_output("miasma 0.3.2").is_none());
        assert!(parse_version_output("miasma 0.3.2 (a b)").is_none());
        assert!(parse_version_output("miasma 0.3.2 ()").is_none());
        assert!(parse_version_output("miasma 0.3.2 (abc) extra").is_none());
        assert!(parse_version_output("").is_none());
        assert!(parse_version_output("something else entirely").is_none());
    }
}
