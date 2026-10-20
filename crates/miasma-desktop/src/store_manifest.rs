//! The Microsoft Store package manifest must declare the languages the app ships. This test
//! reads the template the build script fills in and compares its `<Resource Language>`
//! entries with [`crate::locale::Locale::ALL`], so a new app language cannot be forgotten.

use crate::locale::Locale;

const TEMPLATE: &str = include_str!("../../../installer/msix/AppxManifest.template.xml");

/// The Windows resource language tag of an app language (lower case, as the template writes it).
fn package_language(l: Locale) -> &'static str {
    match l {
        Locale::En => "en-us",
        Locale::Ja => "ja-jp",
        Locale::ZhCn => "zh-cn",
    }
}

/// Every `Language="..."` value inside the `<Resources>` element, in order.
fn declared_languages(xml: &str) -> Vec<String> {
    let start = xml.find("<Resources>").expect("no <Resources> element");
    let end = xml[start..]
        .find("</Resources>")
        .expect("unclosed <Resources>")
        + start;
    let mut out = Vec::new();
    let mut rest = &xml[start..end];
    while let Some(i) = rest.find("<Resource ") {
        rest = &rest[i + "<Resource ".len()..];
        let tag_end = rest.find("/>").expect("unclosed <Resource>");
        let tag = &rest[..tag_end];
        let a = tag
            .find("Language=\"")
            .expect("<Resource> without Language")
            + "Language=\"".len();
        let b = tag[a..].find('"').expect("unclosed Language value") + a;
        out.push(tag[a..b].to_owned());
        rest = &rest[tag_end..];
    }
    out
}

#[test]
fn the_manifest_declares_every_language_the_app_has() {
    let declared = declared_languages(TEMPLATE);
    let want: Vec<String> = Locale::ALL
        .iter()
        .map(|l| package_language(*l).to_owned())
        .collect();
    assert_eq!(declared, want);
}

#[test]
fn the_manifest_template_is_still_well_formed_around_the_resources() {
    assert_eq!(TEMPLATE.matches("<Resources>").count(), 1);
    assert_eq!(TEMPLATE.matches("</Resources>").count(), 1);
    assert!(TEMPLATE.contains("<Package
") || TEMPLATE.contains("<Package
"));
    assert_eq!(TEMPLATE.matches("</Package>").count(), 1);
    // The placeholders the build script fills in are all still there.
    for ph in [
        "@@IDENTITY_NAME@@",
        "@@PUBLISHER@@",
        "@@PUBLISHER_DISPLAY_NAME@@",
        "@@VERSION@@",
    ] {
        assert!(TEMPLATE.contains(ph), "{ph}");
    }
}

#[test]
fn the_language_reader_handles_a_short_example() {
    let xml = "<Resources>\n<Resource Language=\"en-us\" />\n<Resource Language=\"fr-fr\"/>\n</Resources>";
    assert_eq!(declared_languages(xml), ["en-us", "fr-fr"]);
}
