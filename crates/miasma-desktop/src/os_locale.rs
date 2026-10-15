//! The language the operating system is set to, mapped onto the languages the app has.
//!
//! Only used when the person has no saved language preference (first launch): a saved choice
//! always wins, and Settings can still change it.

use crate::locale::Locale;

/// Map a language tag (`ja-JP`, `ja_JP.UTF-8`, `zh-Hans-CN`, `en_US`, ...) to an app language.
/// Japanese gives Japanese, any Chinese gives Simplified Chinese, everything else English.
#[cfg(any(not(windows), test))]
pub fn locale_from_tag(tag: &str) -> Locale {
    let lower = tag.trim().to_ascii_lowercase();
    let primary = lower.split(['-', '_', '.', '@']).next().unwrap_or_default();
    match primary {
        "ja" | "jpn" => Locale::Ja,
        "zh" | "zho" | "chi" => Locale::ZhCn,
        _ => Locale::En,
    }
}

/// Map a Windows language identifier (LANGID) to an app language. The low ten bits are the
/// primary language: 0x11 is Japanese, 0x04 is Chinese.
#[cfg(any(windows, test))]
pub fn locale_from_langid(langid: u16) -> Locale {
    match langid & 0x03ff {
        0x11 => Locale::Ja,
        0x04 => Locale::ZhCn,
        _ => Locale::En,
    }
}

/// The first non-empty value of the POSIX language variables, in their order of precedence.
/// `C` and `POSIX` carry no language.
#[cfg(any(not(windows), test))]
pub fn locale_from_env_values(values: &[Option<String>]) -> Locale {
    values
        .iter()
        .flatten()
        .map(|v| v.trim())
        .find(|v| !v.is_empty())
        .map(|v| {
            if v == "C" || v == "POSIX" {
                Locale::En
            } else {
                locale_from_tag(v)
            }
        })
        .unwrap_or(Locale::En)
}

#[cfg(windows)]
mod win {
    #[link(name = "kernel32")]
    extern "system" {
        /// The display language of the signed-in user (a LANGID); never fails.
        pub fn GetUserDefaultUILanguage() -> u16;
    }
}

/// The app language that matches the operating system's display language.
pub fn detect() -> Locale {
    #[cfg(windows)]
    {
        // SAFETY: no arguments, no pointers; the call only reads the user's language setting.
        let id = unsafe { win::GetUserDefaultUILanguage() };
        locale_from_langid(id)
    }
    #[cfg(not(windows))]
    {
        let vars: Vec<Option<String>> = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .map(|k| std::env::var(k).ok())
            .collect();
        locale_from_env_values(&vars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_map_to_the_three_languages() {
        assert_eq!(locale_from_tag("ja"), Locale::Ja);
        assert_eq!(locale_from_tag("ja-JP"), Locale::Ja);
        assert_eq!(locale_from_tag("ja_JP.UTF-8"), Locale::Ja);
        assert_eq!(locale_from_tag("JA-jp"), Locale::Ja);
        assert_eq!(locale_from_tag("zh"), Locale::ZhCn);
        assert_eq!(locale_from_tag("zh-CN"), Locale::ZhCn);
        assert_eq!(locale_from_tag("zh-Hans-CN"), Locale::ZhCn);
        assert_eq!(locale_from_tag("zh_TW.UTF-8"), Locale::ZhCn);
        assert_eq!(locale_from_tag("en-US"), Locale::En);
        assert_eq!(locale_from_tag("de-DE"), Locale::En);
        assert_eq!(locale_from_tag("ko-KR"), Locale::En);
        assert_eq!(locale_from_tag(""), Locale::En);
        assert_eq!(locale_from_tag("   "), Locale::En);
        // A tag that only starts with the letters of another language.
        assert_eq!(locale_from_tag("jav"), Locale::En);
        assert_eq!(locale_from_tag("zhuang"), Locale::En);
    }

    #[test]
    fn windows_language_ids_map_by_primary_language() {
        assert_eq!(locale_from_langid(0x0411), Locale::Ja); // ja-JP
        assert_eq!(locale_from_langid(0x0804), Locale::ZhCn); // zh-CN
        assert_eq!(locale_from_langid(0x0404), Locale::ZhCn); // zh-TW
        assert_eq!(locale_from_langid(0x0409), Locale::En); // en-US
        assert_eq!(locale_from_langid(0x0407), Locale::En); // de-DE
        assert_eq!(locale_from_langid(0x0000), Locale::En);
    }

    #[test]
    fn posix_variables_use_the_first_one_that_is_set() {
        let v = |a: Option<&str>, b: Option<&str>, c: Option<&str>| {
            locale_from_env_values(&[
                a.map(str::to_owned),
                b.map(str::to_owned),
                c.map(str::to_owned),
            ])
        };
        assert_eq!(v(None, None, Some("ja_JP.UTF-8")), Locale::Ja);
        assert_eq!(v(Some("zh_CN.UTF-8"), None, Some("ja_JP")), Locale::ZhCn);
        assert_eq!(v(Some(""), Some("ja_JP"), None), Locale::Ja);
        assert_eq!(v(Some("C"), Some("ja_JP"), None), Locale::En);
        assert_eq!(v(None, None, None), Locale::En);
    }
}
