//! Strings of the Settings screen's category row and its "Danger zone", and the labels that go
//! with absolute dates.
//!
//! Kept in its own file, like `audit.rs`, so the sentences stay together and are checked together
//! (the parity test at the bottom). The Simplified Chinese lines are a plain first version for the
//! Chinese reviewer to polish.

use super::Locale;

macro_rules! settings_strings {
    ($($f:ident),* $(,)?) => {
        /// One table per language.
        pub struct SettingsStrings { $(pub $f: &'static str),* }
        impl SettingsStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

settings_strings! {
    // The category row.
    cat_general, cat_privacy, cat_network, cat_updates, cat_about, cat_danger,
    // The Danger zone page.
    danger_intro,
    // Absolute dates: the zone the time is written in.
    utc,
}

pub fn settings_strings(locale: Locale) -> &'static SettingsStrings {
    match locale {
        Locale::En => &SE_EN,
        Locale::Ja => &SE_JA,
        Locale::ZhCn => &SE_ZH_CN,
    }
}

static SE_EN: SettingsStrings = SettingsStrings {
    cat_general: "General",
    cat_privacy: "Privacy and storage",
    cat_network: "Network",
    cat_updates: "Updates",
    cat_about: "About",
    cat_danger: "Danger zone",
    danger_intro: "These actions delete data and cannot be undone. Each one asks you to confirm and says what will be deleted.",
    utc: "UTC",
};

static SE_JA: SettingsStrings = SettingsStrings {
    cat_general: "一般",
    cat_privacy: "プライバシーと保存",
    cat_network: "ネットワーク",
    cat_updates: "アップデート",
    cat_about: "このアプリについて",
    cat_danger: "危険な操作",
    danger_intro: "ここにある操作はデータを削除し、元に戻せません。どの操作も、実行前に何が消えるかを示して確認を求めます。",
    utc: "UTC",
};

static SE_ZH_CN: SettingsStrings = SettingsStrings {
    cat_general: "常规",
    cat_privacy: "隐私与存储",
    cat_network: "网络",
    cat_updates: "更新",
    cat_about: "关于",
    cat_danger: "危险操作",
    danger_intro:
        "这里的操作会删除数据，且无法撤销。每项操作在执行前都会说明将删除什么并请您确认。",
    utc: "UTC",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_settings_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            for (name, value) in settings_strings(lang).all() {
                assert!(
                    !value.trim().is_empty(),
                    "{lang:?} settings.{name} is empty"
                );
            }
        }
    }

    #[test]
    fn zh_cn_settings_texts_match_the_english_ones() {
        crate::locale::assert_translation_parity(
            "settings",
            settings_strings(Locale::En).all(),
            settings_strings(Locale::ZhCn).all(),
        );
    }

    #[test]
    fn japanese_has_no_english_leftovers() {
        for (name, value) in settings_strings(Locale::Ja).all() {
            // "UTC" is the one international abbreviation.
            if name == "utc" {
                continue;
            }
            assert!(
                !value.is_ascii(),
                "ja settings.{name} is ASCII only: {value:?}"
            );
        }
    }

    #[test]
    fn category_names_fit_a_narrow_row() {
        for lang in Locale::ALL {
            let s = settings_strings(lang);
            for name in [
                s.cat_general,
                s.cat_privacy,
                s.cat_network,
                s.cat_updates,
                s.cat_about,
                s.cat_danger,
            ] {
                assert!(name.chars().count() <= 20, "{lang:?}: {name:?} is too long");
            }
        }
    }
}
