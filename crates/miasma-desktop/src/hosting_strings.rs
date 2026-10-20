//! Text of the "keep encrypted pieces for others" setting and of the line that replaces the
//! update controls in a Microsoft Store install, in the three languages the app ships. The
//! completeness tests at the bottom fail when a language lacks a text.

use crate::locale::Locale;

macro_rules! host_strings {
    ($($f:ident),* $(,)?) => {
        /// Fixed labels and explanations of the hosting setting.
        pub struct HostStrings { $(pub $f: &'static str),* }
        impl HostStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

host_strings! {
    heading, intro, load_failed,
    switch_label, choice_off, choice_256m, choice_1g, choice_5g,
    desc_off, desc_on, custom_note,
    usage, usage_unknown,
    restart_tag, saved_notice, save_failed,
    store_updates,
}

pub fn host_strings(locale: Locale) -> &'static HostStrings {
    match locale {
        Locale::En => &HOST_EN,
        Locale::Ja => &HOST_JA,
        Locale::ZhCn => &HOST_ZH_CN,
    }
}

static HOST_EN: HostStrings = HostStrings {
    heading: "Storing for others",
    intro: "Miasma can keep small encrypted pieces of other people's files on this computer, so those files can be found later. You cannot read them. The space they use is included in the use shown below.",
    load_failed: "The settings file could not be read. The default value is shown.",
    switch_label: "Keep encrypted pieces for others:",
    choice_off: "Off",
    choice_256m: "256 MiB",
    choice_1g: "1 GiB",
    choice_5g: "5 GiB",
    desc_off: "This computer keeps nothing for other people.",
    desc_on: "Keeps up to {size} of encrypted pieces for other people. When the space is full, new pieces are refused.",
    custom_note: "The settings file sets {n} MiB. Choose a size above to replace it.",
    usage: "In use on this computer now: {used} MiB (your saved files and the pieces kept for others, together).",
    usage_unknown: "The current use is shown while the background service is running.",
    restart_tag: "Applies after restart",
    saved_notice: "Saved. Close Miasma completely and start it again for the change to take effect.",
    save_failed: "The setting could not be saved.",
    store_updates: "Updates are handled by the Microsoft Store.",
};

static HOST_JA: HostStrings = HostStrings {
    heading: "他の人のための保管",
    intro: "Miasma は、他の人のファイルを暗号化した小さな断片をこのパソコンで預かり、あとでそのファイルを見つけられるようにできます。預かった断片の中身は読めません。使う容量は、下に表示する使用量に含まれます。",
    load_failed: "設定ファイルを読み込めませんでした。初期値を表示しています。",
    switch_label: "他の人の暗号化された断片を預かる:",
    choice_off: "しない",
    choice_256m: "256 MiB",
    choice_1g: "1 GiB",
    choice_5g: "5 GiB",
    desc_off: "このパソコンは、他の人のものを何も預かりません。",
    desc_on: "他の人の暗号化された断片を、最大 {size} まで預かります。容量がいっぱいになると、新しい断片は受け付けません。",
    custom_note: "設定ファイルでは {n} MiB になっています。上の大きさを選ぶと置き換わります。",
    usage: "このパソコンでの現在の使用量: {used} MiB (自分の保存ファイルと、預かっている断片の合計)。",
    usage_unknown: "現在の使用量は、バックグラウンドサービスの動作中に表示されます。",
    restart_tag: "再起動後に反映",
    saved_notice: "保存しました。反映するには、Miasma を完全に閉じてからもう一度起動してください。",
    save_failed: "設定を保存できませんでした。",
    store_updates: "更新は Microsoft Store が行います。",
};

static HOST_ZH_CN: HostStrings = HostStrings {
    heading: "为他人保管",
    intro: "Miasma 可以在这台电脑上保管其他人文件的加密数据块，方便日后找回这些文件。你无法读取这些数据块。它们占用的空间已计入下方显示的用量。",
    load_failed: "无法读取设置文件，当前显示的是默认值。",
    switch_label: "为他人保管加密数据块：",
    choice_off: "关闭",
    choice_256m: "256 MiB",
    choice_1g: "1 GiB",
    choice_5g: "5 GiB",
    desc_off: "这台电脑不会为其他人保管任何内容。",
    desc_on: "最多为其他人保管 {size} 的加密数据块。空间用满后，不再接收新的数据块。",
    custom_note: "设置文件中的大小为 {n} MiB。选择上面的大小即可替换。",
    usage: "这台电脑当前已用：{used} MiB（你保存的文件与为他人保管的数据块合计）。",
    usage_unknown: "后台服务运行时会显示当前用量。",
    restart_tag: "重启后生效",
    saved_notice: "已保存。请完全退出 Miasma 后重新启动，更改才会生效。",
    save_failed: "无法保存此设置。",
    store_updates: "更新由 Microsoft Store 负责。",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hosting_string_exists_in_every_locale_and_keeps_its_placeholders() {
        for lang in Locale::ALL {
            let s = host_strings(lang);
            for (name, value) in s.all() {
                assert!(!value.trim().is_empty(), "{lang:?} hosting.{name} is empty");
            }
            for (name, value, ph) in [
                ("desc_on", s.desc_on, "{size}"),
                ("custom_note", s.custom_note, "{n}"),
                ("usage", s.usage, "{used}"),
            ] {
                assert!(value.contains(ph), "{lang:?} hosting.{name} lost {ph}");
            }
            assert!(
                s.store_updates.contains("Microsoft Store"),
                "{lang:?} hosting.store_updates must name the Store"
            );
        }
        let (en, ja, zh) = (
            host_strings(Locale::En),
            host_strings(Locale::Ja),
            host_strings(Locale::ZhCn),
        );
        assert_ne!(en.intro, ja.intro);
        assert_ne!(en.intro, zh.intro);
        assert_ne!(ja.intro, zh.intro);
    }

    #[test]
    fn zh_cn_hosting_texts_match_the_english_ones() {
        crate::locale::assert_translation_parity(
            "hosting",
            host_strings(Locale::En).all(),
            host_strings(Locale::ZhCn).all(),
        );
    }
}
