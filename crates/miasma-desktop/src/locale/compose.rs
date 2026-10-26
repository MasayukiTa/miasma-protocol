//! Strings of the shared send flow (`send_flow.rs`) and of the conversation header and composer
//! (`chat_ui.rs`, `group_ui.rs`).
//!
//! Kept in its own file, like `group.rs`, so the new sentences stay together and are checked
//! together (the parity test at the bottom). Sentences that already exist in the Transfers,
//! Contacts or Chat tables are reused from there and not repeated here. `{name}`-style holes are
//! filled with `transfers::fill`.

use super::Locale;

macro_rules! compose_strings {
    ($($f:ident),* $(,)?) => {
        /// Every sentence of the send flow and the conversation header, one table per language.
        pub struct ComposeStrings { $(pub $f: &'static str),* }
        impl ComposeStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            pub(super) fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

compose_strings! {
    // The send flow
    flow_title, to_label, to_placeholder, to_code, to_code_hint, to_none_contacts, to_off,
    a11y_to, files_label, files_choose, files_add, files_drop, files_none, files_count,
    file_remove, a11y_file_remove, more_options, send, close, cancel,
    err_recipient, err_files, err_folder, err_contact_off,
    result_contact, result_code, st_waiting, st_sending, st_done, st_failed, st_failed_why,
    show_in_files, show_in_contacts, send_more, drop_overlay,
    // The conversation header and menu
    a11y_menu, menu_receipts, menu_verify, verify_title, verify_body, verify_close,
    header_waiting, header_relay, unverified_short,
    // Easy mode: the same state without the word "relay".
    header_relay_easy,
}

pub fn compose_strings(locale: Locale) -> &'static ComposeStrings {
    match locale {
        Locale::En => &CO_EN,
        Locale::Ja => &CO_JA,
        Locale::ZhCn => &CO_ZH_CN,
    }
}

static CO_EN: ComposeStrings = ComposeStrings {
    flow_title: "Send a file",
    to_label: "To",
    to_placeholder: "Choose who to send to",
    to_code: "Anyone, with an invitation code",
    to_code_hint: "You get an invitation code to hand to the person. With it, they can receive the file.",
    to_none_contacts: "You have no contacts yet. Add one under Contacts to send straight to a person.",
    to_off: "{name} (sending is off)",
    a11y_to: "Who to send to",
    files_label: "Files",
    files_choose: "Choose files...",
    files_add: "Add more files...",
    files_drop: "You can also drop files anywhere in this window.",
    files_none: "No files chosen yet.",
    files_count: "{n} files",
    file_remove: "Remove",
    a11y_file_remove: "Remove {name} from the list",
    more_options: "More options",
    send: "Send",
    close: "Close",
    cancel: "Cancel",
    err_recipient: "Choose who to send to.",
    err_files: "Choose at least one file.",
    err_folder: "Folders cannot be sent. Choose the files inside instead.",
    err_contact_off: "Sending to {name} is turned off under Contacts.",
    result_contact: "Sending to {name}",
    result_code: "Started. Give the invitation code to the person who should get the file.",
    st_waiting: "Waiting",
    st_sending: "Sending {pct}",
    st_done: "Sent",
    st_failed: "Failed",
    st_failed_why: "Failed: {why}",
    show_in_files: "Show in Files",
    show_in_contacts: "Show in Contacts",
    send_more: "Send more files",
    drop_overlay: "Drop files to send",
    a11y_menu: "More options for this conversation",
    menu_receipts: "Read receipts",
    menu_verify: "Verify contact",
    verify_title: "Verify {name}",
    verify_body: "Ask {name}, in person or by phone, to read out their own verification code. It should match this one:",
    verify_close: "Close",
    header_waiting: "Waiting for them to receive",
    header_relay: "This computer is not connected to the relay",
    unverified_short: "{u} not in your contacts yet",
    header_relay_easy: "Miasma is not connected right now",
};

static CO_JA: ComposeStrings = ComposeStrings {
    flow_title: "ファイルを送る",
    to_label: "送り先",
    to_placeholder: "送り先を選んでください",
    to_code: "招待コードで誰にでも送る",
    to_code_hint: "相手に渡す招待コードができます。このコードでファイルを受け取れます。",
    to_none_contacts: "まだ連絡先がありません。「連絡先」で追加すると、相手に直接送れます。",
    to_off: "{name}（送信オフ）",
    a11y_to: "送り先の選択",
    files_label: "ファイル",
    files_choose: "ファイルを選ぶ...",
    files_add: "ファイルを追加...",
    files_drop: "ウィンドウのどこにでもファイルをドロップできます。",
    files_none: "ファイルはまだ選ばれていません。",
    files_count: "{n}個のファイル",
    file_remove: "外す",
    a11y_file_remove: "{name} を一覧から外す",
    more_options: "その他の設定",
    send: "送信",
    close: "閉じる",
    cancel: "キャンセル",
    err_recipient: "送り先を選んでください。",
    err_files: "ファイルを1つ以上選んでください。",
    err_folder: "フォルダは送れません。中のファイルを選んでください。",
    err_contact_off: "{name} への送信は「連絡先」でオフになっています。",
    result_contact: "{name} に送信中",
    result_code: "送信を始めました。ファイルを渡したい相手に招待コードを伝えてください。",
    st_waiting: "待機中",
    st_sending: "送信中 {pct}",
    st_done: "送信済み",
    st_failed: "失敗",
    st_failed_why: "失敗：{why}",
    show_in_files: "「ファイル」で見る",
    show_in_contacts: "「連絡先」で見る",
    send_more: "続けてファイルを送る",
    drop_overlay: "ここにドロップして送信",
    a11y_menu: "この会話のその他の操作",
    menu_receipts: "既読表示",
    menu_verify: "連絡先を確認する",
    verify_title: "{name}さんを確認",
    verify_body: "{name}さんに会うか電話で相手自身の確認用コードを読み上げてもらってください。次のコードと同じなら、本人です。",
    verify_close: "閉じる",
    header_waiting: "相手の受信を待っています",
    header_relay: "このコンピューターはリレーに接続されていません",
    unverified_short: "連絡先に未登録：{u}人",
    header_relay_easy: "いまMiasmaはつながっていません",
};

static CO_ZH_CN: ComposeStrings = ComposeStrings {
    flow_title: "发送文件",
    to_label: "发送给",
    to_placeholder: "请选择发送对象",
    to_code: "任何人（使用邀请码）",
    to_code_hint: "你会得到一个邀请码，把它交给对方，对方就能接收文件。",
    to_none_contacts: "你还没有联系人。在“联系人”中添加后，就可以直接发给对方。",
    to_off: "{name}（已关闭发送）",
    a11y_to: "选择发送对象",
    files_label: "文件",
    files_choose: "选择文件...",
    files_add: "添加更多文件...",
    files_drop: "也可以把文件拖放到窗口的任意位置。",
    files_none: "尚未选择文件。",
    files_count: "{n} 个文件",
    file_remove: "移除",
    a11y_file_remove: "从列表中移除 {name}",
    more_options: "更多选项",
    send: "发送",
    close: "关闭",
    cancel: "取消",
    err_recipient: "请选择发送对象。",
    err_files: "请至少选择一个文件。",
    err_folder: "无法发送文件夹，请改为选择其中的文件。",
    err_contact_off: "已在“联系人”中关闭向 {name} 发送。",
    result_contact: "正在发送给 {name}",
    result_code: "已开始发送。请把邀请码交给要接收文件的人。",
    st_waiting: "等待中",
    st_sending: "发送中 {pct}",
    st_done: "已发送",
    st_failed: "失败",
    st_failed_why: "失败：{why}",
    show_in_files: "在“文件”中查看",
    show_in_contacts: "在“联系人”中查看",
    send_more: "继续发送文件",
    drop_overlay: "将文件拖放到此处发送",
    a11y_menu: "此会话的更多选项",
    menu_receipts: "已读回执",
    menu_verify: "验证联系人",
    verify_title: "验证 {name}",
    verify_body: "请当面或通过电话，让 {name} 读出其自己的安全码。它应与下面的安全码一致：",
    verify_close: "关闭",
    header_waiting: "正在等待对方接收",
    header_relay: "本机未连接到中继服务器",
    unverified_short: "{u} 人不在你的联系人中",
    header_relay_easy: "Miasma 当前未连接",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_compose_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            for (name, value) in compose_strings(lang).all() {
                assert!(!value.trim().is_empty(), "{lang:?} compose.{name} is empty");
            }
        }
    }

    #[test]
    fn zh_cn_compose_texts_match_the_english_ones() {
        crate::locale::assert_translation_parity(
            "compose",
            compose_strings(Locale::En).all(),
            compose_strings(Locale::ZhCn).all(),
        );
    }

    #[test]
    fn japanese_has_no_english_leftovers() {
        let ja = compose_strings(Locale::Ja);
        for (name, value) in ja.all() {
            assert!(
                !value.is_ascii(),
                "ja compose.{name} is ASCII only: {value:?}"
            );
        }
    }

    #[test]
    fn compose_placeholders_survive_translation() {
        for lang in Locale::ALL {
            let k = compose_strings(lang);
            for (name, value, holes) in [
                ("to_off", k.to_off, &["{name}"][..]),
                ("files_count", k.files_count, &["{n}"]),
                ("a11y_file_remove", k.a11y_file_remove, &["{name}"]),
                ("err_contact_off", k.err_contact_off, &["{name}"]),
                ("result_contact", k.result_contact, &["{name}"]),
                ("st_sending", k.st_sending, &["{pct}"]),
                ("st_failed_why", k.st_failed_why, &["{why}"]),
                ("verify_title", k.verify_title, &["{name}"]),
                ("verify_body", k.verify_body, &["{name}"]),
                ("unverified_short", k.unverified_short, &["{u}"]),
            ] {
                for hole in holes {
                    assert!(value.contains(hole), "{lang:?} compose.{name} lost {hole}");
                }
            }
        }
    }

    #[test]
    fn no_emoji_in_any_compose_string() {
        for lang in Locale::ALL {
            for (name, value) in compose_strings(lang).all() {
                for ch in value.chars() {
                    assert!(
                        (ch as u32) < 0x1F000 && !('\u{2600}'..='\u{27BF}').contains(&ch),
                        "{lang:?} compose.{name} has an emoji"
                    );
                }
            }
        }
    }
}
