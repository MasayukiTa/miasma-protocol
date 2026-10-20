//! Strings added for the interface audit: the short reason shown next to a disabled main button,
//! the accessible names of text fields, the contact QR dialog, the header state chip and the
//! scope line of the stored-shares confirmation.
//!
//! Kept in its own file, like `compose.rs`, so the sentences stay together and are checked
//! together (the parity test at the bottom). `{name}`-style holes are filled with
//! `transfers::fill`.

use super::Locale;

macro_rules! audit_strings {
    ($($f:ident),* $(,)?) => {
        /// One table per language.
        pub struct AuditStrings { $(pub $f: &'static str),* }
        impl AuditStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

audit_strings! {
    // Why the main button is off.
    need_text, need_mid, need_code, need_share_id, need_folder, need_file, need_contact,
    need_password, need_connection,
    // Accessible names of fields.
    a11y_store_text, a11y_store_id, a11y_get_id, a11y_send_contact, a11y_password,
    a11y_password_repeat, a11y_retention, a11y_file_password, a11y_check_code, a11y_days,
    a11y_recv_id, a11y_recv_path, a11y_via, a11y_send_path, a11y_my_code, a11y_add_code,
    a11y_add_label, a11y_rename, a11y_max_size, a11y_relay_new, a11y_retry_hours,
    a11y_resume_password,
    // The contact QR dialog.
    qr_title, qr_close, a11y_qr,
    // The state chip in the header.
    chip_ready, chip_waiting,
    // The first line of the stored-shares confirmation.
    storage_scope_all, storage_scope_ids, storage_scope_days,
}

pub fn audit_strings(locale: Locale) -> &'static AuditStrings {
    match locale {
        Locale::En => &AU_EN,
        Locale::Ja => &AU_JA,
        Locale::ZhCn => &AU_ZH_CN,
    }
}

static AU_EN: AuditStrings = AuditStrings {
    need_text: "Type or paste the text first.",
    need_mid: "Enter the content ID first.",
    need_code: "Enter the code first.",
    need_share_id: "Enter the Share ID first.",
    need_folder: "Choose where to save it first.",
    need_file: "Choose a file first.",
    need_contact: "Enter the contact code first.",
    need_password: "Enter a password first.",
    need_connection: "Not connected to the background service yet.",
    a11y_store_text: "Text to store",
    a11y_store_id: "Content ID of the stored content",
    a11y_get_id: "Content ID to get back",
    a11y_send_contact: "Contact code of the recipient",
    a11y_password: "Password",
    a11y_password_repeat: "Repeat the password",
    a11y_retention: "How long to keep it",
    a11y_file_password: "Password for this file",
    a11y_check_code: "Check code",
    a11y_days: "Delete shares older than this many days",
    a11y_recv_id: "Share ID or invitation code",
    a11y_recv_path: "Folder to save to",
    a11y_via: "Address to fetch from",
    a11y_send_path: "File to send",
    a11y_my_code: "Your contact code",
    a11y_add_code: "Contact code or invitation text of the person to add",
    a11y_add_label: "Name for the new contact",
    a11y_rename: "Rename {name}",
    a11y_max_size: "Largest file to accept from {name}",
    a11y_relay_new: "Relay address to add",
    a11y_retry_hours: "Retry for this many hours",
    a11y_resume_password: "Password to continue",
    qr_title: "Your contact QR code",
    qr_close: "Close",
    a11y_qr: "QR code of your contact code",
    chip_ready: "Ready",
    chip_waiting: "Waiting for the network",
    storage_scope_all: "This deletes all {n} stored shares.",
    storage_scope_ids: "This deletes {n} selected shares.",
    storage_scope_days: "This deletes the shares older than {n} days.",
};

static AU_JA: AuditStrings = AuditStrings {
    need_text: "先にテキストを入力してください。",
    need_mid: "先にコンテンツIDを入力してください。",
    need_code: "先にコードを入力してください。",
    need_share_id: "先に共有IDを入力してください。",
    need_folder: "先に保存先のフォルダーを選んでください。",
    need_file: "先にファイルを選んでください。",
    need_contact: "先に連絡先コードを入力してください。",
    need_password: "先にパスワードを入力してください。",
    need_connection: "まだバックグラウンドサービスに接続していません。",
    a11y_store_text: "保存するテキスト",
    a11y_store_id: "保存した内容のコンテンツID",
    a11y_get_id: "取得するコンテンツID",
    a11y_send_contact: "送信先の連絡先コード",
    a11y_password: "パスワード",
    a11y_password_repeat: "パスワードをもう一度入力",
    a11y_retention: "保持する期間",
    a11y_file_password: "このファイルのパスワード",
    a11y_check_code: "確認コード",
    a11y_days: "この日数より古い共有を削除",
    a11y_recv_id: "共有IDまたは招待コード",
    a11y_recv_path: "保存先のフォルダー",
    a11y_via: "取得元のアドレス",
    a11y_send_path: "送るファイル",
    a11y_my_code: "あなたの連絡先コード",
    a11y_add_code: "追加する相手の連絡先コードまたは招待メッセージ",
    a11y_add_label: "新しい連絡先の名前",
    a11y_rename: "{name}の名前を変更",
    a11y_max_size: "{name}から受け取るファイルの最大サイズ",
    a11y_relay_new: "追加する中継サーバーのアドレス",
    a11y_retry_hours: "再試行する時間数",
    a11y_resume_password: "再開用のパスワード",
    qr_title: "あなたの連絡先のQRコード",
    qr_close: "閉じる",
    a11y_qr: "あなたの連絡先コードのQRコード",
    chip_ready: "準備完了",
    chip_waiting: "ネットワークを待っています",
    storage_scope_all: "保存している共有{n}件をすべて削除します。",
    storage_scope_ids: "選んだ共有{n}件を削除します。",
    storage_scope_days: "{n}日より古い共有を削除します。",
};

static AU_ZH_CN: AuditStrings = AuditStrings {
    need_text: "请先输入文本。",
    need_mid: "请先输入内容 ID。",
    need_code: "请先输入代码。",
    need_share_id: "请先输入共享 ID。",
    need_folder: "请先选择保存位置。",
    need_file: "请先选择文件。",
    need_contact: "请先输入联系人代码。",
    need_password: "请先输入密码。",
    need_connection: "尚未连接到后台服务。",
    a11y_store_text: "要存储的文本",
    a11y_store_id: "已存储内容的内容 ID",
    a11y_get_id: "要取回的内容 ID",
    a11y_send_contact: "接收者的联系人代码",
    a11y_password: "密码",
    a11y_password_repeat: "再次输入密码",
    a11y_retention: "保留多久",
    a11y_file_password: "此文件的密码",
    a11y_check_code: "验证码",
    a11y_days: "删除早于此天数的共享",
    a11y_recv_id: "共享 ID 或邀请码",
    a11y_recv_path: "保存到的文件夹",
    a11y_via: "获取来源地址",
    a11y_send_path: "要发送的文件",
    a11y_my_code: "你的联系人代码",
    a11y_add_code: "要添加的人的联系人代码或邀请消息",
    a11y_add_label: "新联系人的名称",
    a11y_rename: "重命名 {name}",
    a11y_max_size: "接收来自 {name} 的文件大小上限",
    a11y_relay_new: "要添加的中继服务器地址",
    a11y_retry_hours: "重试的小时数",
    a11y_resume_password: "继续传输所需的密码",
    qr_title: "你的联系人二维码",
    qr_close: "关闭",
    a11y_qr: "你的联系人代码的二维码",
    chip_ready: "已就绪",
    chip_waiting: "正在等待网络",
    storage_scope_all: "将删除全部 {n} 个已保存的共享。",
    storage_scope_ids: "将删除所选的 {n} 个共享。",
    storage_scope_days: "将删除早于 {n} 天的共享。",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_audit_string_exists_in_every_locale() {
        for lang in Locale::ALL {
            for (name, value) in audit_strings(lang).all() {
                assert!(!value.trim().is_empty(), "{lang:?} audit.{name} is empty");
            }
        }
    }

    #[test]
    fn zh_cn_audit_texts_match_the_english_ones() {
        crate::locale::assert_translation_parity(
            "audit",
            audit_strings(Locale::En).all(),
            audit_strings(Locale::ZhCn).all(),
        );
    }

    #[test]
    fn japanese_has_no_english_leftovers() {
        for (name, value) in audit_strings(Locale::Ja).all() {
            assert!(
                !value.is_ascii(),
                "ja audit.{name} is ASCII only: {value:?}"
            );
        }
    }

    #[test]
    fn audit_placeholders_survive_translation() {
        for lang in Locale::ALL {
            let a = audit_strings(lang);
            for (name, value, hole) in [
                ("a11y_rename", a.a11y_rename, "{name}"),
                ("a11y_max_size", a.a11y_max_size, "{name}"),
                ("storage_scope_all", a.storage_scope_all, "{n}"),
                ("storage_scope_ids", a.storage_scope_ids, "{n}"),
                ("storage_scope_days", a.storage_scope_days, "{n}"),
            ] {
                assert!(value.contains(hole), "{lang:?} audit.{name} lost {hole}");
            }
        }
    }

    #[test]
    fn reasons_are_short_plain_sentences() {
        for lang in Locale::ALL {
            let a = audit_strings(lang);
            let reasons = [
                a.need_text,
                a.need_mid,
                a.need_code,
                a.need_share_id,
                a.need_folder,
                a.need_file,
                a.need_contact,
                a.need_password,
                a.need_connection,
            ];
            for (i, value) in reasons.iter().enumerate() {
                let long = value.chars().count() > 48;
                assert!(
                    !long,
                    "{lang:?}: reason number {i} is longer than 48 characters"
                );
            }
        }
    }
}
