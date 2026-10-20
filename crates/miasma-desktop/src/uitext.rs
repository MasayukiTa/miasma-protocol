//! Small labels that were fixed English strings in the window: envelope times, the relative-time
//! words, the transport state words and a few captions. One function per label, all three
//! languages next to each other, so a missing language is a compile error.

use crate::locale::Locale;

fn pick(locale: Locale, en: &'static str, ja: &'static str, zh: &'static str) -> &'static str {
    match locale {
        Locale::En => en,
        Locale::Ja => ja,
        Locale::ZhCn => zh,
    }
}

pub fn created_label(l: Locale) -> &'static str {
    pick(l, "Created:", "作成:", "创建时间：")
}

pub fn expires_label(l: Locale) -> &'static str {
    pick(l, "Expires:", "期限:", "到期时间：")
}

pub fn envelope_id_label(l: Locale) -> &'static str {
    pick(l, "Envelope ID:", "送付ID:", "信封 ID：")
}

pub fn text_files_filter(l: Locale) -> &'static str {
    pick(l, "Text files", "テキストファイル", "文本文件")
}

pub fn replicated(l: Locale, n: u64) -> String {
    match l {
        Locale::En => format!("{n} replicated"),
        Locale::Ja => format!("{n}件を複製済み"),
        Locale::ZhCn => format!("已复制 {n} 个"),
    }
}

/// State of a transport in the status panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Active,
    Ready,
    Degraded,
    Failing,
    Idle,
}

pub fn transport_state(l: Locale, s: TransportState) -> &'static str {
    match s {
        TransportState::Active => pick(l, "Active", "動作中", "使用中"),
        TransportState::Ready => pick(l, "Ready", "準備完了", "就绪"),
        TransportState::Degraded => pick(l, "Degraded", "低下", "性能下降"),
        TransportState::Failing => pick(l, "Failing", "障害", "故障"),
        TransportState::Idle => pick(l, "Idle", "待機中", "空闲"),
    }
}

/// "3 hours ago", "in 2 days": `epoch_secs` against `now`, in the UI language.
/// `0` means the daemon did not know the time.
pub fn relative_time(l: Locale, epoch_secs: u64, now: u64) -> String {
    if epoch_secs == 0 {
        return pick(l, "unknown", "不明", "未知").to_owned();
    }
    let (diff, future) = if epoch_secs > now {
        (epoch_secs - now, true)
    } else {
        (now - epoch_secs, false)
    };
    if !future && diff < 60 {
        return pick(l, "just now", "たった今", "刚刚").to_owned();
    }
    let (n, unit) = if diff < 3600 {
        (diff / 60, 0)
    } else if diff < 86400 {
        (diff / 3600, 1)
    } else {
        (diff / 86400, 2)
    };
    match (l, future) {
        (Locale::En, true) => format!("in {n}{}", ["m", "h", "d"][unit]),
        (Locale::En, false) => format!("{n}{} ago", ["m", "h", "d"][unit]),
        (Locale::Ja, true) => format!("{n}{}後", ["分", "時間", "日"][unit]),
        (Locale::Ja, false) => format!("{n}{}前", ["分", "時間", "日"][unit]),
        (Locale::ZhCn, true) => format!("{n} {}后", ["分钟", "小时", "天"][unit]),
        (Locale::ZhCn, false) => format!("{n} {}前", ["分钟", "小时", "天"][unit]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_is_filled_in_every_language() {
        for l in Locale::ALL {
            for t in [
                created_label(l),
                expires_label(l),
                envelope_id_label(l),
                text_files_filter(l),
            ] {
                assert!(!t.is_empty());
            }
            assert!(!replicated(l, 3).is_empty());
            for s in [
                TransportState::Active,
                TransportState::Ready,
                TransportState::Degraded,
                TransportState::Failing,
                TransportState::Idle,
            ] {
                assert!(!transport_state(l, s).is_empty());
            }
        }
    }

    #[test]
    fn relative_time_follows_the_language() {
        let now = 1_000_000;
        let cases = [
            (Locale::En, now - 30, "just now"),
            (Locale::En, now - 120, "2m ago"),
            (Locale::En, now + 7200, "in 2h"),
            (Locale::En, 0, "unknown"),
            (Locale::Ja, now - 30, "たった今"),
            (Locale::Ja, now - 3 * 3600, "3時間前"),
            (Locale::Ja, now + 2 * 86400, "2日後"),
            (Locale::Ja, 0, "不明"),
            (Locale::ZhCn, now - 5 * 60, "5 分钟前"),
            (Locale::ZhCn, now + 3600, "1 小时后"),
        ];
        for (l, t, want) in cases {
            assert_eq!(relative_time(l, t, now), want, "{l:?} {t}");
        }
    }
}
