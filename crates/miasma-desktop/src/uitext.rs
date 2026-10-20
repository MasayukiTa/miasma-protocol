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

/// Calendar date (year, month 1-12, day 1-31) of a day count since 1970-01-01 (proleptic
/// Gregorian; the days-from-civil inverse by H. Hinnant). No time-zone database is needed.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// "Oct 20, 2026 14:05 UTC", "2026年10月20日 14:05 UTC": the date and time in the language's
/// order, always in UTC (the window has no time-zone database, and a stated zone is better
/// than a silent guess). `0` means the daemon did not know the time.
pub fn absolute_time(l: Locale, epoch_secs: u64) -> String {
    if epoch_secs == 0 {
        return pick(l, "unknown", "不明", "未知").to_owned();
    }
    let (y, m, d) = civil_from_days((epoch_secs / 86_400) as i64);
    let rem = epoch_secs % 86_400;
    let (hh, mm) = (rem / 3_600, rem % 3_600 / 60);
    let zone = crate::locale::settings_strings(l).utc;
    match l {
        Locale::En => {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            format!(
                "{} {d}, {y} {hh:02}:{mm:02} {zone}",
                MONTHS[(m - 1) as usize]
            )
        }
        Locale::Ja | Locale::ZhCn => format!("{y}年{m}月{d}日 {hh:02}:{mm:02} {zone}"),
    }
}

/// Relative and absolute time together: "3d ago (Oct 17, 2026 14:05 UTC)".
pub fn relative_and_absolute(l: Locale, epoch_secs: u64, now: u64) -> String {
    if epoch_secs == 0 {
        return relative_time(l, epoch_secs, now);
    }
    format!(
        "{} ({})",
        relative_time(l, epoch_secs, now),
        absolute_time(l, epoch_secs)
    )
}

/// The sender shown for an envelope in the old format, which carries none.
pub fn unknown_sender(l: Locale) -> &'static str {
    pick(
        l,
        "Unknown sender (old format)",
        "送信者不明（旧形式）",
        "发送者未知（旧格式）",
    )
}

/// When an envelope expires, with the direction in words: "expired 196d ago", "in 3d". The
/// plain relative form ("196d ago") after the label "Expires:" reads as if the expiry were
/// still to come.
pub fn expiry_text(l: Locale, epoch_secs: u64, now: u64) -> String {
    if epoch_secs == 0 {
        return relative_time(l, 0, now);
    }
    let rel = relative_time(l, epoch_secs, now);
    if epoch_secs > now {
        return match l {
            Locale::Ja => format!("{}に期限", rel.trim_end_matches('後').to_owned() + "後"),
            _ => rel,
        };
    }
    match l {
        Locale::En => format!("expired {rel}"),
        Locale::Ja => format!("{rel}に期限切れ"),
        Locale::ZhCn => format!("{rel}已过期"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_times_are_written_in_the_languages_order() {
        // 2026-10-20 14:05:00 UTC, the epoch, a leap day and a year end.
        assert_eq!(
            absolute_time(Locale::En, 1_792_505_100),
            "Oct 20, 2026 14:05 UTC"
        );
        assert_eq!(
            absolute_time(Locale::Ja, 1_792_505_100),
            "2026年10月20日 14:05 UTC"
        );
        assert_eq!(
            absolute_time(Locale::ZhCn, 1_792_505_100),
            "2026年10月20日 14:05 UTC"
        );
        assert_eq!(absolute_time(Locale::En, 1), "Jan 1, 1970 00:00 UTC");
        assert_eq!(
            absolute_time(Locale::En, 951_782_400 + 3_600),
            "Feb 29, 2000 01:00 UTC"
        );
        assert_eq!(
            absolute_time(Locale::En, 1_735_689_599),
            "Dec 31, 2024 23:59 UTC"
        );
        assert_eq!(absolute_time(Locale::Ja, 0), "不明");
    }

    #[test]
    fn relative_and_absolute_keep_both() {
        let now = 1_792_505_100 + 3 * 86_400;
        assert_eq!(
            relative_and_absolute(Locale::En, 1_792_505_100, now),
            "3d ago (Oct 20, 2026 14:05 UTC)"
        );
        assert_eq!(relative_and_absolute(Locale::En, 0, now), "unknown");
    }

    #[test]
    fn an_expiry_in_the_past_says_so() {
        let now = 1_000_000_000;
        assert_eq!(
            expiry_text(Locale::En, now - 196 * 86400, now),
            "expired 196d ago"
        );
        assert_eq!(
            expiry_text(Locale::Ja, now - 196 * 86400, now),
            "196日前に期限切れ"
        );
        assert!(expiry_text(Locale::ZhCn, now - 196 * 86400, now).contains("已过期"));
        assert_eq!(expiry_text(Locale::En, now + 3 * 86400, now), "in 3d");
        assert_eq!(expiry_text(Locale::Ja, now + 3 * 86400, now), "3日後に期限");
        assert_eq!(expiry_text(Locale::En, 0, now), "unknown");
        for l in Locale::ALL {
            assert!(!unknown_sender(l).is_empty());
        }
    }

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
