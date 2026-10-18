//! Speed as text, shared by the desktop and the CLI.
//!
//! Three units, so a user can match whatever they compare with:
//! - bits: decimal SI (1 Mbps = 1 000 000 bit/s), like a speed-test site;
//! - MB/s: decimal bytes (1 MB/s = 1 000 000 byte/s), like macOS Finder and ISPs;
//! - MiB/s: binary bytes (1 MiB/s = 1 048 576 byte/s), like the Windows
//!   Explorer figure that is labelled MB/s.
//!
//! Every figure has one decimal below 10 and none from 10 up. The default text
//! is `42 Mbps (5.2 MB/s / 5.0 MiB/s)`; narrow places use [`format_narrow`]:
//! `42 Mbps (5.0 MiB/s)`.

use serde::{Deserialize, Serialize};

/// `ui.speed_unit`: which unit leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedUnit {
    #[default]
    Bits,
    Bytes,
}

impl SpeedUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bits => "bits",
            Self::Bytes => "bytes",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bits" | "bit" => Some(Self::Bits),
            "bytes" | "byte" => Some(Self::Bytes),
            _ => None,
        }
    }
}

/// `ui.speed_units_shown`: which units appear at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedShown {
    #[default]
    Both,
    BitsOnly,
    BytesOnly,
}

impl SpeedShown {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::BitsOnly => "bits_only",
            Self::BytesOnly => "bytes_only",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "both" => Some(Self::Both),
            "bits_only" => Some(Self::BitsOnly),
            "bytes_only" => Some(Self::BytesOnly),
            _ => None,
        }
    }
}

/// One decimal below 10, none from 10 up.
fn figure(v: f64) -> String {
    if v < 9.95 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

/// `value` in the first of `units` (each `step` times the one before) whose
/// rounded figure stays below `step` (so 999.9 Kbps reads `1.0 Mbps`, never
/// `1000 Kbps`).
fn scaled(value: f64, step: f64, units: &[&str]) -> String {
    let mut v = value;
    let mut i = 0;
    // The base unit (bps, B/s) is a whole number; the figure that would be
    // printed decides the rollover, not the raw value.
    let shown = |v: f64, i: usize| if i == 0 { format!("{v:.0}") } else { figure(v) };
    while i + 1 < units.len() && shown(v, i).parse::<f64>().unwrap_or(0.0) >= step {
        v /= step;
        i += 1;
    }
    format!("{} {}", shown(v, i), units[i])
}

/// Decimal SI bits: `500 bps`, `950 Kbps`, `98 Mbps`, `1.2 Gbps`.
pub fn format_bits(bits_per_s: u64) -> String {
    scaled(
        bits_per_s as f64,
        1000.0,
        &["bps", "Kbps", "Mbps", "Gbps", "Tbps"],
    )
}

/// Decimal bytes: `12 KB/s`, `5.2 MB/s`, `1.1 GB/s`.
pub fn format_mb_s(bits_per_s: u64) -> String {
    scaled(
        bits_per_s as f64 / 8.0,
        1000.0,
        &["B/s", "KB/s", "MB/s", "GB/s", "TB/s"],
    )
}

/// Binary bytes: `12 KiB/s`, `5.0 MiB/s`, `1.1 GiB/s`.
pub fn format_mib_s(bits_per_s: u64) -> String {
    scaled(
        bits_per_s as f64 / 8.0,
        1024.0,
        &["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"],
    )
}

/// Both byte units: `5.2 MB/s / 5.0 MiB/s`.
fn bytes_both(bits_per_s: u64) -> String {
    format!("{} / {}", format_mb_s(bits_per_s), format_mib_s(bits_per_s))
}

fn lead_and_rest(lead: String, rest: String) -> String {
    format!("{lead} ({rest})")
}

/// The full text: `42 Mbps (5.2 MB/s / 5.0 MiB/s)`; with `Bytes` leading:
/// `5.2 MB/s / 5.0 MiB/s (42 Mbps)`.
pub fn format_speed(bits_per_s: u64, unit: SpeedUnit, shown: SpeedShown) -> String {
    match shown {
        SpeedShown::BitsOnly => format_bits(bits_per_s),
        SpeedShown::BytesOnly => bytes_both(bits_per_s),
        SpeedShown::Both => match unit {
            SpeedUnit::Bits => lead_and_rest(format_bits(bits_per_s), bytes_both(bits_per_s)),
            SpeedUnit::Bytes => lead_and_rest(bytes_both(bits_per_s), format_bits(bits_per_s)),
        },
    }
}

/// For narrow places (a sparkline label, a narrow header): one line, one byte
/// unit: `42 Mbps (5.0 MiB/s)`.
pub fn format_narrow(bits_per_s: u64, unit: SpeedUnit, shown: SpeedShown) -> String {
    match shown {
        SpeedShown::BitsOnly => format_bits(bits_per_s),
        SpeedShown::BytesOnly => format_mib_s(bits_per_s),
        SpeedShown::Both => match unit {
            SpeedUnit::Bits => lead_and_rest(format_bits(bits_per_s), format_mib_s(bits_per_s)),
            SpeedUnit::Bytes => lead_and_rest(format_mib_s(bits_per_s), format_bits(bits_per_s)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_boundaries() {
        assert_eq!(format_bits(0), "0 bps");
        assert_eq!(format_bits(500), "500 bps");
        assert_eq!(format_bits(999), "999 bps");
        assert_eq!(format_bits(1_000), "1.0 Kbps");
        assert_eq!(format_bits(9_940), "9.9 Kbps");
        assert_eq!(format_bits(10_000), "10 Kbps");
        assert_eq!(format_bits(999_000), "999 Kbps");
        // 999 999 bit/s rounds to 1000 Kbps and must roll over to Mbps.
        assert_eq!(format_bits(999_999), "1.0 Mbps");
        assert_eq!(format_bits(1_000_000), "1.0 Mbps");
        assert_eq!(format_bits(1_500_000), "1.5 Mbps");
        assert_eq!(format_bits(9_949_000), "9.9 Mbps");
        assert_eq!(format_bits(10_000_000), "10 Mbps");
        assert_eq!(format_bits(98_000_000), "98 Mbps");
        assert_eq!(format_bits(999_400_000), "999 Mbps");
        assert_eq!(format_bits(999_999_999), "1.0 Gbps");
        assert_eq!(format_bits(2_500_000_000), "2.5 Gbps");
        assert_eq!(format_bits(12_000_000_000), "12 Gbps");
    }

    #[test]
    fn byte_units_start_at_bytes_per_second() {
        assert_eq!(format_mb_s(800), "100 B/s");
        assert_eq!(format_mib_s(0), "0 B/s");
        assert_eq!(format_mb_s(8 * 999), "999 B/s");
        assert_eq!(format_mb_s(8 * 1000), "1.0 KB/s");
    }

    #[test]
    fn decimal_byte_boundaries() {
        // 1 000 000 byte/s = 8 Mbps = exactly 1.0 MB/s.
        assert_eq!(format_mb_s(8_000_000), "1.0 MB/s");
        assert_eq!(format_mb_s(8_000), "1.0 KB/s");
        // 999 999 byte/s rolls over to MB/s.
        assert_eq!(format_mb_s(8 * 999_999), "1.0 MB/s");
        assert_eq!(format_mb_s(8 * 999_000), "999 KB/s");
        assert_eq!(format_mb_s(8 * 1_000_000_000), "1.0 GB/s");
        assert_eq!(format_mb_s(8 * 12_340_000), "12 MB/s");
    }

    #[test]
    fn binary_byte_boundaries() {
        // 1 048 576 byte/s = exactly 1.0 MiB/s (8.388608 Mbps).
        assert_eq!(format_mib_s(8 * 1_048_576), "1.0 MiB/s");
        assert_eq!(format_bits(8 * 1_048_576), "8.4 Mbps");
        // 1 000 000 byte/s is still below one MiB/s.
        assert_eq!(format_mib_s(8 * 1_000_000), "977 KiB/s");
        // 1 048 575 byte/s (1023.999 KiB/s) rolls over to MiB/s.
        assert_eq!(format_mib_s(8 * 1_048_575), "1.0 MiB/s");
        assert_eq!(format_mib_s(8 * 1024), "1.0 KiB/s");
        assert_eq!(format_mib_s(8 * 1_073_741_824), "1.0 GiB/s");
        assert_eq!(format_mib_s(8 * 12_000_000), "11 MiB/s");
    }

    #[test]
    fn the_three_units_of_one_rate() {
        // 5 MiB/s = 5 242 880 byte/s = 41 943 040 bit/s.
        let bits = 41_943_040;
        assert_eq!(
            format_speed(bits, SpeedUnit::Bits, SpeedShown::Both),
            "42 Mbps (5.2 MB/s / 5.0 MiB/s)"
        );
        assert_eq!(
            format_speed(bits, SpeedUnit::Bytes, SpeedShown::Both),
            "5.2 MB/s / 5.0 MiB/s (42 Mbps)"
        );
        assert_eq!(
            format_speed(bits, SpeedUnit::Bits, SpeedShown::BitsOnly),
            "42 Mbps"
        );
        assert_eq!(
            format_speed(bits, SpeedUnit::Bits, SpeedShown::BytesOnly),
            "5.2 MB/s / 5.0 MiB/s"
        );
        // 1 MB/s (decimal) and 1 MiB/s (binary) differ by 4.9%.
        assert_eq!(
            format_speed(8_000_000, SpeedUnit::Bits, SpeedShown::Both),
            "8.0 Mbps (1.0 MB/s / 977 KiB/s)"
        );
    }

    #[test]
    fn narrow_text_is_one_short_line() {
        let bits = 41_943_040;
        assert_eq!(
            format_narrow(bits, SpeedUnit::Bits, SpeedShown::Both),
            "42 Mbps (5.0 MiB/s)"
        );
        assert_eq!(
            format_narrow(bits, SpeedUnit::Bytes, SpeedShown::Both),
            "5.0 MiB/s (42 Mbps)"
        );
        assert_eq!(
            format_narrow(bits, SpeedUnit::Bits, SpeedShown::BitsOnly),
            "42 Mbps"
        );
        assert_eq!(
            format_narrow(bits, SpeedUnit::Bits, SpeedShown::BytesOnly),
            "5.0 MiB/s"
        );
    }

    #[test]
    fn setting_names() {
        assert_eq!(SpeedUnit::default(), SpeedUnit::Bits);
        assert_eq!(SpeedShown::default(), SpeedShown::Both);
        assert_eq!(SpeedUnit::parse("Bytes"), Some(SpeedUnit::Bytes));
        assert_eq!(SpeedUnit::parse("kb"), None);
        for s in [
            SpeedShown::Both,
            SpeedShown::BitsOnly,
            SpeedShown::BytesOnly,
        ] {
            assert_eq!(SpeedShown::parse(s.as_str()), Some(s));
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.as_str())
            );
        }
        assert_eq!(SpeedShown::parse("x"), None);
    }
}
