//! Duration and size values as written in the config file.
//!
//! - Durations: a whole number and a unit, `s`, `m`, `h` or `d` (`45s`, `10m`, `1h`, `7d`).
//! - Sizes: a whole number and a binary unit, `B`, `KiB`, `MiB`, `GiB` or `TiB` (`32MiB`), or a
//!   percentage (`5%`) that is resolved against a total (RAM or a volume) at startup.
//!
//! Zero is rejected everywhere: a zero duration or size is never a useful limit.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnitError {
    #[error("invalid duration \"{0}\": expected a whole number and s, m, h or d, e.g. \"10m\"")]
    Duration(String),
    #[error("invalid size \"{0}\": expected a whole number and B, KiB, MiB, GiB or TiB, e.g. \"32MiB\", or a percentage such as \"5%\"")]
    Size(String),
    #[error("invalid size \"{0}\": use binary units ({1})")]
    DecimalUnit(String, &'static str),
    #[error("invalid percentage \"{0}\": must be greater than 0 and at most 100")]
    Percent(String),
    #[error("\"{0}\" must be greater than zero")]
    Zero(String),
    #[error("\"{0}\" is too large")]
    Overflow(String),
}

/// Splits `"32 MiB"` into `("32", "MiB")`.
fn split_number(s: &str) -> (&str, &str) {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    (&s[..end], s[end..].trim())
}

// ─── Durations ──────────────────────────────────────────────────────────────

/// A positive duration with whole-second precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HumanDuration(Duration);

impl HumanDuration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub const fn get(self) -> Duration {
        self.0
    }
}

impl From<HumanDuration> for Duration {
    fn from(d: HumanDuration) -> Self {
        d.0
    }
}

impl FromStr for HumanDuration {
    type Err = UnitError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();
        let (digits, unit) = split_number(s);
        let multiplier = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            _ => return Err(UnitError::Duration(input.into())),
        };
        let value: u64 = digits
            .parse()
            .map_err(|_| UnitError::Duration(input.into()))?;
        if value == 0 {
            return Err(UnitError::Zero(input.into()));
        }
        let secs = value
            .checked_mul(multiplier)
            .ok_or_else(|| UnitError::Overflow(input.into()))?;
        Ok(Self::from_secs(secs))
    }
}

impl fmt::Display for HumanDuration {
    /// The largest unit that divides the value exactly: 90 s is `90s`, 600 s is `10m`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
            if secs.is_multiple_of(size) {
                return write!(f, "{}{unit}", secs / size);
            }
        }
        write!(f, "{secs}s")
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// `#[serde(with = "optional_duration")]` for `Option<HumanDuration>`, where `""` means none.
pub mod optional_duration {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<HumanDuration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(d) => serializer.collect_str(d),
            None => serializer.serialize_str(""),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<HumanDuration>, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.trim().is_empty() {
            return Ok(None);
        }
        s.parse().map(Some).map_err(de::Error::custom)
    }
}

// ─── Sizes ──────────────────────────────────────────────────────────────────

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
const TIB: u64 = 1 << 40;

/// A size limit: an absolute number of bytes, or a percentage of a total resolved at startup.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SizeLimit {
    Bytes(u64),
    /// Greater than 0, at most 100.
    Percent(f64),
}

impl SizeLimit {
    pub const fn mib(n: u64) -> Self {
        Self::Bytes(n * MIB)
    }

    /// Bytes for this limit given `total` bytes (RAM or volume size). A percentage is never resolved to 0.
    pub fn resolve(self, total: u64) -> u64 {
        match self {
            SizeLimit::Bytes(b) => b,
            SizeLimit::Percent(p) => ((total as f64 * p / 100.0).round() as u64).max(1),
        }
    }

    pub fn is_percent(self) -> bool {
        matches!(self, SizeLimit::Percent(_))
    }
}

impl FromStr for SizeLimit {
    type Err = UnitError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();
        if let Some(number) = s.strip_suffix('%') {
            let p: f64 = number
                .trim()
                .parse()
                .map_err(|_| UnitError::Percent(input.into()))?;
            if !(p > 0.0 && p <= 100.0) {
                return Err(UnitError::Percent(input.into()));
            }
            return Ok(SizeLimit::Percent(p));
        }

        let (digits, unit) = split_number(s);
        let multiplier = match unit.to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "kib" => KIB,
            "mib" => MIB,
            "gib" => GIB,
            "tib" => TIB,
            "k" | "kb" => return Err(UnitError::DecimalUnit(input.into(), "KiB")),
            "m" | "mb" => return Err(UnitError::DecimalUnit(input.into(), "MiB")),
            "g" | "gb" => return Err(UnitError::DecimalUnit(input.into(), "GiB")),
            "t" | "tb" => return Err(UnitError::DecimalUnit(input.into(), "TiB")),
            _ => return Err(UnitError::Size(input.into())),
        };
        let value: u64 = digits.parse().map_err(|_| UnitError::Size(input.into()))?;
        if value == 0 {
            return Err(UnitError::Zero(input.into()));
        }
        value
            .checked_mul(multiplier)
            .map(SizeLimit::Bytes)
            .ok_or_else(|| UnitError::Overflow(input.into()))
    }
}

impl fmt::Display for SizeLimit {
    /// Bytes in the largest unit that divides them exactly (`32MiB`); percentages as written (`5%`, `0.5%`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SizeLimit::Percent(p) => write!(f, "{p}%"),
            SizeLimit::Bytes(b) => {
                for (unit, size) in [("TiB", TIB), ("GiB", GIB), ("MiB", MIB), ("KiB", KIB)] {
                    if b.is_multiple_of(size) {
                        return write!(f, "{}{unit}", b / size);
                    }
                }
                write!(f, "{b}B")
            }
        }
    }
}

impl Serialize for SizeLimit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SizeLimit {
    /// Accepts a string (`"32MiB"`, `"5%"`) or a plain integer number of bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = SizeLimit;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a size such as \"32MiB\" or a percentage such as \"5%\"")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<SizeLimit, E> {
                v.parse().map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<SizeLimit, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<SizeLimit, E> {
                v.to_string().parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Approximate, human-readable bytes for logs: `31.6 GiB`, `512 KiB`, `100 B`.
pub fn human_bytes(bytes: u64) -> String {
    for (unit, size) in [("TiB", TIB), ("GiB", GIB), ("MiB", MIB), ("KiB", KIB)] {
        if bytes >= size {
            let value = bytes as f64 / size as f64;
            return if value.fract() == 0.0 {
                format!("{value:.0} {unit}")
            } else {
                format!("{value:.1} {unit}")
            };
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dur(s: &str) -> Result<u64, UnitError> {
        s.parse::<HumanDuration>().map(|d| d.get().as_secs())
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct Sample {
        window: HumanDuration,
        #[serde(with = "optional_duration")]
        learn_for: Option<HumanDuration>,
        memory: SizeLimit,
        disk: SizeLimit,
    }

    mod functional {
        use super::*;

        #[test]
        fn parses_durations() {
            assert_eq!(dur("45s"), Ok(45));
            assert_eq!(dur("10m"), Ok(600));
            assert_eq!(dur("1h"), Ok(3_600));
            assert_eq!(dur("7d"), Ok(604_800));
            assert_eq!(dur(" 30 m "), Ok(1_800));
        }

        #[test]
        fn rejects_bad_durations() {
            for bad in ["", "10", "m", "10x", "1.5h", "-1s", "10 minutes", "1h30m"] {
                assert!(
                    matches!(dur(bad), Err(UnitError::Duration(_))),
                    "{bad:?} should be rejected"
                );
            }
            assert_eq!(dur("0s"), Err(UnitError::Zero("0s".into())));
            assert!(matches!(
                dur("99999999999999999999d"),
                Err(UnitError::Duration(_))
            ));
            assert_eq!(
                dur("999999999999999999d"),
                Err(UnitError::Overflow("999999999999999999d".into()))
            );
        }

        #[test]
        fn formats_durations_in_the_largest_exact_unit() {
            assert_eq!(HumanDuration::from_secs(90).to_string(), "90s");
            assert_eq!(HumanDuration::from_secs(600).to_string(), "10m");
            assert_eq!(HumanDuration::from_secs(7_200).to_string(), "2h");
            assert_eq!(HumanDuration::from_secs(2_592_000).to_string(), "30d");
        }

        #[test]
        fn parses_sizes() {
            assert_eq!("512KiB".parse(), Ok(SizeLimit::Bytes(512 * KIB)));
            assert_eq!("32MiB".parse(), Ok(SizeLimit::mib(32)));
            assert_eq!("2 gib".parse(), Ok(SizeLimit::Bytes(2 * GIB)));
            assert_eq!("1TiB".parse(), Ok(SizeLimit::Bytes(TIB)));
            assert_eq!("4096".parse(), Ok(SizeLimit::Bytes(4096)));
            assert_eq!("100B".parse(), Ok(SizeLimit::Bytes(100)));
            assert_eq!("5%".parse(), Ok(SizeLimit::Percent(5.0)));
            assert_eq!("0.5 %".parse(), Ok(SizeLimit::Percent(0.5)));
            assert_eq!("100%".parse(), Ok(SizeLimit::Percent(100.0)));
        }

        #[test]
        fn rejects_bad_sizes() {
            let err = |s: &str| s.parse::<SizeLimit>().unwrap_err();
            assert_eq!(err("32MB"), UnitError::DecimalUnit("32MB".into(), "MiB"));
            assert_eq!(err("1G"), UnitError::DecimalUnit("1G".into(), "GiB"));
            assert_eq!(err("0MiB"), UnitError::Zero("0MiB".into()));
            assert_eq!(err("0%"), UnitError::Percent("0%".into()));
            assert_eq!(err("150%"), UnitError::Percent("150%".into()));
            assert_eq!(err("abc%"), UnitError::Percent("abc%".into()));
            assert_eq!(err("lots"), UnitError::Size("lots".into()));
            assert_eq!(err("1.5GiB"), UnitError::Size("1.5GiB".into()));
            assert_eq!(
                err("99999999TiB"),
                UnitError::Overflow("99999999TiB".into())
            );
        }

        #[test]
        fn resolves_limits() {
            assert_eq!(SizeLimit::mib(32).resolve(GIB), 32 * MIB);
            assert_eq!(
                SizeLimit::Percent(1.0).resolve(16 * GIB),
                16 * GIB / 100 + 1
            );
            assert_eq!(SizeLimit::Percent(50.0).resolve(100), 50);
            assert_eq!(
                SizeLimit::Percent(0.001).resolve(10),
                1,
                "never resolves to 0"
            );
            assert!(SizeLimit::Percent(5.0).is_percent());
            assert!(!SizeLimit::mib(1).is_percent());
        }

        #[test]
        fn formats_sizes() {
            assert_eq!(SizeLimit::mib(512).to_string(), "512MiB");
            assert_eq!(SizeLimit::Bytes(GIB).to_string(), "1GiB");
            assert_eq!(SizeLimit::Bytes(1_000).to_string(), "1000B");
            assert_eq!(SizeLimit::Percent(5.0).to_string(), "5%");
            assert_eq!(SizeLimit::Percent(0.5).to_string(), "0.5%");
        }

        #[test]
        fn human_bytes_is_approximate() {
            assert_eq!(human_bytes(100), "100 B");
            assert_eq!(human_bytes(512 * KIB), "512 KiB");
            assert_eq!(human_bytes(32 * MIB), "32 MiB");
            assert_eq!(human_bytes(GIB + GIB / 2), "1.5 GiB");
        }

        #[test]
        fn reads_and_writes_toml() {
            let sample: Sample = toml::from_str(
                r#"
            window = "10m"
            learn_for = ""
            memory = "32MiB"
            disk = 4096
            "#,
            )
            .unwrap();
            assert_eq!(sample.window, HumanDuration::from_secs(600));
            assert_eq!(sample.learn_for, None);
            assert_eq!(sample.memory, SizeLimit::mib(32));
            assert_eq!(sample.disk, SizeLimit::Bytes(4096));

            let written = toml::to_string(&sample).unwrap();
            assert!(written.contains("window = \"10m\""), "{written}");
            assert!(written.contains("learn_for = \"\""), "{written}");
            assert_eq!(toml::from_str::<Sample>(&written).unwrap(), sample);
        }

        #[test]
        fn toml_errors_name_the_value() {
            let err = toml::from_str::<Sample>(
                "window = \"10x\"\nlearn_for = \"\"\nmemory = \"1MiB\"\ndisk = \"1MiB\"\n",
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("invalid duration \"10x\""), "{err}");
            assert!(err.contains("line 1"), "{err}");
        }

        proptest! {
            #[test]
            fn durations_round_trip(secs in 1u64..10_000_000) {
                let d = HumanDuration::from_secs(secs);
                prop_assert_eq!(d.to_string().parse::<HumanDuration>(), Ok(d));
            }

            #[test]
            fn byte_sizes_round_trip(value in 1u64..1_000_000, shift in prop::sample::select(vec![0u32, 10, 20, 30])) {
                let size = SizeLimit::Bytes(value << shift);
                prop_assert_eq!(size.to_string().parse::<SizeLimit>(), Ok(size));
            }

            #[test]
            fn percentages_round_trip(tenths in 1u32..=1000) {
                let size = SizeLimit::Percent(f64::from(tenths) / 10.0);
                prop_assert_eq!(size.to_string().parse::<SizeLimit>(), Ok(size));
            }
        }
    }
}
