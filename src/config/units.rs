//! Durations and byte sizes as the configuration spells them.
//!
//! Both accept a bare number or a suffixed string, because a config file
//! saying `request-timeout: 30` and one saying `request-timeout: "30 sec"`
//! should mean the same thing.  `_` is allowed as a digit separator, so
//! `maximum-in-memory-download: "64_MiB"` reads cleanly.

use std::fmt;
use std::time::Duration;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

/// One year, the largest duration the schema permits.
const MAX_SECONDS: u64 = 31_536_000;

/// A span of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ConfigDuration(Duration);

impl ConfigDuration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub fn get(self) -> Duration {
        self.0
    }

    /// Parse the suffixed string form.
    fn parse(text: &str) -> Result<Self, String> {
        let (value, unit) = split_value_unit(text)?;

        let millis = match unit {
            "ms" | "millisecond" | "milliseconds" => value,
            "" | "sec" | "second" | "seconds" => value * 1_000,
            "min" | "minute" | "minutes" => value * 60_000,
            "hr" | "hour" | "hours" => value * 3_600_000,
            "day" | "days" => value * 86_400_000,
            other => return Err(format!("unknown time unit {other:?}")),
        };

        let duration = Duration::from_millis(millis);

        if duration.as_secs() > MAX_SECONDS {
            return Err(format!("{text:?} exceeds the one year maximum"));
        }

        Ok(Self(duration))
    }
}

impl fmt::Display for ConfigDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<'de> Deserialize<'de> for ConfigDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Scalar::deserialize(deserializer)? {
            // A bare number is seconds, per the schema.
            Scalar::Number(seconds) => {
                if seconds < 0.0 {
                    return Err(de::Error::custom("a duration cannot be negative"));
                }

                Ok(Self(Duration::from_secs_f64(seconds)))
            }

            Scalar::Text(text) => Self::parse(&text).map_err(de::Error::custom),
        }
    }
}

/// The word that spells a lifetime with no end.
const FOREVER: &str = "forever";

/// A span of time, or `forever`.
///
/// For a cache lifetime, where a binding must be able to say "no limit"
/// even when `setup` sets one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLifetime {
    Forever,
    For(ConfigDuration),
}

impl ConfigLifetime {
    /// The span, or `None` for forever.
    pub fn get(self) -> Option<Duration> {
        match self {
            ConfigLifetime::Forever => None,
            ConfigLifetime::For(span) => Some(span.get()),
        }
    }
}

impl Serialize for ConfigLifetime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ConfigLifetime::Forever => serializer.serialize_str(FOREVER),
            ConfigLifetime::For(span) => span.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ConfigLifetime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let scalar = Scalar::deserialize(deserializer)?;

        if let Scalar::Text(text) = &scalar
            && text.trim() == FOREVER
        {
            return Ok(ConfigLifetime::Forever);
        }

        let span = match scalar {
            Scalar::Number(seconds) if seconds < 0.0 => {
                return Err(de::Error::custom("a duration cannot be negative"));
            }
            Scalar::Number(seconds) => ConfigDuration(Duration::from_secs_f64(seconds)),
            Scalar::Text(text) => ConfigDuration::parse(&text).map_err(de::Error::custom)?,
        };

        Ok(ConfigLifetime::For(span))
    }
}

/// A quantity of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ByteSize(u64);

impl ByteSize {
    pub const fn bytes(n: u64) -> Self {
        Self(n)
    }

    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }

    pub fn get(self) -> u64 {
        self.0
    }

    fn parse(text: &str) -> Result<Self, String> {
        let (value, unit) = split_value_unit(text)?;

        // Both the decimal and binary spellings appear in the wild, and
        // guessing which one a user meant is worse than honoring both.
        let bytes = match unit.to_ascii_lowercase().as_str() {
            "" | "b" | "byte" | "bytes" => value,
            "kb" => value * 1_000,
            "kib" | "k" => value * 1_024,
            "mb" => value * 1_000_000,
            "mib" | "m" => value * 1_048_576,
            "gb" => value * 1_000_000_000,
            "gib" | "g" => value * 1_073_741_824,
            other => return Err(format!("unknown size unit {other:?}")),
        };

        Ok(Self(bytes))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Scalar::deserialize(deserializer)? {
            Scalar::Number(bytes) => {
                if bytes < 0.0 {
                    return Err(de::Error::custom("a size cannot be negative"));
                }

                Ok(Self(bytes as u64))
            }

            Scalar::Text(text) => Self::parse(&text).map_err(de::Error::custom),
        }
    }
}

/// Either form the schema allows for these values.
#[derive(Deserialize)]
#[serde(untagged)]
enum Scalar {
    Number(f64),
    Text(String),
}

/// Split `"64 MiB"` or `"30sec"` into its number and its unit.
///
/// Underscores are stripped from the digits, so `1_000` parses.
fn split_value_unit(text: &str) -> Result<(u64, &str), String> {
    let trimmed = text.trim();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '_')
        .unwrap_or(trimmed.len());

    let (digits, unit) = trimmed.split_at(digits_end);
    let digits = digits.replace('_', "");

    if digits.is_empty() {
        return Err(format!("{text:?} does not start with a number"));
    }

    let value = digits
        .parse::<u64>()
        .map_err(|_| format!("{digits:?} is not a whole number"))?;

    Ok((value, unit.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn duration(text: &str) -> ConfigDuration {
        serde_json::from_str(text).expect("parses")
    }

    fn size(text: &str) -> ByteSize {
        serde_json::from_str(text).expect("parses")
    }

    fn lifetime(text: &str) -> ConfigLifetime {
        serde_json::from_str(text).expect("parses")
    }

    #[test]
    fn lifetime_reads_forever_and_durations() {
        assert_eq!(lifetime(r#""forever""#), ConfigLifetime::Forever);
        assert_eq!(
            lifetime(r#""2 hours""#).get(),
            Some(Duration::from_secs(7_200))
        );
        assert_eq!(lifetime("30").get(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn lifetime_nonsense_refused() {
        assert!(serde_json::from_str::<ConfigLifetime>(r#""eventually""#).is_err());
        assert!(serde_json::from_str::<ConfigLifetime>("-1").is_err());
    }

    #[test]
    fn duration_bare_number_in_seconds() {
        assert_eq!(duration("30").get(), Duration::from_secs(30));
        assert_eq!(duration("1.5").get(), Duration::from_millis(1500));
    }

    #[test]
    fn duration_every_documented_unit_parses() {
        assert_eq!(duration(r#""250ms""#).get(), Duration::from_millis(250));
        assert_eq!(
            duration(r#""250 milliseconds""#).get(),
            Duration::from_millis(250)
        );
        assert_eq!(duration(r#""30sec""#).get(), Duration::from_secs(30));
        assert_eq!(duration(r#""2 minutes""#).get(), Duration::from_secs(120));
        assert_eq!(duration(r#""1hr""#).get(), Duration::from_secs(3600));
        assert_eq!(duration(r#""2 days""#).get(), Duration::from_secs(172_800));
    }

    /// The schema documents `_` as a place separator.
    #[test]
    fn underscores_separate_digits() {
        assert_eq!(duration(r#""10_000 ms""#).get(), Duration::from_secs(10));
        assert_eq!(size(r#""1_048_576""#).get(), 1_048_576);
    }

    /// An unsuffixed string is still seconds, matching the bare number.
    #[test]
    fn duration_unsuffixed_string_in_seconds() {
        assert_eq!(duration(r#""45""#).get(), Duration::from_secs(45));
    }

    #[test]
    fn duration_unknown_unit_rejected() {
        let err = serde_json::from_str::<ConfigDuration>(r#""5 fortnights""#).unwrap_err();

        assert!(err.to_string().contains("unknown time unit"));
    }

    #[test]
    fn duration_beyond_year_rejected() {
        let err = serde_json::from_str::<ConfigDuration>(r#""400 days""#).unwrap_err();

        assert!(err.to_string().contains("one year"));
    }

    #[test]
    fn negative_values_rejected() {
        assert!(serde_json::from_str::<ConfigDuration>("-1").is_err());
        assert!(serde_json::from_str::<ByteSize>("-1").is_err());
    }

    /// Decimal and binary suffixes mean different things and both appear in
    /// real config files.
    #[test]
    fn size_units_distinguish_decimal_from_binary() {
        assert_eq!(size(r#""1kb""#).get(), 1_000);
        assert_eq!(size(r#""1KiB""#).get(), 1_024);
        assert_eq!(size(r#""64 MiB""#).get(), 67_108_864);
        assert_eq!(size(r#""1GB""#).get(), 1_000_000_000);
    }

    #[test]
    fn size_missing_digits_rejected() {
        let err = serde_json::from_str::<ByteSize>(r#""MiB""#).unwrap_err();

        assert!(err.to_string().contains("does not start with a number"));
    }
}
