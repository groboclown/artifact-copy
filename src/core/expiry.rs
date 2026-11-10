//! When a user's statement of trust stops applying.
//!
//! Shared by quarantine overrides and pinned signing keys, which both
//! answer *when does this stop being trusted*. One field with two
//! spellings: a date, or the word `never`. Where it appears it is
//! required, so an open-ended trust is a decision somebody wrote down,
//! not what happens when a field is left out.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// When a statement of trust stops applying.
///
/// One field with two spellings rather than two fields that can contradict
/// each other: a date, or the word `never`. There is no third state -- an
/// absent expiry is not expressible, which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// Deliberately open-ended, said out loud.
    Never,

    /// Lapses at this moment.
    At(DateTime<Utc>),
}

/// The spelling of [`Expiry::Never`] in a configuration or policy file.
pub(crate) const NEVER: &str = "never";

impl Expiry {
    /// Whether this still applies at `when`.
    pub fn in_force(self, when: DateTime<Utc>) -> bool {
        match self {
            Expiry::Never => true,
            Expiry::At(until) => when <= until,
        }
    }

    /// The date this lapses on, if it lapses.
    pub fn at(self) -> Option<DateTime<Utc>> {
        match self {
            Expiry::Never => None,
            Expiry::At(when) => Some(when),
        }
    }

    fn parse(text: &str) -> std::result::Result<Self, String> {
        if text == NEVER {
            return Ok(Expiry::Never);
        }

        DateTime::parse_from_rfc3339(text)
            .map(|when| Expiry::At(when.with_timezone(&Utc)))
            .map_err(|err| {
                format!("{text:?} is neither {NEVER:?} nor an RFC 3339 timestamp: {err}")
            })
    }
}

impl std::fmt::Display for Expiry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expiry::Never => f.write_str(NEVER),
            Expiry::At(when) => f.write_str(&when.to_rfc3339()),
        }
    }
}

impl Serialize for Expiry {
    fn serialize<S: serde::Serializer>(&self, out: S) -> std::result::Result<S::Ok, S::Error> {
        out.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Expiry {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(input)?;

        Expiry::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `never` is a value, not an absence, so it parses as one.
    #[test]
    fn expiry_never_value_not_absent_field() {
        assert_eq!(Expiry::parse("never"), Ok(Expiry::Never));

        // And the round trip is exact, so a file this tool writes back is
        // one it can read.
        assert_eq!(Expiry::Never.to_string(), "never");
    }

    /// Anything that is neither is refused with both spellings named,
    /// because a typo here silently keeps or drops a trust.
    #[test]
    fn expiry_bad_names_both_spellings() {
        let err = Expiry::parse("forever").expect_err("not a spelling");

        assert!(err.contains("never"), "{err}");
        assert!(err.contains("RFC 3339"), "{err}");
    }
}
