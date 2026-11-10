//! How much of a catalog to take.
//!
//! Lives with the enumerators because that is what it constrains, and because
//! resolving a percentage needs [`Enumerator::count`](super::Enumerator::count) --
//! which most enumerators cannot answer, making the "a percentage needs a
//! total" rule below a real one rather than a formality.

use std::fmt;

/// A parsed `--sample-size` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleSize {
    /// Take this many artifacts.
    Count(u64),

    /// Take this share of the repository, which needs a total to be
    /// meaningful.
    Percent(u32),
}

impl SampleSize {
    /// Resolve against a repository total.
    ///
    /// A percentage without a total is an error, not a guess: the README
    /// says so, and guessing would silently sample the wrong amount.
    pub fn resolve(self, total: Option<u64>) -> Result<u64, String> {
        match self {
            SampleSize::Count(n) => Ok(n),

            SampleSize::Percent(pct) => {
                let total = total.ok_or_else(|| {
                    "this enumerator cannot report a total artifact count, so a \
                     percentage sample size is meaningless; use a number instead"
                        .to_owned()
                })?;

                Ok(total * u64::from(pct) / 100)
            }
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();

        let Some(digits) = trimmed.strip_suffix('%') else {
            return trimmed
                .parse::<u64>()
                .map(SampleSize::Count)
                .map_err(|_| format!("{text:?} is not a whole number or a percentage"));
        };

        let percent = digits
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("{text:?} is not a valid percentage"))?;

        if percent > 100 {
            return Err(format!("{percent}% is more than the whole repository"));
        }

        Ok(SampleSize::Percent(percent))
    }
}

impl fmt::Display for SampleSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SampleSize::Count(n) => write!(f, "{n}"),
            SampleSize::Percent(p) => write!(f, "{p}%"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_size_parses_both_forms() {
        assert_eq!(SampleSize::parse("1000").unwrap(), SampleSize::Count(1000));
        assert_eq!(SampleSize::parse("35%").unwrap(), SampleSize::Percent(35));
        assert_eq!(
            SampleSize::parse(" 35 % ").unwrap(),
            SampleSize::Percent(35)
        );
    }

    #[test]
    fn percentage_over_hundred_refused() {
        assert!(SampleSize::parse("101%").is_err());
    }

    #[test]
    fn count_needs_no_total() {
        assert_eq!(SampleSize::Count(50).resolve(None).unwrap(), 50);
    }

    /// The README's own rule: a percentage against an enumerator that cannot
    /// count is an error, never a guess.
    #[test]
    fn percentage_without_total_is_error() {
        let err = SampleSize::Percent(35).resolve(None).unwrap_err();

        assert!(err.contains("cannot report a total"));
    }

    #[test]
    fn percentage_with_total_resolves() {
        assert_eq!(SampleSize::Percent(35).resolve(Some(1000)).unwrap(), 350);
    }
}
