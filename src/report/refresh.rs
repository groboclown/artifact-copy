//! Which parts of a report database a run asks the server for instead.
//!
//! A database opened with `--db` is a cache by default: what a run already
//! learned, it does not ask again. A refreshed part is asked again, and the
//! answer is still written back, so the next run has it.
//!
//! ```text
//!   source       versions and metadata InventorySource answers
//!   target       whether a target already holds an artifact
//!   payloads     bytes an earlier run fetched
//!   enumeration  where an interrupted walk stopped
//!   spider       where an interrupted dependency walk stopped
//!   all          every part above, and the file is replaced
//! ```

use std::fmt;

/// One part of a report database that a run may refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Part {
    Source,
    Target,
    Payloads,
    Enumeration,
    Spider,

    /// Every part, and the database file is replaced.
    All,
}

impl Part {
    pub fn as_str(self) -> &'static str {
        match self {
            Part::Source => "source",
            Part::Target => "target",
            Part::Payloads => "payloads",
            Part::Enumeration => "enumeration",
            Part::Spider => "spider",
            Part::All => "all",
        }
    }

    /// Every spelling, in the order a message lists them.
    pub fn every() -> &'static [Part] {
        &[
            Part::Source,
            Part::Target,
            Part::Payloads,
            Part::Enumeration,
            Part::Spider,
            Part::All,
        ]
    }
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The parts a run refreshes. Empty is the default: everything cached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refresh {
    parts: Vec<Part>,
}

impl Refresh {
    pub fn new(parts: impl IntoIterator<Item = Part>) -> Self {
        Self {
            parts: parts.into_iter().collect(),
        }
    }

    /// Whether `part` is asked of the server rather than the database.
    pub fn covers(&self, part: Part) -> bool {
        self.parts.contains(&Part::All) || self.parts.contains(&part)
    }

    /// Whether the database file is replaced before the run.
    pub fn replaces(&self) -> bool {
        self.parts.contains(&Part::All)
    }

    /// The parts as given, for a caller that checks them.
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_none_by_default() {
        let refresh = Refresh::default();

        for part in Part::every() {
            assert!(!refresh.covers(*part), "{part}");
        }

        assert!(!refresh.replaces());
    }

    #[test]
    fn refresh_one_part_covers_only_itself() {
        let refresh = Refresh::new([Part::Target]);

        assert!(refresh.covers(Part::Target));
        assert!(!refresh.covers(Part::Source));
        assert!(!refresh.replaces());
    }

    #[test]
    fn refresh_all_covers_every_part_and_replaces() {
        let refresh = Refresh::new([Part::All]);

        for part in Part::every() {
            assert!(refresh.covers(*part), "{part}");
        }

        assert!(refresh.replaces());
    }
}
