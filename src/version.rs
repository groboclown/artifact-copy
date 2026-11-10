//! Reading, ordering and matching version strings.
//!
//! Split out of [`Ecosystem`](crate::ecosystem::Ecosystem) because the two
//! answer different questions and not every repository needs both. An
//! ecosystem knows how a coordinate is spelled and what a registry calls
//! itself; a version handler knows only that `1.10` comes after `1.9` --
//! or, for some conventions, that the question has no answer.
//!
//! # Why it is its own trait
//!
//! Two repository kinds want version handling without an ecosystem to take
//! it from:
//!
//! - A **raw repository** imposes a coordinate scheme on paths and has no
//!   ecosystem at all. "Which of these is newer" is still a real question,
//!   and there is no registry to answer it.
//! - A **GitHub repository** whose tags happen to be semver can say so,
//!   rather than being refused every range because *tags in general* have
//!   no order.
//!
//! Both want the same thing: a handler chosen per repository, independent
//! of whether an ecosystem is involved.
//!
//! **Not an extension point.** The built-in handlers are expected to cover
//! the conventions in use, and the flexibility would not pay for the
//! complexity. An embedder that needs its own supplies an
//! [`Ecosystem`](crate::ecosystem::Ecosystem), which is one.
//!
//! # Everything is batched
//!
//! For the same reason as `Ecosystem`: a handler reached through an
//! ecosystem may be out of process, and sorting an 800-version packument
//! through a marshaled pairwise `compare` would be thousands of round
//! trips. One call per artifact is the shape that survives, so it is the
//! shape of the interface.
//!
//! References: [PEP 440](https://peps.python.org/pep-0440/), [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).

mod maven;
mod pep440;
mod semver;
mod tags;

pub use maven::MavenVersions;
pub use pep440::Pep440Versions;
pub use semver::Semver;
pub use tags::Tags;

use std::sync::Arc;

use crate::core::error::{Error, Result};
use crate::model::{Release, Version, VersionSpec};

/// Whether pre-release versions are candidates.
///
/// An enum rather than a `bool` so a call site says `PreRelease::Include`
/// instead of `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreRelease {
    /// General-availability releases only.
    Exclude,

    /// Alpha, beta, release candidate, snapshot, dev.
    Include,
}

/// One convention for reading and ordering versions.
pub trait VersionHandler: Send + Sync {
    /// Read a version qualifier as this convention spells specifications.
    ///
    /// `4.17.21` is exact and `^4.17.0` is a range to npm; `[1.0,2.0)` is a
    /// range and `1.0` exact to Maven; PyPI pins with `==`. The rule is the
    /// convention's own, and a caller that guessed would be wrong for at
    /// least one of them.
    ///
    /// Separate from coordinate parsing because a version qualifier can
    /// arrive somewhere other than a coordinate -- a quarantine rule's
    /// `pkg:npm/tuna@<2`, say -- where the surrounding syntax is a purl
    /// rather than the ecosystem's own.
    fn version_spec(&self, text: &str) -> VersionSpec;

    /// Tag raw version strings as GA or pre-release.
    ///
    /// A whole packument in one call.
    fn classify(&self, texts: &[String]) -> Vec<Version>;

    /// The highest version satisfying a constraint.
    ///
    /// Always the highest match, per `README.md`. Replaces a pairwise
    /// `compare` plus `matches`: one call-out per artifact instead of
    /// O(n log n).
    fn select(&self, spec: &VersionSpec, of: &[Version], pre: PreRelease) -> Option<Version>;

    /// Where `a` falls relative to `b`, by this convention's own rules.
    ///
    /// Separate from [`VersionHandler::select`], whose doc says it replaced
    /// a pairwise compare: that was about the cost of *selection*, where one
    /// call-out beats `O(n log n)` of them. This answers a different
    /// question -- whether a version falls inside an advisory's affected
    /// range -- which needs an ordering and has no selection to fold into.
    ///
    /// **[`Ranking::Indeterminate`] is not a tie.** A convention with no
    /// order, such as raw repository tags, can place no version relative to
    /// another, and saying so is the point: a caller that reads "cannot
    /// tell" as "equal", or as "outside the range", silently answers a
    /// security question it did not answer.
    fn compare(&self, a: &Version, b: &Version) -> Ranking;

    /// Ascending order, by this convention's own rules.
    ///
    /// Never substitute a generic comparator. Maven's `ComparableVersion`,
    /// PEP 440 and semver disagree in ways that change which artifact gets
    /// migrated -- and a convention with no order at all leaves the list
    /// alone rather than imposing one.
    fn sort(&self, versions: &mut [Version]);

    /// Build one version, tagging its release status.
    ///
    /// Defaulted through [`VersionHandler::classify`] so a handler states
    /// the rule once. An unclassifiable string is treated as a pre-release
    /// rather than dropped: it stays visible and cannot be selected by a
    /// run that excludes pre-releases, which is the conservative reading.
    fn version(&self, text: &str) -> Version {
        self.classify(std::slice::from_ref(&text.to_owned()))
            .pop()
            .unwrap_or_else(|| Version::new(text, Release::PreRelease))
    }
}

/// Node-semver, the commonest convention by a wide margin.
/// Where one version falls relative to another.
///
/// A four-valued answer rather than [`std::cmp::Ordering`], because some
/// conventions have no order at all and the difference between *equal* and
/// *cannot be placed* decides whether an artifact is screened or merely
/// looks screened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ranking {
    Before,
    Same,
    After,

    /// No ordering exists between these two.
    ///
    /// Raw repository tags are the case that forces this: `nightly` and
    /// `v2.1` are both tags and neither precedes the other. Never collapse
    /// it into `Same` -- see [`VersionHandler::compare`].
    Indeterminate,
}

impl Ranking {
    /// Read an ordering as a ranking, for a convention that has one.
    pub fn of(ordering: std::cmp::Ordering) -> Self {
        match ordering {
            std::cmp::Ordering::Less => Ranking::Before,
            std::cmp::Ordering::Equal => Ranking::Same,
            std::cmp::Ordering::Greater => Ranking::After,
        }
    }

    /// Whether `a` was at or after `b`, with `Indeterminate` answering
    /// neither.
    pub fn at_or_after(self) -> Option<bool> {
        match self {
            Ranking::Same | Ranking::After => Some(true),
            Ranking::Before => Some(false),
            Ranking::Indeterminate => None,
        }
    }

    /// Whether `a` was strictly before `b`, with `Indeterminate` answering
    /// neither.
    pub fn before(self) -> Option<bool> {
        match self {
            Ranking::Before => Some(true),
            Ranking::Same | Ranking::After => Some(false),
            Ranking::Indeterminate => None,
        }
    }
}

pub const SEMVER: &str = "semver";

/// Maven's `ComparableVersion` ordering and bracketed ranges.
pub const MAVEN: &str = "maven";

/// Python's PEP 440.
pub const PEP440: &str = "pep440";

/// Names with no order at all, which is what a git tag is.
pub const TAGS: &str = "tags";

/// Build the handler a `kind` names.
///
/// A closed set, unlike an extension `kind`: these are conventions rather
/// than protocols, and the list is short because there are only so many
/// ways people number releases. A name that is not here is a typo the
/// configuration can name outright rather than something to resolve later.
pub fn open(kind: &str) -> Result<Arc<dyn VersionHandler>> {
    match kind {
        SEMVER => Ok(Arc::new(Semver)),
        MAVEN => Ok(Arc::new(MavenVersions)),
        PEP440 => Ok(Arc::new(Pep440Versions)),
        TAGS => Ok(Arc::new(Tags)),

        other => Err(Error::UnknownKind {
            collection: "version handler",
            kind: other.to_owned(),
        }),
    }
}

/// Every built-in kind, for an error that names the alternatives.
pub fn kinds() -> &'static [&'static str] {
    &[MAVEN, PEP440, SEMVER, TAGS]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::Npm;
    use crate::model::Release;

    #[test]
    fn every_advertised_kind_opens() {
        for kind in kinds() {
            assert!(open(kind).is_ok(), "{kind} should open");
        }
    }

    /// A typo must name the alternatives, since nothing else enumerates
    /// them for a user.
    #[test]
    fn kind_unknown_names_itself() {
        let err = match open("semvar") {
            Err(err) => err,
            Ok(_) => panic!("should not have opened"),
        };

        assert!(err.to_string().contains("semvar"), "{err}");
    }

    /// Each ecosystem delegates to a named handler, so configuring that
    /// handler on a repository with no ecosystem gives the same answers.
    /// The point of the whole split, and it would be invisible otherwise.
    #[test]
    fn handler_named_agrees_with_ecosystem() {
        use crate::ecosystem::{Maven, PyPi, Raw};

        let pairs: [(&dyn VersionHandler, &dyn VersionHandler, &str); 4] = [
            (&Npm, &*open(SEMVER).expect("opens"), "1.2.3"),
            (&Maven, &*open(MAVEN).expect("opens"), "1.0-SNAPSHOT"),
            (&PyPi, &*open(PEP440).expect("opens"), "1.0.dev1"),
            (&Raw, &*open(TAGS).expect("opens"), "nightly"),
        ];

        for (ecosystem, handler, text) in pairs {
            assert_eq!(
                ecosystem.version(text).release(),
                handler.version(text).release(),
                "{text}"
            );
            assert_eq!(ecosystem.version_spec(text), handler.version_spec(text));
        }
    }

    /// Exercised through npm because a trait needs an implementation to be
    /// tested at all, and semver is the convention most readers can check
    /// the expectations of by eye. Each handler's own dialect -- Maven's
    /// `ComparableVersion`, PEP 440, GitHub's refusal to order tags -- is
    /// tested beside that handler.
    fn versions(texts: &[&str]) -> Vec<Version> {
        let owned: Vec<String> = texts.iter().map(|t| (*t).to_owned()).collect();

        Npm.classify(&owned)
    }

    /// The README requires the highest match, not the first or the newest
    /// published.
    #[test]
    fn select_takes_the_highest() {
        let best = Npm
            .select(
                &VersionSpec::Range("^1.0.0".into()),
                &versions(&["1.0.0", "1.2.0", "1.10.0", "2.0.0"]),
                PreRelease::Exclude,
            )
            .expect("matched");

        // 1.10.0 beats 1.2.0: numeric ordering, not lexical.
        assert_eq!(best.text(), "1.10.0");
    }

    #[test]
    fn select_none_when_nothing_satisfies() {
        assert!(
            Npm.select(
                &VersionSpec::Range("^9".into()),
                &versions(&["1.0.0"]),
                PreRelease::Exclude
            )
            .is_none()
        );
    }

    /// One call tags a whole packument, which is the point of batching.
    #[test]
    fn classify_tags_whole_list() {
        let tagged = versions(&["1.0.0", "2.0.0-rc.1", "nonsense"]);

        assert_eq!(tagged.len(), 3);
        assert_eq!(tagged[0].release(), Release::General);
        assert_eq!(tagged[1].release(), Release::PreRelease);

        // Unparseable text is treated as a pre-release: never selected by
        // default, but still visible rather than silently dropped.
        assert_eq!(tagged[2].release(), Release::PreRelease);
    }

    #[test]
    fn sort_ascending() {
        let mut list = versions(&["2.0.0", "1.10.0", "1.2.0", "2.0.0-rc.1"]);

        Npm.sort(&mut list);

        let order: Vec<&str> = list.iter().map(|v| v.text()).collect();

        assert_eq!(order, ["1.2.0", "1.10.0", "2.0.0-rc.1", "2.0.0"]);
    }

    /// The default `version` is `classify` for one string, and an
    /// unclassifiable one is a pre-release rather than an error -- visible,
    /// and never selected by a run that excludes them.
    #[test]
    fn classify_single_version() {
        assert_eq!(Npm.version("1.2.3").release(), Release::General);
        assert_eq!(Npm.version("nonsense").release(), Release::PreRelease);
    }
}
