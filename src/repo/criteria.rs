//! What a resolved artifact must satisfy, beyond the version asked for.
//!
//! Not part of the coordinate, which is why this is not in `model`: a user
//! asking for `lodash` with no version wants the newest one that is
//! *acceptable*, and what counts as acceptable is a policy of the run
//! rather than part of what was typed.
//!
//! [`criteria_for`] is where configuration becomes one of these, and it
//! carries the precedence rule the whole configuration uses: the most
//! specific setting wins, and an absent one falls back rather than
//! overriding with a default.

use crate::config::UnknownPublishTime;
use crate::version::PreRelease;

/// What a resolved artifact must satisfy beyond the version it was asked
/// for.
///
/// Separate from [`crate::model::VersionSpec`] because these are not
/// properties of the coordinate: a user asking for `lodash` with no version
/// wants the newest one that is *acceptable*, and what counts as acceptable
/// is a policy of the run rather than part of what was typed.
///
/// Grouped rather than passed one by one so that adding a criterion does
/// not reshape every implementation of the trait.
#[derive(Debug, Clone, Copy)]
pub struct Criteria {
    /// Whether pre-releases are candidates.
    pub pre: PreRelease,

    /// Artifacts must have been published at least this long ago.
    ///
    /// A crude but effective guard against mirroring a compromised release
    /// inside the window where it would be noticed and yanked.
    ///
    /// Applied **after** selection rather than during it, because publish
    /// time is not in the version list -- it arrives with the metadata. A
    /// version that fails the window therefore steps down to the next
    /// newest rather than failing the request.
    pub minimum_age: Option<std::time::Duration>,

    /// What to do about an artifact whose publish time is unknown.
    ///
    /// Configured per source, defaulting from `setup`, because the answer
    /// is a property of the repository: a mirror reporting no timestamps
    /// and a registry reporting them all sit in the same configuration.
    pub unknown_publish_time: UnknownPublishTime,
}

impl Criteria {
    pub fn new(pre: PreRelease) -> Self {
        Self {
            pre,
            minimum_age: None,
            unknown_publish_time: UnknownPublishTime::default(),
        }
    }

    /// Whether pre-releases are candidates.
    ///
    /// Separate from [`criteria_for`] because this comes from the command
    /// line rather than from the configuration: `--pre-release` is a
    /// statement about one invocation, and a source cannot say it on a
    /// user's behalf.
    pub fn pre_release(mut self, pre: PreRelease) -> Self {
        self.pre = pre;
        self
    }

    pub fn minimum_age(mut self, age: std::time::Duration) -> Self {
        self.minimum_age = Some(age);
        self
    }

    pub fn unknown_publish_time(mut self, decision: UnknownPublishTime) -> Self {
        self.unknown_publish_time = decision;
        self
    }

    /// Whether an artifact is old enough.
    ///
    /// An **unknown** publish time is the user's call, not the tool's --
    /// see [`UnknownPublishTime`]. There is no answer that is right for
    /// both a registry that reports every timestamp and a mirror that
    /// reports none.
    pub(crate) fn old_enough(&self, published: Option<chrono::DateTime<chrono::Utc>>) -> bool {
        let Some(minimum) = self.minimum_age else {
            return true;
        };

        let Some(published) = published else {
            return self.unknown_publish_time == UnknownPublishTime::Allow;
        };

        match chrono::Duration::from_std(minimum) {
            Ok(minimum) => chrono::Utc::now().signed_duration_since(published) >= minimum,

            // A window too large for `chrono` excludes everything, which is
            // what such a setting literally asks for.
            Err(_) => false,
        }
    }
}

impl Default for Criteria {
    fn default() -> Self {
        Self::new(PreRelease::Exclude)
    }
}

/// Build the criteria for one source, resolving `setup` defaults.
///
/// Precedence is the same everywhere in this configuration: the most
/// specific setting wins, and an absent one falls back rather than
/// overriding with a default. A source that says nothing inherits `setup`;
/// `setup` saying nothing leaves the built-in default.
///
/// **Configuration only.** Pre-releases are not settled here -- that comes
/// from `--pre-release`, which is about one invocation rather than about a
/// repository. A caller adds it with [`Criteria::pre_release`].
///
/// For a **proxy** the proxy's own declaration is what to pass: it is the
/// source being resolved against, and the default `resolve` drives the
/// proxy's own `versions` and `metadata`, so an upstream's window never
/// comes into play. Worth knowing before someone tries to make one apply.
pub fn criteria_for(source: &crate::config::Source, setup: &crate::config::Setup) -> Criteria {
    let mut criteria = Criteria::default();

    if let Some(window) = &source.minimum_publish_time {
        criteria.minimum_age = Some(window.get());
    }

    criteria.unknown_publish_time = source
        .unknown_publish_time
        .or(setup.unknown_publish_time)
        .unwrap_or_default();

    criteria
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigDuration, Setup, UnknownPublishTime};
    use chrono::{Duration as ChronoDuration, Utc};

    fn source() -> crate::config::Source {
        serde_json::from_value(serde_json::json!({
            "host": "h",
            "kind": "npm",
        }))
        .expect("a minimal source")
    }

    fn criteria() -> Criteria {
        Criteria::new(PreRelease::Exclude).minimum_age(std::time::Duration::from_secs(86_400))
    }

    /// The window itself is unchanged by the setting: a dated artifact is
    /// judged on its date whatever the unknown-time answer is.
    #[test]
    fn window_dated_artifact_judged_on_date() {
        let old = Some(Utc::now() - ChronoDuration::days(30));
        let fresh = Some(Utc::now() - ChronoDuration::minutes(5));

        for decision in [UnknownPublishTime::Allow, UnknownPublishTime::Refuse] {
            let criteria = criteria().unknown_publish_time(decision);

            assert!(criteria.old_enough(old), "{decision:?}");
            assert!(!criteria.old_enough(fresh), "{decision:?}");
        }
    }

    /// The decision the user now owns.
    #[test]
    fn window_unknown_publish_time_follows_configured() {
        assert!(
            !criteria()
                .unknown_publish_time(UnknownPublishTime::Refuse)
                .old_enough(None)
        );

        assert!(
            criteria()
                .unknown_publish_time(UnknownPublishTime::Allow)
                .old_enough(None)
        );
    }

    /// A window that silently stopped applying would be worse than one that
    /// visibly refuses, so the strict answer is the built-in default.
    #[test]
    fn window_unknown_publish_time_refused_by_default() {
        assert_eq!(UnknownPublishTime::default(), UnknownPublishTime::Refuse);
        assert!(!criteria().old_enough(None));
    }

    /// With no window configured the setting is irrelevant: publish time is
    /// not being asked about at all.
    #[test]
    fn window_absent_unknown_time_not_asked() {
        for decision in [UnknownPublishTime::Allow, UnknownPublishTime::Refuse] {
            let criteria = Criteria::new(PreRelease::Exclude).unknown_publish_time(decision);

            assert!(criteria.old_enough(None), "{decision:?}");
        }
    }

    // -- Precedence -------------------------------------------------------

    #[test]
    fn source_overrides_setup_default() {
        let mut source = source();
        source.unknown_publish_time = Some(UnknownPublishTime::Allow);

        let setup = Setup {
            unknown_publish_time: Some(UnknownPublishTime::Refuse),
            ..Setup::default()
        };

        assert_eq!(
            criteria_for(&source, &setup).unknown_publish_time,
            UnknownPublishTime::Allow
        );
    }

    /// A source saying nothing inherits rather than resetting to the
    /// built-in default -- which is the difference between a `setup` section
    /// that works and one that is silently ignored.
    #[test]
    fn source_silent_inherits_setup_default() {
        let setup = Setup {
            unknown_publish_time: Some(UnknownPublishTime::Allow),
            ..Setup::default()
        };

        assert_eq!(
            criteria_for(&source(), &setup).unknown_publish_time,
            UnknownPublishTime::Allow
        );
    }

    #[test]
    fn source_and_setup_silent_built_in_stands() {
        assert_eq!(
            criteria_for(&source(), &Setup::default()).unknown_publish_time,
            UnknownPublishTime::Refuse
        );
    }

    #[test]
    fn window_from_source() {
        let mut source = source();
        source.minimum_publish_time = Some(ConfigDuration::from_secs(3_600));

        let criteria = criteria_for(&source, &Setup::default());

        assert_eq!(
            criteria.minimum_age,
            Some(std::time::Duration::from_secs(3_600))
        );
    }

    #[test]
    fn window_none_when_source_has_none() {
        assert_eq!(criteria_for(&source(), &Setup::default()).minimum_age, None);
    }
}
