//! Standing one extension point in front of several others.
//!
//! The vocabulary shared by every proxy, of whatever kind. A proxy is
//! handed an **ordered list** of upstreams, each with an **optional,
//! non-unique classifier**, and may use either, neither, or both:
//!
//! - **Order** expresses precedence.
//! - **Classifier** assigns a responsibility -- *this one is releases, that
//!   one is snapshots* -- for a proxy whose upstreams are not
//!   interchangeable.
//!
//! # Checked at construction
//!
//! A proxy states its own arity and classifier rules through the `require_`
//! methods here, in its `open`. A configuration that cannot work is then a
//! startup error naming what was wrong, rather than a failure found
//! partway through a walk over a million artifacts.
//!
//! # Generic over what is proxied
//!
//! [`Upstreams<T>`] holds `Arc<T>` for an unsized `T`, so one list serves
//! `dyn Source` and `dyn Enumerator` alike. The rules that need to know what
//! an upstream *is* -- only the ecosystem ones so far -- are behind
//! [`Proxied`], which each extension point implements for its own trait
//! object.
//!
//! This module was a second copy waiting to happen: it started inside
//! `repo::proxy` and moved here the moment enumerators needed the same list.
//! It lives in `repo` beside both proxies rather than under either, because
//! it belongs to neither.

use std::sync::Arc;

use crate::core::error::{Error, Result};
use crate::model::EcosystemId;

/// What a proxy needs to know about a thing it stands in front of.
///
/// One question so far: which ecosystems does it speak. Asked *without*
/// being shown an artifact, which is the whole reason this exists -- a
/// proxy deciding whether its upstreams are compatible cannot invent one
/// to probe them with.
pub trait Proxied: Send + Sync {
    /// Which ecosystems this upstream speaks.
    ///
    /// Almost always one entry. A repository manager pointed at one
    /// repository still holds one format; the plural is for a source that
    /// genuinely fronts several, and the list is bounded by what an
    /// adapter supports rather than by anything a run finds.
    fn ecosystems(&self) -> Vec<EcosystemId>;
}

/// One thing a proxy stands in front of.
pub struct Upstream<T: ?Sized> {
    /// Which responsibility this upstream has, if the proxy assigns any.
    ///
    /// Not unique across a list, and not required. A proxy that cares says
    /// so with [`Upstreams::require_unique_classifiers`] or
    /// [`Upstreams::require_exactly_one_of`].
    pub classifier: Option<String>,

    /// Shared rather than owned: two proxies naming the same configured
    /// source get the same instance, and therefore the same caches.
    pub item: Arc<T>,
}

impl<T: ?Sized> Upstream<T> {
    pub fn new(item: Arc<T>) -> Self {
        Self {
            classifier: None,
            item,
        }
    }

    pub fn classified(item: Arc<T>, classifier: impl Into<String>) -> Self {
        Self {
            classifier: Some(classifier.into()),
            item,
        }
    }

    /// Whether this upstream answers to `classifier`.
    pub fn is(&self, classifier: &str) -> bool {
        self.classifier.as_deref() == Some(classifier)
    }
}

/// The ordered upstreams a proxy was built over.
///
/// A newtype rather than a bare `Vec` so the rules a proxy imposes have
/// somewhere to live and are spelled the same way by every proxy. The
/// order is the configuration's order, always, and is never sorted here --
/// a proxy that wants a different order arranges one itself and says why.
pub struct Upstreams<T: ?Sized> {
    /// Bounded by the configuration file, not by the size of any
    /// repository, so this does not violate the memory discipline.
    entries: Vec<Upstream<T>>,
}

impl<T: ?Sized> Upstreams<T> {
    pub fn new(entries: Vec<Upstream<T>>) -> Self {
        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// In configuration order.
    pub fn iter(&self) -> impl Iterator<Item = &Upstream<T>> {
        self.entries.iter()
    }

    /// The upstreams answering to one classifier, in configuration order.
    ///
    /// Several may, which is why this is not an `Option`: two snapshot
    /// repositories behind one proxy is a reasonable thing to configure.
    pub fn with_classifier<'s>(
        &'s self,
        classifier: &'s str,
    ) -> impl Iterator<Item = &'s Upstream<T>> {
        self.entries
            .iter()
            .filter(move |entry| entry.is(classifier))
    }

    /// Refuse fewer than `least` upstreams.
    ///
    /// `what` names the proxy, because the message is read by someone
    /// looking at a configuration file with several proxies in it.
    pub fn require_at_least(&self, least: usize, what: &str) -> Result<()> {
        if self.entries.len() < least {
            return Err(Error::Config(format!(
                "a {what} proxy needs at least {least} entries under 'proxy-to', \
                 and this one has {}",
                self.entries.len()
            )));
        }

        Ok(())
    }

    /// Refuse more than `most` upstreams.
    pub fn require_at_most(&self, most: usize, what: &str) -> Result<()> {
        if self.entries.len() > most {
            return Err(Error::Config(format!(
                "a {what} proxy takes at most {most} entries under 'proxy-to', \
                 and this one has {}",
                self.entries.len()
            )));
        }

        Ok(())
    }

    /// Refuse two upstreams sharing a classifier.
    ///
    /// For a proxy that reads a classifier as a role rather than as a tag:
    /// two upstreams both claiming to be the release repository is a
    /// configuration mistake, not a pair to choose between.
    ///
    /// An upstream with **no** classifier is not compared against anything,
    /// including another that also has none. Absent is not a value.
    pub fn require_unique_classifiers(&self, what: &str) -> Result<()> {
        let mut seen: Vec<&str> = Vec::new();

        for entry in &self.entries {
            let Some(classifier) = entry.classifier.as_deref() else {
                continue;
            };

            if seen.contains(&classifier) {
                return Err(Error::Config(format!(
                    "a {what} proxy needs distinct classifiers under 'proxy-to', \
                     and {classifier:?} is used twice"
                )));
            }

            seen.push(classifier);
        }

        Ok(())
    }

    /// Refuse anything but exactly one upstream carrying one of `allowed`.
    ///
    /// The rule for a proxy with one distinguished upstream and any number
    /// of ordinary ones -- exactly one primary, say. Entries carrying a
    /// classifier outside `allowed` are ignored by this check; a proxy that
    /// wants to refuse those as well calls
    /// [`Upstreams::require_known_classifiers`].
    pub fn require_exactly_one_of(&self, allowed: &[&str], what: &str) -> Result<()> {
        let matched: Vec<&str> = self
            .entries
            .iter()
            .filter_map(|entry| entry.classifier.as_deref())
            .filter(|classifier| allowed.contains(classifier))
            .collect();

        if matched.len() == 1 {
            return Ok(());
        }

        Err(Error::Config(format!(
            "a {what} proxy needs exactly one entry under 'proxy-to' classified as \
             one of {}, and this one has {}",
            join(allowed),
            matched.len()
        )))
    }

    /// Refuse a classifier the proxy does not recognize.
    ///
    /// A typo in a classifier is otherwise silent: the proxy simply never
    /// finds the upstream it was looking for, and the run does less than it
    /// was asked to while reporting nothing.
    pub fn require_known_classifiers(&self, allowed: &[&str], what: &str) -> Result<()> {
        for entry in &self.entries {
            let Some(classifier) = entry.classifier.as_deref() else {
                continue;
            };

            if !allowed.contains(&classifier) {
                return Err(Error::Config(format!(
                    "a {what} proxy does not use the classifier {classifier:?}; \
                     it understands {}",
                    join(allowed)
                )));
            }
        }

        Ok(())
    }
}

impl<'u, T: ?Sized> IntoIterator for &'u Upstreams<T> {
    type Item = &'u Upstream<T>;
    type IntoIter = std::slice::Iter<'u, Upstream<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<T: Proxied + ?Sized> Upstreams<T> {
    /// Every ecosystem any upstream speaks, in first-seen order.
    ///
    /// The **union**, because a proxy can answer for whatever any of its
    /// upstreams can. This is what a proxy reports as its own, which is
    /// what lets a proxy be an upstream of another proxy.
    pub fn ecosystems(&self) -> Vec<EcosystemId> {
        let mut out: Vec<EcosystemId> = Vec::new();

        for entry in &self.entries {
            for spoken in entry.item.ecosystems() {
                if !out.contains(&spoken) {
                    out.push(spoken);
                }
            }
        }

        out
    }

    /// Refuse upstreams that are not alternatives for anything.
    ///
    /// The rule for a proxy whose upstreams are meant to be **alternative
    /// answers to the same question**. A failover from an npm registry to a
    /// Maven mirror is not a failover: the two hold disjoint sets of
    /// artifacts, so the fallback can only ever answer "not found", and the
    /// configuration that produced it is a mistake rather than an
    /// adventurous topology.
    ///
    /// The test is that **at least one ecosystem is spoken by every
    /// upstream** -- there is something these are alternatives for. It is
    /// deliberately not "they all speak exactly the same one": a repository
    /// manager serves Maven, npm and PyPI from one API, which is why
    /// `Source::ecosystem` takes the artifact in the first place, and a
    /// Maven registry falling back to a Nexus that also holds npm is a
    /// perfectly ordinary thing to configure.
    ///
    /// Answered from [`Proxied::ecosystems`] rather than by probing with an
    /// invented artifact, which is why that trait exists.
    pub fn require_shared_ecosystem(&self, what: &str) -> Result<()> {
        let Some(first) = self.entries.first() else {
            return Err(Error::Config(format!(
                "a {what} proxy has no entries under 'proxy-to', so there is no \
                 ecosystem it could answer for"
            )));
        };

        let mut shared = first.item.ecosystems();

        for entry in &self.entries[1..] {
            let spoken = entry.item.ecosystems();

            shared.retain(|candidate| spoken.contains(candidate));

            if shared.is_empty() {
                return Err(Error::Config(format!(
                    "a {what} proxy needs its entries under 'proxy-to' to share at \
                     least one ecosystem, so that they are alternatives for something. \
                     One speaks {} and another speaks {}, which are disjoint",
                    names(&first.item.ecosystems()),
                    names(&spoken),
                )));
            }
        }

        Ok(())
    }
}

impl<T: ?Sized> Default for Upstreams<T> {
    /// An empty list, which every proxy so far refuses. Useful only for
    /// building one up.
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

/// Ecosystem ids for an error message.
fn names(ids: &[EcosystemId]) -> String {
    match ids.is_empty() {
        true => "nothing".to_owned(),
        false => join(&ids.iter().map(EcosystemId::as_str).collect::<Vec<_>>()),
    }
}

/// A list of names for an error message, quoted so an empty one is visible.
pub(crate) fn join(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}
