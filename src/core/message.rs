//! Human-readable text that could one day be translated.
//!
//! Wherever prose crosses a data-exchange boundary -- a report record, an
//! extension protocol message -- it travels as an **identifier plus named
//! parameters**, with the English as a fallback rather than as the payload.
//! A consumer that wants Japanese looks up the id and substitutes the args;
//! one that wants what we produced reads the fallback.
//!
//! ```text
//!   { "id": "source-host-unknown",
//!     "args": { "source": "central", "host": "nowhere" },
//!     "text": "source \"central\" names host \"nowhere\", which is not configured" }
//! ```
//!
//! **This is deliberately not an i18n library.** There is no catalog, no
//! locale negotiation, no plural rules. Adding those later should not have
//! to change a single interface, which is the whole point of doing the
//! cheap part now: the shape is fixed, so the machinery can arrive behind
//! it without breaking a report anyone has already written a tool against.
//!
//! # Where this applies, and where it does not
//!
//! Only text that **leaves the process as data**: problems and their
//! records, license verdicts, extension protocol messages. Those are read
//! by other programs and by people who did not run the command.
//!
//! Log lines stay plain U.S. English. [`Log`](super::log::Log) lines are read
//! by whomever ran the tool, next to the command they typed, and wrapping
//! them in identifiers would cost every call site something and buy nothing.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The argument naming the artifact a message is about, as a purl.
///
/// Versioned when the version is known. The report database links a
/// problem to its artifact through this argument alone, so it must match
/// `artifact.purl` exactly:
///
/// ```text
///   purl  = pkg:npm/fs@0.0.1-security   the primary artifact
///   purl1 = pkg:maven/g/parent@2        further artifacts, numbered from 1
///   purl0, purl1, ...                   a list with no primary, from 0
/// ```
pub const PURL_ARG: &str = "purl";

/// The argument naming an artifact when no purl is at hand, such as a bare
/// package name read from a document.
pub const ARTIFACT_NAME_ARG: &str = "artifact_name";

/// The argument carrying what an HTTP error response said, apart from the
/// rendered text so a consumer can query it.
pub const HTTP_DETAIL_ARG: &str = "http_detail";

/// The argument carrying the URL a failure happened at, for investigation.
/// Kept out of the rendered text where a file name says it better.
pub const URL_ARG: &str = "url";

/// The argument naming the file of an artifact a failure happened to.
pub const FILE_ARG: &str = "file";

/// The argument naming a further artifact, `purl0`, `purl1`, and so on.
pub fn purl_key(ordinal: usize) -> String {
    format!("{PURL_ARG}{ordinal}")
}

/// A message identified by name, with its substitutions kept apart from its
/// rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Stable, kebab-case. Names the *message*, not the occurrence -- two
    /// reports of the same situation share an id and differ in `args`.
    ///
    /// Like problem codes, these are API once anyone translates against
    /// them, so renaming one is a breaking change.
    pub id: String,

    /// Named substitutions. Named rather than positional because word order
    /// differs between languages, and a translator reordering `{host}` and
    /// `{source}` must not have to think about argument indices.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,

    /// The English rendering.
    ///
    /// Optional in the format so a future translator may omit it, and
    /// always written today -- a consumer that knows nothing of our ids still
    /// has something to show a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl Message {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            args: BTreeMap::new(),
            text: None,
        }
    }

    /// Record one substitution.
    pub fn arg(mut self, name: &str, value: impl fmt::Display) -> Self {
        self.args.insert(name.to_owned(), value.to_string());
        self
    }

    /// Set the English rendering.
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    /// What to show a person now.
    ///
    /// The fallback when there is one; otherwise the id and its arguments,
    /// which is ugly but never a lie.
    pub fn render(&self) -> String {
        if let Some(text) = &self.text {
            return text.clone();
        }

        if self.args.is_empty() {
            return self.id.clone();
        }

        let args: Vec<String> = self
            .args
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();

        format!("{} ({})", self.id, args.join(", "))
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Build a [`Message`] from an id and a format string.
///
/// The format string uses inline captures, and every captured name is also
/// recorded as an argument -- so one line produces both the English and the
/// structured form, and they cannot drift apart:
///
/// ```ignore
/// message!(
///     "source-host-unknown",
///     "source {source:?} names host {host:?}, which is not configured",
///     source = name,
///     host = &source.host,
/// )
/// ```
#[macro_export]
macro_rules! message {
    ($id:literal $(,)?) => {
        $crate::core::message::Message::new($id)
    };

    ($id:literal, $fmt:literal $(, $name:ident = $value:expr)* $(,)?) => {{
        // Every value is evaluated before any name is bound.  A sequence of
        // `let` statements would let an argument name shadow a variable a
        // later argument refers to -- `source = name, host = &source.host`
        // would resolve `source` to the new binding and not compile, or
        // worse, compile against the wrong thing.
        let ( $($name,)* ) = ( $($value,)* );

        // Warns on an artifact object passed as an argument: it must
        // arrive as a purl string, under `purl` or `purlN`.
        #[allow(unused_imports)]
        use $crate::core::message::probe::{Artifact as _, Plain as _};
        $( (&$crate::core::message::probe::Probe(&$name)).checked(); )*

        $crate::core::message::Message::new($id)
            .text(format!($fmt))
            $( .arg(stringify!($name), &$name) )*
    }};
}

/// Compile-time check that `message!` takes no artifact objects.
///
/// Autoref specialization: method lookup tries `&Probe<T>` before
/// `&&Probe<T>`, so an artifact type finds the deprecated [`Artifact`]
/// method first and every other type falls through to [`Plain`].
///
/// Dead code once every call site is clean, which is the goal.
#[doc(hidden)]
#[allow(dead_code)]
pub(crate) mod probe {
    use crate::core::problem::Subject;
    use crate::model::{ArtifactId, ResolvedArtifact};

    pub(crate) struct Probe<'a, T>(pub(crate) &'a T);

    pub(crate) trait Artifact {
        #[deprecated(note = "pass an artifact to message! as a purl string, \
                             under `purl` or `purlN`")]
        fn checked(&self) {}
    }

    pub(crate) trait Plain {
        fn checked(&self) {}
    }

    impl<T> Plain for &Probe<'_, T> {}

    /// The artifact itself and the references a capture usually holds.
    macro_rules! artifact {
        ($($kind:ty),*) => {$(
            impl Artifact for Probe<'_, $kind> {}
            impl Artifact for Probe<'_, &$kind> {}
            impl Artifact for Probe<'_, &&$kind> {}
        )*};
    }

    artifact!(ArtifactId, ResolvedArtifact, Subject);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_args_round_trip() {
        let message = message!(
            "source-host-unknown",
            "source {source:?} names host {host:?}, which is not configured",
            source = "central",
            host = "nowhere",
        );

        let json = serde_json::to_string(&message).expect("serializable");
        let read: Message = serde_json::from_str(&json).expect("readable");

        assert_eq!(read.id, "source-host-unknown");
        assert_eq!(read.args["source"], "central");
        assert_eq!(read.args["host"], "nowhere");
    }

    /// `message!` keys are its identifiers, so they must spell the constants.
    #[test]
    fn macro_keys_match_purl_identifiers() {
        let message = message!("x", "{purl} and {purl1}", purl = "a", purl1 = "b");

        assert_eq!(message.args[PURL_ARG], "a");
        assert_eq!(message.args[&purl_key(1)], "b");
    }

    /// The whole point: the structured form and the English come from one
    /// line, so they cannot say different things.
    #[test]
    fn macro_fills_text_and_args() {
        let message = message!("x", "a {one} and a {two}", one = 1, two = "two");

        assert_eq!(message.render(), "a 1 and a two");
        assert_eq!(message.args["one"], "1");
        assert_eq!(message.args["two"], "two");
    }

    /// A translator may drop the English; the id and args still carry it.
    #[test]
    fn render_without_text_uses_id_args() {
        let message = Message::new("host-unreachable").arg("host", "example.test");

        assert_eq!(message.render(), "host-unreachable (host=example.test)");
    }

    #[test]
    fn render_bare_id_as_itself() {
        assert_eq!(Message::new("aborted").render(), "aborted");
    }

    /// `text` is optional in the format so a future translator can omit it,
    /// and absent fields must not appear as nulls.
    #[test]
    fn wire_omits_empty_parts() {
        let json = serde_json::to_value(Message::new("x")).expect("serializable");

        assert!(json.get("args").is_none());
        assert!(json.get("text").is_none());
    }

    /// An argument name must not shadow a variable a later argument uses.
    ///
    /// `source = name, host = &source.host` is the natural way to write this
    /// and would break under sequential `let` bindings, because `source`
    /// would already mean the new binding by the time `host` is evaluated.
    #[test]
    fn macro_argument_may_shadow_outer_variable() {
        struct Entry {
            host: &'static str,
        }

        let source = Entry { host: "nowhere" };
        let name = "central";

        let built = message!(
            "source-host-unknown",
            "source {source:?} names host {host:?}",
            source = name,
            host = source.host,
        );

        assert_eq!(built.args["source"], "central");
        assert_eq!(built.args["host"], "nowhere");
    }

    #[test]
    fn macro_accepts_no_arguments() {
        let message = message!("nothing-to-say", "nothing to say");

        assert_eq!(message.render(), "nothing to say");
        assert!(message.args.is_empty());
    }
}
