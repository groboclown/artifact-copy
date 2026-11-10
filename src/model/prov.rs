//! The causal chain: why is this artifact being looked at?
//!
//! This is domain data, not a logging construct.  Reports carry it for later
//! analysis, and ambient thread-local context would be wrong under `tokio`,
//! where one task migrates between threads and one thread interleaves many
//! tasks.
//!
//! ```text
//!   commons-lang3:3.14.0
//!     <- runtime dependency of spring-core:6.1.0
//!     <- requested: "org.springframework:spring-core:6.1.0"
//! ```

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{ArtifactId, DepKind, Release, Version};
use crate::core::message::Message;
use crate::message;

/// One link in the chain.
#[derive(Debug, Clone)]
pub enum Cause {
    /// Named on the command line.
    Requested { arg: String },

    /// Read out of a lock file.
    LockFile { path: PathBuf, entry: String },

    /// Reached by spidering another artifact's dependencies.
    ///
    /// `version` is the parent's resolved version, so a report keys the
    /// edge on one release rather than on every release of the name.
    /// `None` where the parent has no versions, as in a raw repository.
    Dependency {
        of: ArtifactId,
        version: Option<Version>,
        kind: DepKind,
    },

    /// Produced by enumerating a repository.
    Enumerated { enumerator: String },

    /// Listed by a report database used as a work list.
    ///
    /// `entry` is the exact purl the report listed. `destinations` are the
    /// targets the work was outstanding for, empty when the report was
    /// read as an inventory. `run` is the run that last recorded the entry.
    Report {
        path: PathBuf,
        entry: String,
        source: String,
        destinations: Vec<String>,
        run: Option<i64>,
    },
}

/// What kind of link a [`Cause`] is, as a report stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseKind {
    Requested,
    LockFile,
    Dependency,
    Enumerated,
    Report,
}

/// Every message id a cause renders to starts with this, e.g.
/// `cause-lock-file`.
pub const CAUSE_ID_PREFIX: &str = "cause-";

/// The argument names a cause's [`Message`] carries.
///
/// A report reader keys on these, so each is API once published.
pub mod cause_arg {
    pub use crate::core::message::PURL_ARG as PURL;

    pub const ARG: &str = "arg";
    pub const PATH: &str = "path";
    pub const ENTRY: &str = "entry";
    pub const KIND: &str = "kind";
    pub const RELEASE: &str = "release";
    pub const ENUMERATOR: &str = "enumerator";
    pub const SOURCE: &str = "source";
    pub const DESTINATION: &str = "destination";

    /// Between the targets a `destination` names, when there are several.
    /// A configured name cannot hold it.
    pub const DESTINATION_SEPARATOR: &str = ",";
    pub const RUN: &str = "run";
}

impl CauseKind {
    const ALL: [CauseKind; 5] = [
        CauseKind::Requested,
        CauseKind::LockFile,
        CauseKind::Dependency,
        CauseKind::Enumerated,
        CauseKind::Report,
    ];

    /// The spelling the report database's `cause_kind` table holds.
    pub fn as_str(self) -> &'static str {
        match self {
            CauseKind::Requested => "requested",
            CauseKind::LockFile => "lock-file",
            CauseKind::Dependency => "dependency",
            CauseKind::Enumerated => "enumerated",
            CauseKind::Report => "report",
        }
    }

    /// The kind a cause message id names; `None` for any other id.
    pub fn of(id: &str) -> Option<Self> {
        let kind = id.strip_prefix(CAUSE_ID_PREFIX)?;

        Self::ALL.into_iter().find(|known| known.as_str() == kind)
    }
}

impl Cause {
    pub fn kind(&self) -> CauseKind {
        match self {
            Cause::Requested { .. } => CauseKind::Requested,
            Cause::LockFile { .. } => CauseKind::LockFile,
            Cause::Dependency { .. } => CauseKind::Dependency,
            Cause::Enumerated { .. } => CauseKind::Enumerated,
            Cause::Report { .. } => CauseKind::Report,
        }
    }

    /// This link as it crosses the report boundary: an id plus named
    /// arguments, with the English as a fallback.
    ///
    /// `message!` records every name it renders, so the text and the
    /// arguments cannot drift. An argument the text leaves out is added
    /// after it.
    pub fn message(&self) -> Message {
        match self {
            Cause::Requested { arg } => {
                message!("cause-requested", "requested: {arg:?}", arg = arg)
            }

            Cause::LockFile { path, entry } => message!(
                "cause-lock-file",
                "{entry} in lock file {path}",
                entry = entry,
                path = path.display(),
            ),

            Cause::Dependency { of, version, kind } => {
                let Some(version) = version else {
                    return message!(
                        "cause-dependency",
                        "{kind} dependency of {purl}",
                        kind = kind,
                        purl = of.purl()
                    );
                };

                message!(
                    "cause-dependency",
                    "{kind} dependency of {purl}",
                    kind = kind,
                    purl = of.purl_at(version.text()),
                )
                .arg(cause_arg::RELEASE, version.release().as_str())
            }

            Cause::Enumerated { enumerator } => message!(
                "cause-enumerated",
                "found by enumerator {enumerator:?}",
                enumerator = enumerator,
            ),

            Cause::Report {
                path,
                entry,
                source,
                destinations,
                run,
            } => {
                let rendered = match destinations.as_slice() {
                    [] => message!(
                        "cause-report",
                        "{purl} recorded for source {source:?} in report {path}",
                        purl = entry,
                        source = source,
                        path = path.display(),
                    ),

                    [destination] => message!(
                        "cause-report",
                        "{purl} outstanding from source {source:?} to target {destination:?} in report {path}",
                        purl = entry,
                        source = source,
                        destination = destination,
                        path = path.display(),
                    ),

                    // Joined, so a report reader can split it again.
                    several => message!(
                        "cause-report",
                        "{purl} outstanding from source {source:?} to targets {destination} in report {path}",
                        purl = entry,
                        source = source,
                        destination = &several.join(cause_arg::DESTINATION_SEPARATOR),
                        path = path.display(),
                    ),
                };

                match run {
                    Some(run) => rendered.arg(cause_arg::RUN, run),
                    None => rendered,
                }
            }
        }
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message().render())
    }
}

/// A node in the causal chain.
///
/// Linked through `Arc` so a wide dependency fan-out shares one spine rather
/// than cloning a full path per node.
#[derive(Debug)]
pub struct Provenance {
    parent: Option<Arc<Provenance>>,
    cause: Cause,
}

impl Provenance {
    /// Start a chain.
    pub fn root(cause: Cause) -> Self {
        Self {
            parent: None,
            cause,
        }
    }

    /// Extend this chain with a further cause.
    pub fn child(self: &Arc<Self>, cause: Cause) -> Arc<Self> {
        Arc::new(Self {
            parent: Some(Arc::clone(self)),
            cause,
        })
    }

    pub fn cause(&self) -> &Cause {
        &self.cause
    }

    /// Walk from this node outwards to the root cause.
    pub fn chain(&self) -> impl Iterator<Item = &Cause> {
        let mut next = Some(self);

        std::iter::from_fn(move || {
            let node = next?;
            next = node.parent.as_deref();

            Some(&node.cause)
        })
    }

    /// How deep this chain runs.  The spider compares it against the
    /// configured depth limit.
    pub fn depth(&self) -> usize {
        self.chain().count()
    }

    /// One line per link, each indented under the last.
    pub fn render(&self) -> String {
        let mut out = String::new();

        for (level, cause) in self.chain().enumerate() {
            if level > 0 {
                out.push('\n');
                out.push_str(&"  ".repeat(level));
                out.push_str("<- ");
            }

            out.push_str(&cause.to_string());
        }

        out
    }
}

/// One link as stored outside the process, for a frontier on disk.
///
/// A mirror rather than serde on [`Cause`] itself, so the stored shape is
/// decided here: the parent artifact travels as its purl, which is how
/// every store in this crate keys an artifact.
#[derive(Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "kebab-case")]
enum Stored {
    Requested {
        arg: String,
    },
    LockFile {
        path: PathBuf,
        entry: String,
    },
    Dependency {
        of: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        release: Option<Release>,
        kind: DepKind,
    },
    Enumerated {
        enumerator: String,
    },
    Report {
        path: PathBuf,
        entry: String,
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        destinations: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run: Option<i64>,
    },
}

impl Provenance {
    /// The chain as JSON, root first.
    pub fn to_json(&self) -> String {
        let mut links: Vec<Stored> = self
            .chain()
            .map(|cause| match cause {
                Cause::Requested { arg } => Stored::Requested { arg: arg.clone() },

                Cause::LockFile { path, entry } => Stored::LockFile {
                    path: path.clone(),
                    entry: entry.clone(),
                },

                Cause::Dependency { of, version, kind } => Stored::Dependency {
                    of: match version {
                        Some(version) => of.purl_at(version.text()),
                        None => of.purl(),
                    },
                    release: version.as_ref().map(Version::release),
                    kind: *kind,
                },

                Cause::Enumerated { enumerator } => Stored::Enumerated {
                    enumerator: enumerator.clone(),
                },

                // One target keeps the shape a chain had before there could
                // be several.
                Cause::Report {
                    path,
                    entry,
                    source,
                    destinations,
                    run,
                } => Stored::Report {
                    path: path.clone(),
                    entry: entry.clone(),
                    source: source.clone(),
                    destination: match destinations.as_slice() {
                        [one] => Some(one.clone()),
                        _ => None,
                    },
                    destinations: match destinations.len() > 1 {
                        true => destinations.clone(),
                        false => Vec::new(),
                    },
                    run: *run,
                },
            })
            .collect();

        links.reverse();

        serde_json::to_string(&links).expect("a provenance chain serializes")
    }

    /// Rebuild a chain [`Provenance::to_json`] wrote.
    ///
    /// The error is prose for the store that held the text to wrap.
    pub fn from_json(text: &str) -> Result<Arc<Self>, String> {
        let links: Vec<Stored> = serde_json::from_str(text).map_err(|err| err.to_string())?;
        let mut chain: Option<Arc<Self>> = None;

        for link in links {
            let cause = match link {
                Stored::Requested { arg } => Cause::Requested { arg },
                Stored::LockFile { path, entry } => Cause::LockFile { path, entry },
                Stored::Enumerated { enumerator } => Cause::Enumerated { enumerator },

                Stored::Dependency { of, release, kind } => {
                    let parsed = ArtifactId::parse(&of).map_err(|err| err.to_string())?;

                    // A version without its class would have to be guessed.
                    let version = match (parsed.version, release) {
                        (Some(text), Some(release)) => Some(Version::new(text, release)),
                        (None, None) => None,
                        _ => return Err(format!("dependency {of} stored without its release")),
                    };

                    Cause::Dependency {
                        of: parsed.id,
                        version,
                        kind,
                    }
                }

                Stored::Report {
                    path,
                    entry,
                    source,
                    destination,
                    mut destinations,
                    run,
                } => {
                    destinations.extend(destination);

                    Cause::Report {
                        path,
                        entry,
                        source,
                        destinations,
                        run,
                    }
                }
            };

            chain = Some(match chain {
                Some(parent) => parent.child(cause),
                None => Arc::new(Self::root(cause)),
            });
        }

        chain.ok_or_else(|| "an empty provenance chain".to_owned())
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EcosystemId;

    fn id(name: &str) -> ArtifactId {
        ArtifactId::new(EcosystemId::npm(), None, name)
    }

    #[test]
    fn json_round_trips_every_cause() {
        let root = Arc::new(Provenance::root(Cause::LockFile {
            path: "dir/package-lock.json".into(),
            entry: "pkg:npm/app".into(),
        }));

        let leaf = root
            .child(Cause::Dependency {
                of: id("app"),
                version: None,
                kind: DepKind::Dev,
            })
            .child(Cause::Dependency {
                of: id("lib"),
                version: Some(Version::new("2.0.0-rc.1", Release::PreRelease)),
                kind: DepKind::Runtime,
            })
            .child(Cause::Requested { arg: "x".into() })
            .child(Cause::Enumerated {
                enumerator: "e".into(),
            })
            .child(Cause::Report {
                path: "migration.db".into(),
                entry: "pkg:npm/app@1.0.0".into(),
                source: "origin".into(),
                destinations: vec!["mirror".into()],
                run: Some(7),
            })
            .child(Cause::Report {
                path: "migration.db".into(),
                entry: "pkg:npm/app@1.0.0".into(),
                source: "origin".into(),
                destinations: vec!["mirror".into(), "backup".into()],
                run: None,
            });

        let back = Provenance::from_json(&leaf.to_json()).expect("parses");
        let messages = |prov: &Provenance| prov.chain().map(Cause::message).collect::<Vec<_>>();

        assert_eq!(messages(&back), messages(&leaf));
    }

    /// A stored version without its release class would have to be guessed.
    #[test]
    fn json_version_without_release_refused() {
        let stored = r#"[{"cause":"dependency","of":"pkg:npm/app@1.0.0","kind":"runtime"}]"#;

        assert!(Provenance::from_json(stored).is_err());
    }

    /// Each message id names its own kind, so a report reader can key on it.
    #[test]
    fn message_id_names_kind() {
        let causes = [
            Cause::Requested { arg: "x".into() },
            Cause::LockFile {
                path: "package-lock.json".into(),
                entry: "app@1.0.0".into(),
            },
            Cause::Dependency {
                of: id("app"),
                version: None,
                kind: DepKind::Runtime,
            },
            Cause::Enumerated {
                enumerator: "e".into(),
            },
            Cause::Report {
                path: "migration.db".into(),
                entry: "pkg:npm/app@1.0.0".into(),
                source: "origin".into(),
                destinations: Vec::new(),
                run: None,
            },
        ];

        for cause in causes {
            assert_eq!(CauseKind::of(&cause.message().id), Some(cause.kind()));
        }
    }

    /// The parent's version is in the text and the `purl` argument; its
    /// release class travels only as an argument.
    #[test]
    fn dependency_names_parent_version() {
        let message = Cause::Dependency {
            of: id("app"),
            version: Some(Version::new("1.0.0", Release::General)),
            kind: DepKind::Runtime,
        }
        .message();

        assert_eq!(message.render(), "runtime dependency of pkg:npm/app@1.0.0");
        assert_eq!(message.args[cause_arg::PURL], "pkg:npm/app@1.0.0");
        assert_eq!(message.args[cause_arg::RELEASE], "general");
    }

    /// A report root says where the work came from without naming a lock
    /// file nobody passed.
    #[test]
    fn report_renders_destination() {
        let cause = |destinations: &[&str]| Cause::Report {
            path: "migration.db".into(),
            entry: "pkg:npm/app@1.0.0".into(),
            source: "origin".into(),
            destinations: destinations.iter().map(|name| name.to_string()).collect(),
            run: Some(3),
        };

        assert_eq!(
            cause(&["mirror"]).to_string(),
            r#"pkg:npm/app@1.0.0 outstanding from source "origin" to target "mirror" in report migration.db"#
        );
        assert_eq!(
            cause(&[]).to_string(),
            r#"pkg:npm/app@1.0.0 recorded for source "origin" in report migration.db"#
        );
        assert_eq!(cause(&[]).message().args[cause_arg::RUN], "3");
    }

    /// Several targets render as one list, and travel as one argument a
    /// reader can split.
    #[test]
    fn report_renders_destinations() {
        let cause = Cause::Report {
            path: "migration.db".into(),
            entry: "pkg:npm/app@1.0.0".into(),
            source: "origin".into(),
            destinations: vec!["mirror".into(), "backup".into()],
            run: None,
        };

        assert_eq!(
            cause.to_string(),
            r#"pkg:npm/app@1.0.0 outstanding from source "origin" to targets mirror,backup in report migration.db"#
        );
        assert_eq!(
            cause.message().args[cause_arg::DESTINATION],
            "mirror,backup"
        );
    }

    #[test]
    fn json_empty_chain_refused() {
        assert!(Provenance::from_json("[]").is_err());
    }

    #[test]
    fn chain_runs_from_leaf_to_root() {
        let root = Arc::new(Provenance::root(Cause::Requested {
            arg: "app@1.0.0".into(),
        }));

        let mid = root.child(Cause::Dependency {
            of: id("app"),
            version: None,
            kind: DepKind::Runtime,
        });

        let leaf = mid.child(Cause::Dependency {
            of: id("middle"),
            version: None,
            kind: DepKind::Runtime,
        });

        assert_eq!(leaf.depth(), 3);

        let rendered = leaf.render();
        assert!(rendered.starts_with("runtime dependency of pkg:npm/middle"));
        assert!(rendered.ends_with(r#"<- requested: "app@1.0.0""#));
    }

    #[test]
    fn siblings_share_one_spine() {
        let root = Arc::new(Provenance::root(Cause::Enumerated {
            enumerator: "npm-replicate".into(),
        }));

        let a = root.child(Cause::Dependency {
            of: id("a"),
            version: None,
            kind: DepKind::Runtime,
        });
        let b = root.child(Cause::Dependency {
            of: id("b"),
            version: None,
            kind: DepKind::Dev,
        });

        assert_eq!(a.depth(), 2);
        assert_eq!(b.depth(), 2);
        assert_eq!(Arc::strong_count(&root), 3);
    }
}
