//! The tool's settings, as the rest of the crate reads them.
//!
//! Mirrors the committed `schema/config.schema.json`.
//!
//! # Reading one is not this module's job
//!
//! Finding configuration files, validating them against the schema and
//! merging them is [`crate::cli::ConfigLoader`], because *where the
//! settings come from* is only ever a command line's question. An embedder
//! builds one of these directly.
//!
//! What stays here is the answer to *what are the settings*, which every
//! layer below needs: `net` reads a retry plan, `ext` reads constraints,
//! `repo` reads a publish window. Those types cannot move under `cli`
//! without making the network layer depend on the command line.

mod lower;
mod model;
#[cfg(test)]
mod schema_sync;
mod secret;
mod transport;
mod units;

pub(crate) use lower::{Origins, lower};
pub use model::{
    AdditionalHost, Advisor, Comments, Config, Enumerator, Extension, FreshnessRule, Host,
    LogLevel, Logging, Mirror, NamePattern, NameRule, OmitRule, OutputFormat, Payloads,
    ProxyEnumeratorUpstream, ProxyTo, ProxyToEnumerator, ProxyUpstream, Retry, RetryRule, Setup,
    SigningKey, SigningScheme, Source, Target, TlsVerify, UnknownPublishTime,
};
pub use secret::{Authentication, Secret, SecretValue};
pub(crate) use transport::{insecure_hosts, refused as refused_plain_http};
pub use units::{ByteSize, ConfigDuration, ConfigLifetime};
