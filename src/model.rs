//! Domain types shared by every layer.
//!
//! Nothing here knows how to talk to a registry.  Ecosystem-specific rules --
//! version ordering, coordinate syntax, which dependency kinds exist -- live
//! in the adapters, which is why [`Version`] keeps the raw text and a flag
//! the adapter computed rather than a parsed structure.
//!
//! ```text
//!   ecosystem_id   which ecosystem something belongs to
//!   artifact       what one is, and the files and digests under it
//!   version        an exact version, and a requested constraint
//!   dep            an edge between two of them
//!   prov           why this artifact is being looked at
//! ```
//!
//! This module declares nothing of its own.

mod artifact;
mod dep;
mod ecosystem_id;
mod last_download;
mod listing_depth;
mod prov;
mod version;

pub use artifact::{
    ArtifactId, ArtifactRequest, Digest, DigestAlg, FileRef, ParsedPurl, ResolvedArtifact, SigRef,
    SigScheme,
};
pub use dep::{DepKind, Dependency};
pub use ecosystem_id::EcosystemId;
pub use last_download::LastDownload;
pub use listing_depth::ListingDepth;
pub use prov::{CAUSE_ID_PREFIX, Cause, CauseKind, Provenance, cause_arg};
pub use version::{Release, Version, VersionSpec};
